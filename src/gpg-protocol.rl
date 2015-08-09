/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Simon Gomizelj, 2015
 */

#include "gpg-protocol.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "util.h"

struct gpg_t {
    int fd;
    char buf[BUFSIZ];

    /* ragel parser state */
    int cs;
    char *p;
    char *pe;
};

static int gpg_buffer_refill(struct gpg_t *gpg)
{
    ssize_t nbytes_r = read(gpg->fd, gpg->buf, sizeof(gpg->buf) - 1);
    if (nbytes_r < 0)
        return -1;

    gpg->buf[nbytes_r] = 0;
    gpg->p = gpg->buf;
    gpg->pe = gpg->buf + nbytes_r;
    return nbytes_r;
}

%%{
    machine status;

    action error {
        fprintf(stderr, "%s: gpg protocol error: %s", program_invocation_short_name, fpc);
        rc = -EIO;
    }
    action return { return rc; }

    newline = '\n';
    main := ( 'OK' | 'ERR' >error ) [^\n]* newline %return;
}%%

%%write data nofinal;

static int gpg_check_return(struct gpg_t *gpg)
{
    int rc = 0;

    %%access gpg->;
    %%variable p gpg->p;
    %%variable pe gpg->pe;
    %%write init;

    for (;;) {
        if (gpg->p == NULL || gpg->p == gpg->pe) {
            if (gpg_buffer_refill(gpg) <= 0)
                break;
        }

        char *eof = gpg->pe;
        %%write exec;

        if (gpg->cs == status_error) {
            warnx("error parsing gpg protocol");
            break;
        }
    }

    (void)status_en_main;
    return rc;
}

static _printf_(2, 3) int gpg_send_message(struct gpg_t *gpg, const char *fmt, ...)
{
    va_list ap;
    int nbytes_r, rc;

    va_start(ap, fmt);
    nbytes_r = vdprintf(gpg->fd, fmt, ap);
    va_end(ap);

    rc = gpg_check_return(gpg);
    return rc == 0 ? nbytes_r : rc;
}

struct gpg_t *gpg_agent_connection(const char *sock, const char *home)
{
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    size_t len;
    socklen_t sa_len;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return NULL;

    sa.un = (struct sockaddr_un){ .sun_family = AF_UNIX };

    if (!sock || !sock[0]) {
        len = snprintf(sa.un.sun_path, sizeof(sa.un.sun_path),
                       "%s/.gnupg/S.gpg-agent",
                       home ? home : get_home_dir());
    } else {
        len = strcspn(sock, ":");
        memcpy(&sa.un.sun_path, sock, len);
    }

    sa_len = len + sizeof(sa.un.sun_family);
    if (connect(fd, &sa.sa, sa_len) < 0) {
        close(fd);
        return NULL;
    }

    struct gpg_t *gpg = malloc(sizeof(struct gpg_t));
    *gpg = (struct gpg_t) { .fd = fd };

    if (gpg_check_return(gpg) < 0) {
        gpg_close(gpg);
        return NULL;
    }

    return gpg;
}

int gpg_reload_agent(struct gpg_t *gpg)
{
    return gpg_send_message(gpg, "RELOADAGENT\n");
}

int gpg_update_tty(struct gpg_t *gpg)
{
    const char *tty = ttyname(STDIN_FILENO);
    const char *term = getenv("TERM");
    const char *display = getenv("DISPLAY");
    const char *xauthority = getenv("XAUTHORITY");

    /* In this case, there's no information to update, so lets bail to
     * avoid clearing what's already there */
    if (!tty && !display)
        return 0;

    gpg_send_message(gpg, "RESET\n");

    if (tty) {
        gpg_send_message(gpg, "OPTION ttyname=%s\n", tty);
        gpg_send_message(gpg, "OPTION ttytype=%s\n", term ? term : "dumb");
    }

    if (display) {
        gpg_send_message(gpg, "OPTION display=%s\n", display);

        if (xauthority)
            gpg_send_message(gpg, "OPTION xauthority=%s\n", xauthority);
        else
            gpg_send_message(gpg, "OPTION xauthority=%s/.Xauthority\n", get_home_dir());
    }

    gpg_send_message(gpg, "UPDATESTARTUPTTY\n");
    return 0;
}

%%{
    machine keyinfo;

    action clear { keylen = 0; }
    action append { keygrip[keylen++] = fc; }
    action term {
        struct fingerprint_t *next = fpt;
        fpt = malloc(sizeof(struct fingerprint_t));
        *fpt = (struct fingerprint_t){
            .fingerprint = strndup(keygrip, keylen),
            .flags = keyflags,
            .next = next
        };
        keyflags = 0;
    }

    action flag {
        switch (fc) {
        case 'D':
            keyflags |= KEY_DISABLED;
            break;
        case 'S':
            keyflags |= KEY_SSHCONTROL;
            break;
        case 'c':
            keyflags |= KEY_CONFIRM;
            break;
        }
    }

    action error { fprintf(stderr, "%s: gpg protocol error: %s", program_invocation_short_name, fpc); }
    action return { return fpt; }

    newline = '\n';
    status = ( 'OK' | 'ERR' >error [^\n]* ) newline %return;

    # KEYGRIP is the keygrip
    keygrip = xdigit{40} >clear $append;

    # TYPE describes the type of the key:
    #     'D' - Regular key stored on disk,
    #     'T' - Key is stored on a smartcard (token),
    #     'X' - Unknown type,
    #     '-' - Key is missing.
    type = [DTX\-];

    # SERIALNO is an ASCII string with the serial number of the
    #          smartcard.  If the serial number is not known a single
    #          dash '-' is used instead.
    serialno = alpha+ | '-';

    # IDSTR is the IDSTR used to distinguish keys on a smartcard.  If it
    #       is not known a dash is used instead.
    idstr = [^\ ]+ | '-';

    # CACHED is 1 if the passphrase for the key was found in the key cache.
    #        If not, a '-' is used instead.
    cached = [1\-];

    # PROTECTION describes the key protection type:
    #     'P' - The key is protected with a passphrase,
    #     'C' - The key is not protected,
    #     '-' - Unknown protection.
    protection = [PC\-];

    # FPR returns the formatted ssh-style fingerprint of the key.  It is only
    #     printed if the option --ssh-fpr has been used.  It defaults to '-'.
    fpr = '-';

    # TTL is the TTL in seconds for that key or '-' if n/a.
    ttl = digit+ | '-';

    # FLAGS is a word consisting of one-letter flags:
    #       'D' - The key has been disabled,
    #       'S' - The key is listed in sshcontrol (requires --with-ssh),
    #       'c' - Use of the key needs to be confirmed,
    #       '-' - No flags given.
    flags = [DSc\-]+ >flag;

    # KEYINFO <keygrip> <type> <serialno> <idstr> <cached> <protection> <fpr>
    entry = 'S KEYINFO' space keygrip space type       space serialno space idstr space
                              cached  space protection space fpr      space ttl   space
                              flags   newline
                              @term;

    main := ( entry | status )*;
}%%

%%write data nofinal;

struct fingerprint_t *gpg_keyinfo(struct gpg_t *gpg)
{
    static const char message[] = "KEYINFO --list --with-ssh\n";
    struct fingerprint_t *fpt = NULL;
    char keygrip[40];
    size_t keylen = 0;
    enum keyflags keyflags = 0;

    ssize_t nbytes_w = write(gpg->fd, message, sizeof(message) - 1);
    if (nbytes_w < 0)
        return NULL;

    %%access gpg->;
    %%variable p gpg->p;
    %%variable pe gpg->pe;
    %%write init;

    for (;;) {
        if (gpg->p == NULL || gpg->p == gpg->pe) {
            if (gpg_buffer_refill(gpg) <= 0)
                break;
        }

        char *eof = gpg->pe;
        %%write exec;

        if (gpg->cs == keyinfo_error) {
            warnx("error parsing gpg protocol");
            break;
        }
    }

    (void)keyinfo_en_main;
    return fpt;
}

int gpg_preset_passphrase(struct gpg_t *gpg, const char *fingerprint, int timeout, const char *password)
{
    static const char *hex_digits = "0123456789ABCDEF";

    if (!fingerprint)
        return -EINVAL;

    if (!password)
        return gpg_send_message(gpg, "PRESET_PASSPHRASE %s %d\n", fingerprint, timeout);

    size_t i, size = strlen(password);
    char bin_password[2 * size + 1];

    for(i = 0; i < size; i++) {
        bin_password[2 * i] = hex_digits[password[i] >> 4];
        bin_password[2 * i + 1] = hex_digits[password[i] & 0x0f];
    }

    bin_password[2 * size] = '\0';
    return gpg_send_message(gpg, "PRESET_PASSPHRASE %s %d %s\n", fingerprint, timeout, bin_password);
}

void free_fingerprints(struct fingerprint_t *fpt)
{
    while (fpt) {
        struct fingerprint_t *node = fpt;
        fpt = fpt->next;

        free(node->fingerprint);
        free(node);
    }
}

void gpg_close(struct gpg_t *gpg)
{
    close(gpg->fd);
    free(gpg);
}

// vim: et:sts=4:sw=4:cino=(0
