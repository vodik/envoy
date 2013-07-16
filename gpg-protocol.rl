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
 * Copyright (C) Simon Gomizelj, 2013
 */

#include "gpg-protocol.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <getopt.h>
#include <err.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

static int gpg_check_return(int fd)
{
    char buf[BUFSIZ];
    ssize_t nbytes_r = read(fd, buf, BUFSIZ);
    if (nbytes_r <= 0)
        return -1;

    if (strncmp(buf, "OK", 2) == 0)
        return 0;

    fprintf(stderr, "%s: gpg protocol error: %s", program_invocation_short_name, buf);
    return -1;
}

static int __attribute__((format (printf, 2, 3))) gpg_send_message(int fd, const char *fmt, ...)
{
    va_list ap;
    int nbytes_r;

    va_start(ap, fmt);
    nbytes_r = vdprintf(fd, fmt, ap);
    va_end(ap);

    return gpg_check_return(fd) == 0 ? nbytes_r : -1;
}

int gpg_agent_connection(const char *sock)
{
    char *split;
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    size_t len;
    socklen_t sa_len;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        warn("couldn't create socket");
        return -1;
    }

    split = strchr(sock, ':');
    len = split - sock;

    sa.un = (struct sockaddr_un){ .sun_family = AF_UNIX };
    memcpy(&sa.un.sun_path, sock, len);

    sa_len = len + sizeof(sa.un.sun_family);
    if (connect(fd, &sa.sa, sa_len) < 0) {
        warn("failed to connect to gpg-agent");
        return -1;
    }

    if (gpg_check_return(fd) < 0) {
        warnx("incorrect response from gpg-agent");
        return -1;
    }

    return fd;
}

int gpg_update_tty(int fd)
{
    const char *display = getenv("DISPLAY");
    const char *tty = ttyname(STDIN_FILENO);
    const char *term = getenv("TERM");

    gpg_send_message(fd, "RESET\n");

    if (tty)
        gpg_send_message(fd, "OPTION ttyname=%s\n", tty);

    if (term)
        gpg_send_message(fd, "OPTION ttytype=%s\n", term);

    if (display) {
        struct passwd *pwd = getpwuid(getuid());
        if (pwd == NULL || pwd->pw_dir == NULL)
            err(EXIT_FAILURE, "failed to lookup passwd entry");

        gpg_send_message(fd, "OPTION display=%s\n", display);
        gpg_send_message(fd, "OPTION xauthority=%s/.Xauthority\n", pwd->pw_dir);
    }

    gpg_send_message(fd, "UPDATESTARTUPTTY\n");
    return 0;
}

%%{
    machine keyinfo;

    action clear  { buflen = 0; }
    action append { buffer[buflen++] = fc; }
    action term   {
        struct fingerprint_t *node = calloc(1, sizeof(struct fingerprint_t));
        node->fingerprint = strndup(buffer, buflen);
        node->next = fpt;
        fpt = node;
    }

    fingerprint = xdigit+ >clear $append %term;

    action done { return fpt; }
    action error {
        fprintf(stderr, "%s: gpg protocol error: %s", program_invocation_short_name, fpc);
        return fpt;
    }

    newline = '\n';
    status = ( 'OK' >done | 'ERR' >error ) [^\n]* newline;
    entry = 'S KEYINFO ' fingerprint ' D - - ' ( '1' | '-' ) ' P -' newline;

    main := ( entry | status )*;
}%%

%%write data;

struct fingerprint_t *gpg_keyinfo(int fd)
{
    static const char message[] = "KEYINFO --list\n";
    struct fingerprint_t *fpt = NULL;
    int cs;

    ssize_t nbytes_r = write(fd, message, sizeof(message) - 1);
    if (nbytes_r < 0)
        return NULL;

    %%write init;

    for (;;) {
        char buf[BUFSIZ];

        size_t buflen = 0;
        char buffer[40];

        nbytes_r = read(fd, buf, BUFSIZ);
        if (nbytes_r < 0)
            return NULL;

        char *p = buf, *pe = &buf[nbytes_r];

        %%write exec;

        if (cs == keyinfo_error) {
            warnx("error parsing gpg protocol");
            break;
        }
    }

    return fpt;
}

int gpg_preset_passphrase(int fd, const char *fingerprint, int timeout, const char *password)
{
    static const char *hex_digits = "0123456789ABCDEF";
    size_t nbytes_r;

    if (!password) {
        nbytes_r = dprintf(fd, "PRESET_PASSPHRASE %s %d\n", fingerprint, timeout);
        return gpg_check_return(fd) == 0 ? nbytes_r : -1;
    }

    size_t i, size = strlen(password);
    char *bin_password = malloc(2 * size + 1);

    for(i = 0; i < size; i++) {
        bin_password[2 * i] = hex_digits[password[i] >> 4];
        bin_password[2 * i + 1] = hex_digits[password[i] & 0x0f];
    }

    bin_password[2 * size] = '\0';
    nbytes_r = dprintf(fd, "PRESET_PASSPHRASE %s %d %s\n", fingerprint, timeout, bin_password);

    free(bin_password);
    return gpg_check_return(fd) == 0 ? nbytes_r : -1;
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

// vim: et:sts=4:sw=4:cino=(0
