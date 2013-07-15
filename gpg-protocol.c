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

static int __attribute__((format (printf, 2, 3))) gpg_send_message(int fd, const char *fmt, ...)
{
    va_list ap;
    int nbytes;
    char buf[BUFSIZ];

    va_start(ap, fmt);
    nbytes = vdprintf(fd, fmt, ap);
    va_end(ap);

    if (nbytes < 0)
        return -1;

    if (read(fd, buf, BUFSIZ) < 0)
        return -1;

    return !strncmp(buf, "OK\n", 3);
}

int gpg_agent_connection(const char *sock)
{
    char buf[BUFSIZ], *split;
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    size_t len;
    socklen_t sa_len;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0), nbytes;
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

    nbytes = read(fd, buf, BUFSIZ);
    if (nbytes < 0)
        err(EXIT_FAILURE, "failed to read from gpg-agent socket");

    if (strncmp(buf, "OK", 2) != 0) {
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

// vim: et:sts=4:sw=4:cino=(0
