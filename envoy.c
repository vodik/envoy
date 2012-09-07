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
 * Copyright (C) Simon Gomizelj, 2012
 */

#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <err.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "config.h"

int main()
{
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    int fd, rc;

    fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        err(EXIT_FAILURE, "couldn't create socket");

    memset(&sa, 0, sizeof(sa));
    sa.un.sun_family = AF_UNIX;
    strncpy(sa.un.sun_path, SOCK_PATH, sizeof(sa.un.sun_path));

    rc = connect(fd, &sa.sa, sizeof(sa));
    if (rc < 0)
        err(EXIT_FAILURE, "failed to connect");

    int nread;
    char buf[BUFSIZ];

    nread = read(fd, buf, BUFSIZ);
    buf[nread] = 0;

    fputs(buf, stdout);
    close(fd);

    return 0;
}

// vim: et:sts=4:sw=4:cino=(0
