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

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <err.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

int main()
{
    struct agent_data_t data;
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    int fd;

    fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        err(EXIT_FAILURE, "couldn't create socket");

    memset(&sa, 0, sizeof(sa));
    sa.un.sun_family = AF_UNIX;
    strncpy(sa.un.sun_path, SOCK_PATH, sizeof(sa.un.sun_path));

    if (connect(fd, &sa.sa, sizeof(sa)) < 0)
        err(EXIT_FAILURE, "failed to connect");

    if (read(fd, &data, sizeof(data)) < 0)
        err(EXIT_FAILURE, "failed to read data");

    if (data.first_run)
        printf("FIRST RUN!\n");

    printf("export SSH_AUTH_SOCK=%s\n", data.sock);
    printf("export SSH_AGENT_PID=%d\n", data.pid);

    close(fd);
    return 0;
}

// vim: et:sts=4:sw=4:cino=(0
