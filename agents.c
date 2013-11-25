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

#include "agents.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "socket.h"

const struct agent_t Agent[LAST_AGENT] = {
    [AGENT_SSH_AGENT] = {
        .name = "ssh-agent",
        .argv = (char *const []){ "/usr/bin/ssh-agent", NULL }
    },
    [AGENT_GPG_AGENT] = {
        .name = "gpg-agent",
        .argv = (char *const []){ "/usr/bin/gpg-agent", "--daemon", "--enable-ssh-support", NULL }
    }
};

static int read_agent(int fd, struct agent_data_t *data)
{
    int nbytes_r;

    while (true) {
        nbytes_r = read(fd, data, sizeof(*data));
        if (nbytes_r < 0) {
            if (errno != EAGAIN)
                return -errno;
        } else {
            return nbytes_r;
        }
    }
}

static int start_agent(int fd, struct agent_data_t *data, enum agent type, bool defer)
{
    struct agent_request_t req = {
        .type  = type,
        .defer = defer,
        .start = true
    };

    if (write(fd, &req, sizeof(struct agent_data_t)) < 0)
        return -errno;
    return read_agent(fd, data);
}

int envoy_agent(struct agent_data_t *data, enum agent id, bool start, bool defer)
{
    socklen_t sa_len;
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -errno;

    sa_len = init_envoy_socket(&sa.un);
    if (connect(fd, &sa.sa, sa_len) < 0)
        return -errno;

    int ret = start_agent(fd, data, id, defer);

    close(fd);
    return ret;
}

enum agent lookup_agent(const char *string)
{
    size_t i;

    for (i = 0; i < LAST_AGENT; i++)
        if (strcmp(Agent[i].name, string) == 0)
            break;

    return i;
}

// vim: et:sts=4:sw=4:cino=(0
