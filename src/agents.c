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

#include "agents.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "socket.h"
#include "util.h"

const struct agent_t Agent[] = {
    [AGENT_SSH_AGENT] = {
        .name = { "ssh-agent", "ssh" },
        .argv = (char *const []){ "/usr/bin/ssh-agent", NULL }
    },
    [AGENT_GPG_AGENT] = {
        .name = { "gpg-agent", "gpg" },
        .argv = (char *const []){ "/usr/bin/gpg-agent", "--daemon", "--enable-ssh-support", NULL }
    }
};

static int envoy_connect(void)
{
    socklen_t sa_len;
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    sa_len = init_envoy_socket(&sa.un);
    if (connect(fd, &sa.sa, sa_len) < 0)
        return -1;
    return fd;
}

static ssize_t envoy_request(const struct agent_request_t *req, struct agent_data_t *data)
{
    ssize_t nbytes_r = 0;
    int fd = envoy_connect();
    if (fd < 0)
        return -1;

    if (write(fd, req, sizeof(struct agent_request_t)) < 0)
        return -1;

    nbytes_r = read(fd, data, sizeof(struct agent_data_t));
    close(fd);
    return nbytes_r;
}

int envoy_get_agent(enum agent type, struct agent_data_t *data, enum options opts)
{
    const struct agent_request_t req = { .type = type, .opts = opts };
    return envoy_request(&req, data) < 0 ? -1 : 0;
}

int envoy_kill_agent(enum agent type)
{
    const struct agent_request_t req = { .type = type, .opts = AGENT_KILL };
    struct agent_data_t data;

    if (envoy_request(&req, &data) < 0)
        return -1;
    return data.status == ENVOY_STOPPED ? 0 : -1;
}

enum agent lookup_agent(const char *string)
{
    size_t i;
    for (i = 0; i < sizeof(Agent) / sizeof(Agent[0]); i++) {
        const struct agent_t *agent = &Agent[i];

        if (streq(agent->name[0], string) || streq(agent->name[1], string))
            return i;
    }
    return -1;
}

// vim: et:sts=4:sw=4:cino=(0
