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

#include "envoy.h"

#include <stdlib.h>
#include <stdbool.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

static bool read_agent(int fd, struct agent_data_t *data)
{
    int nbytes_r;

    while (true) {
        nbytes_r = read(fd, data, sizeof(*data));
        if (nbytes_r < 0) {
            if (errno != EAGAIN) {
                warn("failed to receive data from server");
                break;
            }
        } else
            break;
    }

    switch (data->status) {
    case ENVOY_STOPPED:
    case ENVOY_STARTED:
    case ENVOY_RUNNING:
        break;
    case ENVOY_FAILED:
        errx(EXIT_FAILURE, "agent failed to start, check envoyd's log");
    case ENVOY_BADUSER:
        errx(EXIT_FAILURE, "connection rejected, user is unauthorized to use this agent");
    }

    return true;
}

static bool start_agent(int fd, struct agent_data_t *data, enum agent type)
{
    if (write(fd, &type, sizeof(enum agent)) < 0)
        err(EXIT_FAILURE, "failed to write agent type");

    bool rc = read_agent(fd, data);

    if (data->status == ENVOY_STOPPED)
        errx(EXIT_FAILURE, "envoyd reported agent stopped twice");
    if (data->pid == 0)
        errx(EXIT_FAILURE, "envoyd did not provide a valid pid");

    return rc;
}

bool get_agent(struct agent_data_t *data, enum agent id, bool start)
{
    socklen_t sa_len;
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        err(EXIT_FAILURE, "couldn't create socket");

    sa_len = init_envoy_socket(&sa.un);
    if (connect(fd, &sa.sa, sa_len) < 0)
        err(EXIT_FAILURE, "failed to connect to agent");

    bool rc = read_agent(fd, data);

    if (rc && start && data->status == ENVOY_STOPPED)
        rc = start_agent(fd, data, id);

    close(fd);
    return rc;
}
