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

#ifndef AGENT_H
#define AGENT_H

#include <stdbool.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

enum agent {
    AGENT_DEFAULT = -1,
    AGENT_SSH_AGENT = 0,
    AGENT_GPG_AGENT,
    LAST_AGENT
};

enum status {
    ENVOY_STOPPED = 0,
    ENVOY_STARTED,
    ENVOY_RUNNING,
    ENVOY_FAILED,
    ENVOY_BADUSER,
};

struct agent_t {
    const char *name;
    char *const *argv;
};

struct agent_request_t {
    enum agent type;
    bool defer;
    bool start;
};

struct agent_data_t {
    enum agent type;
    enum status status;
    pid_t pid;
    char sock[PATH_MAX];
    char gpg[PATH_MAX];
    char unit_path[PATH_MAX];
};

extern const struct agent_t Agent[LAST_AGENT];

int envoy_agent(struct agent_data_t *data, struct agent_request_t *req);
enum agent lookup_agent(const char *string);

#endif

// vim: et:sts=4:sw=4:cino=(0
