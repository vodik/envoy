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

#pragma once

#include <stdbool.h>
#include <limits.h>
#include <sys/types.h>

enum agent {
    AGENT_DEFAULT = -1,
    AGENT_SSH_AGENT = 0,
    AGENT_GPG_AGENT,
};

enum status {
    ENVOY_STOPPED = 0,
    ENVOY_STARTED,
    ENVOY_RUNNING,
    ENVOY_FAILED,
    ENVOY_BADUSER,
};

enum options {
    AGENT_DEFAULTS = 0,
    AGENT_STATUS   = 1 << 0,
    AGENT_ENVIRON  = 1 << 1,
    AGENT_KILL     = 1 << 2
};

struct agent_t {
    const char *name[2];
    char *const *argv;
};

struct agent_request_t {
    enum agent type;
    enum options opts;
};

struct agent_data_t {
    enum agent type;
    enum status status;
    char sock[PATH_MAX];
    char gpg[PATH_MAX];
    char unit_path[PATH_MAX];
};

static inline bool agent_running(struct agent_data_t *data)
{
    return data->status == ENVOY_STARTED || data->status == ENVOY_RUNNING;
}

static inline bool agent_started(struct agent_data_t *data)
{
    return data->status == ENVOY_STARTED;
}

extern const struct agent_t Agent[];

int envoy_get_agent(enum agent type, struct agent_data_t *data, enum options opts);
int envoy_kill_agent(enum agent type);

enum agent lookup_agent(const char *string);

// vim: et:sts=4:sw=4:cino=(0
