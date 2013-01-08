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

#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

enum agent_status {
    ENVOY_RUNNING = 0,
    ENVOY_FIRSTRUN
};

struct agent_data_t {
    pid_t pid;
    enum agent_status status;
    char sock[PATH_MAX];
    char gpg[PATH_MAX];
};

size_t init_envoy_socket(struct sockaddr_un *un);

#endif
