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
#include <string.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>

#include "agents.h"
#include "socket.h"
#include "gpg-protocol.h"
#include "util.h"

static const char *exe_path;

static int get_agent(struct agent_data_t *data, enum agent id)
{
    int ret = envoy_agent_get_environment(id, data);
    if (ret < 0)
        err(EXIT_FAILURE, "failed to fetch agent");

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

    return ret;
}

static void source_env(struct agent_data_t *data)
{
    if (data->type == AGENT_GPG_AGENT) {
        _cleanup_gpg_ struct gpg_t *agent = gpg_agent_connection(data->gpg);
        gpg_update_tty(agent);

        setenv("GPG_AGENT_INFO", data->gpg, true);
    }

    setenv("SSH_AUTH_SOCK", data->sock, true);
}

static inline int safe_execv(const char *path, char *const argv[])
{
    _cleanup_free_ char *real = realpath(path, NULL);

    if (real && streq(real, exe_path))
        return 0;

    return execv(path, argv);
}

static _noreturn_ void exec_wrapper(const char *cmd, int argc, char *argv[])
{
    /* command + NULL + argv */
    struct agent_data_t data;
    char *args[argc + 1];
    int i;

    if (get_agent(&data, AGENT_DEFAULT) < 0)
        errx(EXIT_FAILURE, "recieved no data, did the agent fail to start?");

    for (i = 0; i < argc; i++)
        args[i] = argv[i];
    args[argc] = NULL;

    source_env(&data);
    if (cmd[0] == '/') {
        safe_execv(args[0], args);
    } else {
        const char *path = getenv("PATH");
        if (!path)
            err(EXIT_FAILURE, "command %s not found", cmd);
        _cleanup_free_ char *buf = strdup(path);

        char *saveptr, *segment = strtok_r(buf, ":", &saveptr);
        for (; segment; segment = strtok_r(NULL, ":", &saveptr)) {
            _cleanup_free_ char *full_path;

            safe_asprintf(&full_path, "%s/%s", segment, cmd);
            safe_execv(full_path, args);
        }
    }

    err(EXIT_FAILURE, "command %s not found", cmd);
}

int main(int argc, char *argv[])
{
    exe_path = realpath("/proc/self/exe", NULL);
    if (!exe_path)
        err(EXIT_FAILURE, "failed to resolve /proc/self/exe");

    if (!streq(program_invocation_short_name, "envoy-exec"))
        exec_wrapper(program_invocation_short_name, argc, argv);

    if (argc == 1) {
        fprintf(stderr, "usage: %s command\n", program_invocation_short_name);
        return 1;
    }

    exec_wrapper(argv[1], argc - 1, argv + 1);
}

// vim: et:sts=4:sw=4:cino=(0
