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
#include <getopt.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>

#include "agents.h"
#include "socket.h"
#include "gpg-protocol.h"
#include "util.h"

static const char *exe_path;

static void source_agent_env(enum agent id)
{
    struct agent_data_t data;
    int ret = envoy_get_agent(id, &data, AGENT_ENVIRON);
    if (ret < 0)
        warn("failed to fetch envoy agent");

    switch (data.status) {
    case ENVOY_STOPPED:
    case ENVOY_STARTED:
    case ENVOY_RUNNING:
        break;
    case ENVOY_FAILED:
        warnx("agent failed to start, check envoyd's log");
    case ENVOY_BADUSER:
        warnx("connection rejected, user is unauthorized to use this agent");
    }

    if (data.type == AGENT_GPG_AGENT) {
        _cleanup_gpg_ struct gpg_t *agent = gpg_agent_connection(data.gpg);
        gpg_update_tty(agent);

        putenvf("GPG_AGENT_INFO=%s", data.gpg);
    } else {
        unsetenv("GPG_AGENT_INFO");
    }

    putenvf("SSH_AUTH_SOCK=%s", data.sock);
    putenvf("SSH_AGENT_PID=%d", data.pid);
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
    char *args[argc + 1];
    int i;

    for (i = 0; i < argc; i++)
        args[i] = argv[i];
    args[argc] = NULL;

    if (cmd[0] == '/') {
        safe_execv(args[0], args);
    } else {
        const char *path = getenv("PATH");
        if (!path)
            errx(EXIT_FAILURE, "command %s not found", cmd);
        _cleanup_free_ char *buf = strdup(path);

        char *saveptr, *segment = strtok_r(buf, ":", &saveptr);
        for (; segment; segment = strtok_r(NULL, ":", &saveptr)) {
            char *full_path = joinpath(segment, cmd, NULL);
            safe_execv(full_path, args);
            free(full_path);
        }
    }

    errx(EXIT_FAILURE, "command %s not found", cmd);
}

static _noreturn_ void usage(FILE *out)
{
    fprintf(out, "usage: %s [options]\n", program_invocation_short_name);
    fputs("Options:\n"
        " -h, --help            display this help and exit\n"
        " -v, --version         display version\n"
        " -t, --agent=AGENT     set the agent to start\n", out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    enum agent type = AGENT_DEFAULT;
    const char *path;

    static const struct option opts[] = {
        { "help",    no_argument,       0, 'h' },
        { "version", no_argument,       0, 'v' },
        { "agent",   required_argument, 0, 't' },
        { 0, 0, 0, 0 }
    };

    exe_path = realpath("/proc/self/exe", NULL);
    if (!exe_path)
        err(EXIT_FAILURE, "failed to resolve /proc/self/exe");

    if (!streq(program_invocation_short_name, "envoy-exec")) {
        path = argv[0];
    } else {
        opterr = 0;

        while (true) {
            int opt = getopt_long(argc, argv, "hvt:", opts, NULL);
            if (opt == -1)
                break;

            switch (opt) {
            case 'h':
                usage(stdout);
                break;
            case 'v':
                printf("%s %s\n", program_invocation_short_name, ENVOY_VERSION);
                return 0;
            case 't':
                type = lookup_agent(optarg);
                if (type < 0)
                    errx(EXIT_FAILURE, "unknown agent: %s", optarg);
                break;
            default:
                break;
            }
        }

        path = argv[optind];
        argc -= optind;
        argv += optind;

        if (argc == 0)
            usage(stderr);
    }

    source_agent_env(type);
    exec_wrapper(path, argc, argv);
}

// vim: et:sts=4:sw=4:cino=(0
