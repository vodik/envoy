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

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

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
        _cleanup_gpg_ struct gpg_t *agent = gpg_agent_connection(data.gpg, NULL);
        gpg_update_tty(agent);
    }

    if (data.gpg[0])
        putenvf("GPG_AGENT_INFO=%s", data.gpg);
    putenvf("SSH_AUTH_SOCK=%s", data.sock);
}

static inline int safe_execv(const char *path, char *const argv[])
{
    _cleanup_free_ char *real = realpath(path, NULL);
    if (real && streq(real, exe_path))
        return 0;
    return execv(path, argv);
}

static char *extract_binary(char *path)
{
    struct stat st;
    char *memblock, *command = NULL;

    _cleanup_close_ int fd = open(path, O_RDONLY);
    if (fd < 0)
        return command;

    fstat(fd, &st);
    memblock = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED | MAP_POPULATE, fd, 0);
    madvise(memblock, st.st_size, MADV_WILLNEED | MADV_SEQUENTIAL);

    if (memblock[0] != '#' || memblock[1] != '!')
        goto error;

    memblock += strcspn(memblock, "\n");
    while (*memblock++ == '\n') {
        memblock += strspn(memblock, "\t ");
        if (memblock[0] == '\0')
            break;

        size_t eol = strcspn(memblock, "\n");
        if (*memblock == '#') {
            memblock += eol;
            continue;
        } else {
            command = strndup(memblock, eol);
            goto error;
        }
    }

error:
    memblock != MAP_FAILED ? munmap(memblock, st.st_size) : 0;
    return command;
}

static _noreturn_ void exec_from_path(const char *cmd, char *argv[])
{
    char *path = strdup(getenv("PATH"));
    if (!path)
        errx(EXIT_FAILURE, "command %s not found", cmd);

    char *saveptr = NULL, *segment = strtok_r(path, ":", &saveptr);
    for (; segment; segment = strtok_r(NULL, ":", &saveptr)) {
        char *full_path = joinpath(segment, cmd, NULL);
        safe_execv(full_path, argv);
        free(full_path);
    }

    errx(EXIT_FAILURE, "command %s not found", cmd);
}

static _noreturn_ void exec_wrapper(int argc, char *argv[])
{
    /* command + NULL + argv */
    char *new_argv[argc + 1];
    char *cmd = extract_binary(argv[0]);
    int i;

    if (cmd) {
        exe_path = argv[0];
    } else {
        cmd = argv[0];
        exe_path = realpath("/proc/self/exe", NULL);
        if (!exe_path)
            err(EXIT_FAILURE, "failed to resolve /proc/self/exe");
    }

    new_argv[0] = cmd;
    for (i = 1; i < argc; i++)
        new_argv[i] = argv[i];
    new_argv[argc] = NULL;

    if (cmd[0] == '/' || cmd[0] == '.') {
        safe_execv(cmd, new_argv);
        // If the exec failed, the wrapper was called by its full path
        cmd = program_invocation_short_name;
    }
    exec_from_path(cmd, new_argv);
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

    static const struct option opts[] = {
        { "help",    no_argument,       0, 'h' },
        { "version", no_argument,       0, 'v' },
        { "agent",   required_argument, 0, 't' },
        { 0, 0, 0, 0 }
    };

    if (streq(program_invocation_short_name, "envoy-exec")) {
        while (true) {
            int opt = getopt_long(argc, argv, "+hvt:", opts, NULL);
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
                usage(stderr);
            }
        }

        argc -= optind;
        argv += optind;

        if (argc == 0)
            usage(stderr);
    }

    source_agent_env(type);
    exec_wrapper(argc, argv);
}

// vim: et:sts=4:sw=4:cino=(0
