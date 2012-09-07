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
#include <getopt.h>
#include <err.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

enum action {
    ACTION_PRINT,
    ACTION_ADD,
    ACTION_FORCE_ADD,
    ACTION_INVALID
};

static void ssh_key_add(int argc, char *argv[])
{
    char *args[argc + 2];
    int i;

    for (i = 0; i < argc; ++i)
        args[i + 1] = argv[i];

    args[0] = "ssh-add";
    args[argc + 1] = NULL;

    if (execvp(args[0], args) < 0)
        err(EXIT_FAILURE, "failed to start ssh-add");
}

static int get_agent(struct agent_data_t *data)
{
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;

    int fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        err(EXIT_FAILURE, "couldn't create socket");

    memset(&sa, 0, sizeof(sa));
    sa.un.sun_family = AF_UNIX;
    strncpy(sa.un.sun_path, SOCK_PATH, sizeof(sa.un.sun_path));

    if (connect(fd, &sa.sa, sizeof(sa)) < 0)
        err(EXIT_FAILURE, "failed to connect");

    int rc = read(fd, data, sizeof(*data));

    close(fd);
    return rc;
}

int main(int argc, char *argv[])
{
    struct agent_data_t data;
    enum action verb = ACTION_ADD;

    static const struct option opts[] = {
        { "print", no_argument, 0, 'p' },
        { "add",   no_argument, 0, 'a' },
        { 0, 0, 0, 0 }
    };

    while (true) {
        int opt = getopt_long(argc, argv, "pa", opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'p':
            verb = ACTION_PRINT;
            break;
        case 'a':
            verb = ACTION_FORCE_ADD;
            break;
        default:
            return EXIT_FAILURE;
        }
    }

    argv += optind;
    argc -= optind;

    if (get_agent(&data) < 0)
        err(EXIT_FAILURE, "failed to read data");

    setenv("SSH_AUTH_SOCK", data.sock, true);

    switch (verb) {
    case ACTION_PRINT:
        printf("export SSH_AUTH_SOCK=%s\n",  data.sock);
        printf("export SSH_AGENT_PID=%ld\n", (long)data.pid);
    case ACTION_ADD:
        if (!data.first_run)
            return 0;
    case ACTION_FORCE_ADD:
        ssh_key_add(argc, argv);
        break;
    default:
        break;
    }

    return 0;
}

// vim: et:sts=4:sw=4:cino=(0
