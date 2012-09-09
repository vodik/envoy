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
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

enum action {
    ACTION_PRINT,
    ACTION_ADD,
    ACTION_FORCE_ADD,
    ACTION_KILL,
    ACTION_INVALID
};

static char *get_key_path(const char *home, const char *fragment)
{
    char *out;

    /* path exists, add it */
    if (access(fragment, F_OK) == 0)
        return strdup(fragment);

    /* assume it's a key in $HOME/.ssh */
    if (asprintf(&out, "%s/.ssh/%s", home, fragment) < 0)
        err(EXIT_FAILURE, "failed to allocate memory");

    return out;
}

static void add_keys(char **keys, int count, int first_run)
{
    struct passwd *pwd;
    char **argv;
    int i;

    if (count == 0 && !first_run)
        errx(EXIT_FAILURE, "no keys specified");

    pwd = getpwuid(getuid());
    if (pwd == NULL || pwd->pw_dir == NULL)
        /* unlikely */
        err(EXIT_FAILURE, "failed to lookup passwd entry");

    /* command + end-of-opts + NULL + keys */
    if (first_run && count == 0)
        argv = calloc(1 + 3, sizeof(char*));
    else
        argv = calloc(count + 3, sizeof(char*));

    if (argv == NULL)
        err(EXIT_FAILURE, "failed to allocate memory");

    argv[0] = "/usr/bin/ssh-add";
    argv[1] = "--";

    /* if none specified, add ~/.ssh/id_rsa */
    if (count == 0) {
        argv[2] = get_key_path(pwd->pw_dir, "id_rsa");
        argv[3] = NULL;
    } else {
        for (i = 0; i < count; i++)
            argv[2 + i] = get_key_path(pwd->pw_dir, keys[i]);
        argv[2 + i] = NULL;
    }

    execv(argv[0], argv);
    err(EXIT_FAILURE, "failed to launch ssh-add");
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

static void __attribute__((__noreturn__)) usage(FILE *out)
{
    fprintf(out, "usage: %s [options] [files ...]\n", program_invocation_short_name);
    fputs("Options:\n"
        " -h, --help       display this help and exit\n"
        " -v, --version    display version\n"
        " -a, --add        also add keys (default)\n"
        " -k, --kill       kill the running ssh-agent\n"
        " -p, --print      print out environmental arguments\n", out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    struct agent_data_t data;
    enum action verb = ACTION_ADD;

    static const struct option opts[] = {
        { "help",    no_argument, 0, 'h' },
        { "version", no_argument, 0, 'v' },
        { "add",     no_argument, 0, 'a' },
        { "kill",    no_argument, 0, 'k' },
        { "print",   no_argument, 0, 'p' },
        { 0, 0, 0, 0 }
    };

    while (true) {
        int opt = getopt_long(argc, argv, "hvakp", opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'h':
            usage(stdout);
            break;
        case 'v':
            printf("%s %s\n", program_invocation_short_name, ENVOY_VERSION);
            return 0;
        case 'a':
            verb = ACTION_ADD;
            break;
        case 'k':
            verb = ACTION_KILL;
            break;
        case 'p':
            verb = ACTION_PRINT;
            break;
        default:
            usage(stderr);
        }
    }

    if (get_agent(&data) < 0)
        err(EXIT_FAILURE, "failed to read data");

    setenv("SSH_AUTH_SOCK", data.sock, true);

    switch (verb) {
    case ACTION_PRINT:
        printf("export SSH_AUTH_SOCK='%s'\n",  data.sock);
        printf("export SSH_AGENT_PID='%ld'\n", (long)data.pid);
        break;
    case ACTION_ADD:
        add_keys(&argv[optind], argc - optind, data.first_run);
        break;
    case ACTION_KILL:
        kill(data.pid, SIGTERM);
        break;
    default:
        break;
    }

    return 0;
}

// vim: et:sts=4:sw=4:cino=(0
