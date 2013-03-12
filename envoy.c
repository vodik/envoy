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

#include "common.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
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
    ACTION_NONE,
    ACTION_FORCE_ADD,
    ACTION_CLEAR,
    ACTION_KILL,
    ACTION_LIST,
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

static void __attribute__((__noreturn__)) add_keys(char **keys, int count)
{
    /* command + end-of-opts + NULL + keys */
    char *args[count + 3];
    struct passwd *pwd;
    int i;

    pwd = getpwuid(getuid());
    if (pwd == NULL || pwd->pw_dir == NULL)
        err(EXIT_FAILURE, "failed to lookup passwd entry");

    args[0] = "/usr/bin/ssh-add";
    args[1] = "--";

    for (i = 0; i < count; i++)
        args[2 + i] = get_key_path(pwd->pw_dir, keys[i]);

    args[2 + count] = NULL;

    execv(args[0], args);
    err(EXIT_FAILURE, "failed to launch ssh-add");
}

static int __attribute__((format (printf, 2, 3))) gpg_send_message(int fd, const char *fmt, ...)
{
    va_list ap;
    int nbytes;
    char buf[BUFSIZ];

    va_start(ap, fmt);
    nbytes = vsnprintf(buf, BUFSIZ - 1, fmt, ap);
    va_end(ap);

    buf[nbytes++] = '\n';
    if (write(fd, buf, nbytes) < 0)
        return -1;

    if (read(fd, buf, BUFSIZ) < 0)
        return -1;

    return !strncmp(buf, "OK\n", 3);
}

static void gpg_send_messages(int fd)
{
    const char *display = getenv("DISPLAY");
    const char *tty = ttyname(STDIN_FILENO);
    const char *term = getenv("TERM");

    gpg_send_message(fd, "RESET");

    if (tty)
        gpg_send_message(fd, "OPTION ttyname=%s", tty);

    if (term)
        gpg_send_message(fd, "OPTION ttytype=%s", term);

    if (display) {
        struct passwd *pwd = getpwuid(getuid());
        if (pwd == NULL || pwd->pw_dir == NULL)
            err(EXIT_FAILURE, "failed to lookup passwd entry");

        gpg_send_message(fd, "OPTION display=%s", display);
        gpg_send_message(fd, "OPTION xauthority=%s/.Xauthority", pwd->pw_dir);
    }

    gpg_send_message(fd, "UPDATESTARTUPTTY");
}

static int gpg_update_tty(const char *sock)
{
    char buf[BUFSIZ], *split;
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    size_t len;
    socklen_t sa_len;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0), nbytes;
    if (fd < 0)
        err(EXIT_FAILURE, "couldn't create socket");

    split = strchr(sock, ':');
    len = split - sock;

    sa.un = (struct sockaddr_un){ .sun_family = AF_UNIX };
    memcpy(&sa.un.sun_path, sock, len);

    sa_len = len + sizeof(sa.un.sun_family);
    if (connect(fd, &sa.sa, sa_len) < 0)
        err(EXIT_FAILURE, "failed to connect to gpg-agent");

    nbytes = read(fd, buf, BUFSIZ);
    if (nbytes < 0)
        err(EXIT_FAILURE, "failed to read from gpg-agent socket");

    if (strncmp(buf, "OK", 2) != 0)
        errx(EXIT_FAILURE, "incorrect response from gpg-agent");

    gpg_send_messages(fd);
    close(fd);
    return 0;
}

static void print_env(struct agent_data_t *data)
{
    if (data->type == AGENT_GPG_AGENT)
        printf("export GPG_AGENT_INFO='%s'\n", data->gpg);

    printf("export SSH_AUTH_SOCK='%s'\n", data->sock);
    printf("export SSH_AGENT_PID='%d'\n", data->pid);
}

static void source_env(struct agent_data_t *data)
{
    if (data->type == AGENT_GPG_AGENT)
        gpg_update_tty(data->gpg);

    setenv("SSH_AUTH_SOCK", data->sock, true);
}

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
        errx(EXIT_FAILURE, "envoyd reported agent stopped twice?");

    return rc;
}

static bool get_agent(struct agent_data_t *data, enum agent id, bool start)
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

static void __attribute__((__noreturn__)) exec_wrapper(const char *cmd, int argc, char *argv[])
{
    /* command + NULL + argv */
    struct agent_data_t data;
    char *args[argc + 1];
    int i;

    if (get_agent(&data, AGENT_DEFAULT, true) == 0)
        errx(EXIT_FAILURE, "recieved no data, did the agent fail to start?");

    asprintf(&args[0], "/usr/bin/%s", cmd);
    for (i = 0; i < argc - 1; i++)
        args[1 + i] = argv[1 + i];
    args[argc] = NULL;

    source_env(&data);
    execv(args[0], args);
    err(EXIT_FAILURE, "failed to launch ssh");
}

static void __attribute__((__noreturn__)) usage(FILE *out)
{
    fprintf(out, "usage: %s [options] [files ...]\n", program_invocation_short_name);
    fputs("Options:\n"
        " -h, --help            display this help\n"
        " -v, --version         display version\n"
        " -a, --add             add private key identities\n"
        " -k, --clear           force identities to expire (gpg-agent only)\n"
        " -K, --kill            kill the running agent\n"
        " -l, --list            list fingerprints of all loaded identities\n"
        " -p, --print           print out environmental arguments\n"
        " -t, --agent=AGENT     set the prefered to start\n", out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    bool source = true;
    struct agent_data_t data;
    enum action verb = ACTION_NONE;
    enum agent type = AGENT_DEFAULT;

    static const struct option opts[] = {
        { "help",    no_argument, 0, 'h' },
        { "version", no_argument, 0, 'v' },
        { "add",     no_argument, 0, 'a' },
        { "clear",   no_argument, 0, 'k' },
        { "kill",    no_argument, 0, 'K' },
        { "list",    no_argument, 0, 'l' },
        { "print",   no_argument, 0, 'p' },
        { "agent",   required_argument, 0, 't' },
        { 0, 0, 0, 0 }
    };

    if (strcmp(program_invocation_short_name, "ssh") == 0 ||
        strcmp(program_invocation_short_name, "scp") == 0) {
        exec_wrapper(program_invocation_short_name, argc, argv);
    }

    while (true) {
        int opt = getopt_long(argc, argv, "hvakKlpt:", opts, NULL);
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
            verb = ACTION_FORCE_ADD;
            break;
        case 'k':
            verb = ACTION_CLEAR;
            source = false;
            break;
        case 'K':
            verb = ACTION_KILL;
            source = false;
            break;
        case 'l':
            verb = ACTION_LIST;
            break;
        case 'p':
            verb = ACTION_PRINT;
            break;
        case 't':
            type = find_agent(optarg);
            if (type == LAST_AGENT)
                errx(EXIT_FAILURE, "unknown agent: %s", optarg);
            break;
        default:
            usage(stderr);
        }
    }

    if (get_agent(&data, type, source) == 0)
        errx(EXIT_FAILURE, "recieved no data, did the agent fail to start?");

    if (data.status == ENVOY_STOPPED)
        return 0;

    if (source)
        source_env(&data);

    switch (verb) {
    case ACTION_PRINT:
        print_env(&data);
        /* fall through */
    case ACTION_NONE:
        if (data.status == ENVOY_RUNNING || data.type == AGENT_GPG_AGENT)
            break;
        /* fall through */
    case ACTION_FORCE_ADD:
        add_keys(&argv[optind], argc - optind);
        break;
    case ACTION_CLEAR:
        if (data.type == AGENT_GPG_AGENT)
            kill(data.pid, SIGHUP);
        else
            errx(EXIT_FAILURE, "only gpg-agent supports this operation");
        break;
    case ACTION_KILL:
        kill(data.pid, SIGTERM);
        break;
    case ACTION_LIST:
        execl("/usr/bin/ssh-add", "ssh-add", "-l", NULL);
        err(EXIT_FAILURE, "failed to launch ssh-add");
    default:
        break;
    }

    return 0;
}

// vim: et:sts=4:sw=4:cino=(0
