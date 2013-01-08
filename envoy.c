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

static void add_keys(char **keys, int count)
{
    /* command + end-of-opts + NULL + keys */
    char *argv[count + 3];
    struct passwd *pwd;
    int i;

    pwd = getpwuid(getuid());
    if (pwd == NULL || pwd->pw_dir == NULL)
        err(EXIT_FAILURE, "failed to lookup passwd entry");

    argv[0] = "/usr/bin/ssh-add";
    argv[1] = "--";

    for (i = 0; i < count; i++)
        argv[2 + i] = get_key_path(pwd->pw_dir, keys[i]);

    argv[2 + count] = NULL;

    execv(argv[0], argv);
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

static int gpg_update_tty(const char *sock)
{
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    socklen_t sa_len;

    char buf[BUFSIZ], *split;
    const char *display = NULL, *tty = NULL, *term = NULL;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0), nbytes;
    if (fd < 0)
        err(EXIT_FAILURE, "couldn't create socket");

    split = strchr(sock, ':');
    sa_len = split - sock + 2;

    memset(&sa, 0, sizeof(sa));
    sa.un.sun_family = AF_UNIX;
    memcpy(&sa.un.sun_path, sock, sa_len);

    if (connect(fd, &sa.sa, sa_len) < 0)
        err(EXIT_FAILURE, "failed to connect");

    nbytes = read(fd, buf, BUFSIZ);
    if (nbytes < 0)
        err(EXIT_FAILURE, "failed to read from gpg-agent socket");

    if (strncmp(buf, "OK", 2) != 0)
        errx(EXIT_FAILURE, "incorrect response from gpg-agent");

    gpg_send_message(fd, "RESET");

    tty = ttyname(STDIN_FILENO);
    if (tty)
        gpg_send_message(fd, "OPTION ttyname=%s", tty);

    term = getenv("TERM");
    if (term)
        gpg_send_message(fd, "OPTION ttytype=%s", getenv("TERM"));

    display = getenv("DISPLAY");
    if (display) {
        struct passwd *pwd = getpwuid(getuid());
        if (pwd == NULL || pwd->pw_dir == NULL)
            err(EXIT_FAILURE, "failed to lookup passwd entry");

        gpg_send_message(fd, "OPTION display=%s", display);
        gpg_send_message(fd, "OPTION xauthority=%s/.Xauthority", pwd->pw_dir);
    }

    gpg_send_message(fd, "UPDATESTARTUPTTY");

    close(fd);
    return 0;
}

static void print_env(struct agent_data_t *data)
{
    if (data->gpg[0])
        printf("export GPG_AGENT_INFO='%s'\n", data->gpg);

    printf("export SSH_AUTH_SOCK='%s'\n",  data->sock);
    printf("export SSH_AGENT_PID='%zd'\n", data->pid);
}

static void source_env(struct agent_data_t *data)
{
    setenv("SSH_AUTH_SOCK", data->sock, true);

    if (data->gpg[0]) {
        setenv("GPG_AGENT_INFO", data->gpg,  true);
        gpg_update_tty(data->gpg);
    }
}

static size_t get_agent(struct agent_data_t *data)
{
    size_t len;
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;

    int nbytes_r, fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        err(EXIT_FAILURE, "couldn't create socket");

    len = init_envoy_socket(&sa.un);
    if (connect(fd, &sa.sa, len) < 0)
        err(EXIT_FAILURE, "failed to connect");

    for (;;) {
        nbytes_r = read(fd, data, sizeof(*data));
        if (nbytes_r < 0) {
            if (errno != EAGAIN) {
                warn("failed to receive data from server");
                break;
            }
        } else
            break;
    }

    close(fd);

    switch (data->status) {
    case ENVOY_RUNNING:
    case ENVOY_FIRSTRUN:
        return nbytes_r;
    case ENVOY_BADUSER:
        errx(EXIT_FAILURE, "connection rejected, user is unauthorized to use this agent");
    }
}

static void __attribute__((__noreturn__)) usage(FILE *out)
{
    fprintf(out, "usage: %s [options] [files ...]\n", program_invocation_short_name);
    fputs("Options:\n"
        " -h, --help       display this help\n"
        " -v, --version    display version\n"
        " -a, --add        add private key identities\n"
        " -k, --clear      force identities to expire (gpg-agent only)\n"
        " -K, --kill       kill the running agent\n"
        " -l, --list       list fingerprints of all loaded identities\n"
        " -p, --print      print out environmental arguments\n", out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    bool source = true;
    struct agent_data_t data;
    enum action verb = ACTION_ADD;

    static const struct option opts[] = {
        { "help",    no_argument, 0, 'h' },
        { "version", no_argument, 0, 'v' },
        { "add",     no_argument, 0, 'a' },
        { "clear",   no_argument, 0, 'k' },
        { "kill",    no_argument, 0, 'K' },
        { "list",    no_argument, 0, 'l' },
        { "print",   no_argument, 0, 'p' },
        { 0, 0, 0, 0 }
    };

    while (true) {
        int opt = getopt_long(argc, argv, "hvakKlp", opts, NULL);
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
            source = false;
            break;
        default:
            usage(stderr);
        }
    }

    switch (get_agent(&data)) {
    case 0:
        errx(EXIT_FAILURE, "recieved no data, did ssh-agent fail to start?");
    default:
        break;
    }

    if (source)
        source_env(&data);

    switch (verb) {
    case ACTION_PRINT:
        if (data.gpg[0])
            gpg_update_tty(data.gpg);
        print_env(&data);
        break;
    case ACTION_ADD:
        /* when there are no agumert, with gpg-agent it should be a no op */
        if (!data.status == ENVOY_FIRSTRUN || data.gpg[0])
            return 0;
    case ACTION_FORCE_ADD:
        add_keys(&argv[optind], argc - optind);
        break;
    case ACTION_CLEAR:
        if (data.gpg[0])
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
