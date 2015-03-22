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
#include <stdarg.h>
#include <getopt.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>
#include <unistd.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "agents.h"
#include "socket.h"
#include "gpg-protocol.h"
#include "util.h"

static struct termios old_termios;

enum action {
    ACTION_PRINT,
    ACTION_NONE,
    ACTION_FORCE_ADD,
    ACTION_KILL,
    ACTION_RELOAD,
    ACTION_LIST,
    ACTION_UNLOCK,
    ACTION_INVALID
};

static void term_cleanup(void)
{
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_termios);
}

static ssize_t read_password(char **password)
{
    struct termios new_termios;
    size_t len = 0;
    ssize_t nbytes_r;

    fputs("Password: ", stdout);
    fflush(stdout);

    if (tcgetattr(fileno(stdin), &old_termios) < 0)
        err(EXIT_FAILURE, "failed to get terminal attributes");

    atexit(term_cleanup);

    new_termios = old_termios;
    new_termios.c_lflag &= ~ECHO;

    if (tcsetattr(fileno(stdin), TCSAFLUSH, &new_termios) < 0)
        err(EXIT_FAILURE, "failed to set terminal attributes");

    nbytes_r = getline(password, &len, stdin);
    if (nbytes_r < 0)
        errx(EXIT_FAILURE, "failed to read password");

    (*password)[--nbytes_r] = 0;
    tcsetattr(fileno(stdin), TCSAFLUSH, &old_termios);

    putchar('\n');
    return nbytes_r;
}

static int get_agent(struct agent_data_t *data, enum agent id, bool start, bool env)
{
    enum options options = start ? AGENT_DEFAULTS : AGENT_STATUS;
    if (env)
        options |= AGENT_ENVIRON;

    int ret = envoy_get_agent(id, data, options);
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

static char *get_key_path(const char *home, const char *fragment)
{
    /* path exists, add it */
    if (fragment[0] == '-' || access(fragment, F_OK) == 0)
        return strdup(fragment);

    /* assume it's a key in $HOME/.ssh */
    return joinpath(home, ".ssh", fragment, NULL);
}

static _noreturn_ void add_keys(char **keys, int count)
{
    /* command + end-of-opts + NULL + keys */
    const char *home_dir = get_home_dir();
    char *args[count + 3];
    int i;

    args[0] = "/usr/bin/ssh-add";
    args[1] = "--";

    for (i = 0; i < count; i++)
        args[2 + i] = get_key_path(home_dir, keys[i]);

    args[2 + count] = NULL;

    execv(args[0], args);
    err(EXIT_FAILURE, "failed to launch ssh-add");
}

static void print_sh_env(struct agent_data_t *data)
{
    if (data->type == AGENT_GPG_AGENT && data->gpg[0])
        printf("export GPG_AGENT_INFO='%s'\n", data->gpg);

    printf("export SSH_AUTH_SOCK='%s'\n", data->sock);
}

static void print_csh_env(struct agent_data_t *data)
{
    if (data->type == AGENT_GPG_AGENT && data->gpg[0])
        printf("setenv GPG_AGENT_INFO '%s';\n", data->gpg);

    printf("setenv SSH_AUTH_SOCK '%s';\n", data->sock);
}

static void print_fish_env(struct agent_data_t *data)
{
    if (data->type == AGENT_GPG_AGENT && data->gpg[0])
        printf("set -x GPG_AGENT_INFO '%s';\n", data->gpg);

    printf("set -x SSH_AUTH_SOCK '%s';\n", data->sock);
}

static void source_env(struct agent_data_t *data)
{
    if (data->type == AGENT_GPG_AGENT) {
        _cleanup_gpg_ struct gpg_t *agent = gpg_agent_connection(data->gpg, NULL);
        if (!agent)
            warn("failed to connect to GPG_AUTH_SOCK");
        else
            gpg_update_tty(agent);
    }

    putenvf("SSH_AUTH_SOCK=%s", data->sock);
}

static void reload_agent(struct agent_data_t *data)
{
    if (data->type != AGENT_GPG_AGENT)
        errx(EXIT_FAILURE, "only gpg-agent supports this operation");

    _cleanup_gpg_ struct gpg_t *agent = gpg_agent_connection(data->gpg, NULL);
    if (!agent)
        err(EXIT_FAILURE, "failed to connect to GPG_AUTH_SOCK");

    gpg_reload_agent(agent);
}

static int unlock(const struct agent_data_t *data, char *password)
{
    if (data->type != AGENT_GPG_AGENT)
        errx(EXIT_FAILURE, "only gpg-agent supports this operation");

    _cleanup_gpg_ struct gpg_t *agent = gpg_agent_connection(data->gpg, NULL);
    if (!agent)
        err(EXIT_FAILURE, "failed to connect to GPG_AUTH_SOCK");

    if (!password)
        read_password(&password);

    const struct fingerprint_t *fgpt = gpg_keyinfo(agent);
    for (; fgpt; fgpt = fgpt->next) {
        if (fgpt->flags & KEY_DISABLED)
            continue;

        if (gpg_preset_passphrase(agent, fgpt->fingerprint, -1, password) < 0) {
            warnx("failed to unlock key '%s'", fgpt->fingerprint);
            return 1;
        }
    }

    return 0;
}

static _noreturn_ void usage(FILE *out)
{
    fprintf(out, "usage: %s [options] [key ...]\n", program_invocation_short_name);
    fputs("Options:\n"
        " -h, --help            display this help\n"
        " -v, --version         display version\n"
        " -d, --defer           defer adding keys until the next envoy invocation\n"
        " -a, --add             add private key identities\n"
        " -k, --kill            kill the running agent\n"
        " -r, --reload          reload the agent (gpg-agent only)\n"
        " -l, --list            list fingerprints of all loaded identities\n"
        " -u, --unlock=[PASS]   unlock the agent's keyring (gpg-agent only)\n"
        " -p, --print           print out environmental arguments\n"
        " -s, --sh              print sh style commands\n"
        " -c, --csh             print csh style commands\n"
        " -f, --fish            print fish style commands\n"
        " -t, --agent=AGENT     set the preferred to start\n", out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    bool source = true;
    bool defer = false;
    struct agent_data_t data;
    char *password = NULL;
    enum action verb = ACTION_NONE;
    enum agent type = AGENT_DEFAULT;
    void (*print_env)(struct agent_data_t *data) = print_sh_env;

    static const struct option opts[] = {
        { "help",    no_argument,       0, 'h' },
        { "version", no_argument,       0, 'v' },
        { "defer",   no_argument,       0, 'd' },
        { "add",     no_argument,       0, 'a' },
        { "kill",    no_argument,       0, 'k' },
        { "reload",  no_argument,       0, 'r' },
        { "list",    no_argument,       0, 'l' },
        { "unlock",  optional_argument, 0, 'u' },
        { "print",   no_argument,       0, 'p' },
        { "sh",      no_argument,       0, 's' },
        { "csh",     no_argument,       0, 'c' },
        { "fish",    no_argument,       0, 'f' },
        { "agent",   required_argument, 0, 't' },
        { 0, 0, 0, 0 }
    };

    while (true) {
        int opt = getopt_long(argc, argv, "hvdakrlu::pscft:", opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'h':
            usage(stdout);
            break;
        case 'v':
            printf("%s %s\n", program_invocation_short_name, ENVOY_VERSION);
            return 0;
        case 'd':
            defer = true;
            break;
        case 'a':
            verb = ACTION_FORCE_ADD;
            defer = false;
            break;
        case 'k':
            verb = ACTION_KILL;
            source = false;
            break;
        case 'r':
            verb = ACTION_RELOAD;
            source = false;
            break;
        case 'l':
            verb = ACTION_LIST;
            break;
        case 'u':
            verb = ACTION_UNLOCK;
            password = optarg;
            break;
        case 'p':
            verb = ACTION_PRINT;
            break;
        case 's':
            print_env = print_sh_env;
            break;
        case 'c':
            print_env = print_csh_env;
            break;
        case 'f':
            print_env = print_fish_env;
            break;
        case 't':
            type = lookup_agent(optarg);
            if (type < 0)
                errx(EXIT_FAILURE, "unknown agent: %s", optarg);
            break;
        default:
            usage(stderr);
        }
    }

    if (get_agent(&data, type, source, defer) < 0)
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
        if (data.type == AGENT_GPG_AGENT || !agent_started(&data))
            break;
        if (defer)
            break;
        /* fall through */
    case ACTION_FORCE_ADD:
        add_keys(&argv[optind], argc - optind);
        break;
    case ACTION_KILL:
        if (envoy_kill_agent(type) < 0)
            errx(EXIT_FAILURE, "failed to kill agent");
        break;
    case ACTION_RELOAD:
        reload_agent(&data);
        break;
    case ACTION_LIST:
        execlp("ssh-add", "ssh-add", "-l", NULL);
        err(EXIT_FAILURE, "failed to launch ssh-add");
    case ACTION_UNLOCK:
        unlock(&data, password);
        break;
    default:
        break;
    }

    return 0;
}

// vim: et:sts=4:sw=4:cino=(0
