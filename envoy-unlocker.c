#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <getopt.h>
#include <signal.h>
#include <termios.h>

#include "lib/envoy.h"
#include "gpg-protocol.h"

bool termios_dirty = false;
struct termios old_termios;

static void sighandler(int signum)
{
    switch (signum) {
    case SIGINT:
    case SIGTERM:
        tcsetattr(fileno(stdin), TCSAFLUSH, &old_termios);
        exit(EXIT_SUCCESS);
    }
}

static int get_agent(struct agent_data_t *data, enum agent id, bool start)
{
    int ret = envoy_agent(data, id, start);
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

static ssize_t read_password(char **password)
{
    struct termios new_termios;
    size_t len = 0;
    ssize_t nbytes_r;

    fputs("Password: ", stdout);
    fflush(stdout);

    if (tcgetattr(fileno(stdin), &old_termios) < 0)
        err(EXIT_FAILURE, "failed to get terminal attributes");

    new_termios = old_termios;
    new_termios.c_lflag &= ~ECHO;

    if (tcsetattr(fileno(stdin), TCSAFLUSH, &new_termios) < 0)
        err(EXIT_FAILURE, "failed to set terminal attributes");

    nbytes_r = getline(password, &len, stdin);
    if (nbytes_r < 0)
        err(EXIT_FAILURE, "failed to read password");

    (*password)[--nbytes_r] = 0;
    tcsetattr(fileno(stdin), TCSAFLUSH, &old_termios);

    putchar('\n');
    return nbytes_r;
}

static int unlock(const struct agent_data_t *data, const char *password)
{
    struct gpg_t *agent = gpg_agent_connection(data->gpg);
    if (!agent)
        err(EXIT_FAILURE, "failed to open connection to gpg-agent");

    const struct fingerprint_t *fgpt = gpg_keyinfo(agent);
    for (; fgpt; fgpt = fgpt->next) {
        printf("unlocking %s...\n", fgpt->fingerprint);

        if (gpg_preset_passphrase(agent, fgpt->fingerprint, -1, password) < 0) {
            fprintf(stderr, "failed to unlock!\n");
            return 1;
        }
    }

    gpg_close(agent);
    return 0;
}

static void __attribute__((__noreturn__)) usage(FILE *out)
{
    fprintf(out, "usage: %s [-p password]\n", program_invocation_short_name);
    fputs("Options:\n"
        " -h, --help            display this help\n"
        " -v, --version         display version\n"
        " -p, --password        provide the password as an argument\n", out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    struct agent_data_t data;
    char *password = NULL;

    static const struct option opts[] = {
        { "help",    no_argument, 0, 'h' },
        { "version", no_argument, 0, 'v' },
        { "pasword", required_argument, 0, 'p' },
        { 0, 0, 0, 0 }
    };

    while (true) {
        int opt = getopt_long(argc, argv, "hvp:", opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'h':
            usage(stdout);
            break;
        case 'v':
            printf("%s %s\n", program_invocation_short_name, ENVOY_VERSION);
            return 0;
        case 'p':
            password = optarg;
            break;
        default:
            usage(stderr);
        }
    }

    if (get_agent(&data, AGENT_DEFAULT, true) < 0)
        errx(EXIT_FAILURE, "recieved no data, did the agent fail to start?");

    if (data.type != AGENT_GPG_AGENT) {
        fprintf(stderr, "Unlocking is only supported for gpg-agent.");
        return 1;
    }

    signal(SIGTERM, sighandler);
    signal(SIGINT,  sighandler);

    if (password == NULL)
        read_password(&password);

    return unlock(&data, password);
}
