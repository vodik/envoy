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
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <pwd.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/signalfd.h>
#include <systemd/sd-daemon.h>

#include "agents.h"
#include "socket.h"
#include "dbus.h"
#include "util.h"

struct agent_node_t {
    uid_t uid;
    char *scope, *slice;
    struct agent_data_t d;
    struct agent_node_t *next;
};

static DBusConnection *bus = NULL;
static enum agent default_type = AGENT_SSH_AGENT;
static struct agent_node_t *agents = NULL;
static bool sd_activated = false;
static bool multiuser_mode;
static uid_t server_uid;

static union agent_environ_t {
    struct {
        char *path;
        char *home;
        char *gnupghome;
    } arg;
    char *const env[4];
} agent_env = {
    .env = { 0 }
};

static void cleanup(int fd)
{
    struct agent_node_t *node;

    if (!sd_activated) {
        close(fd);
        unlink_envoy_socket();
    }

    for (node = agents; node; node = node->next) {
        if (node->d.unit_path[0])
            stop_unit(bus, node->d.unit_path, NULL);
        else
            kill(node->d.pid, SIGTERM);
    }
}

static bool unit_running(struct agent_data_t *data)
{
    bool running = true;

    if (data->unit_path[0]) {
        _cleanup_free_ char *state = NULL;
        get_unit_state(bus, data->unit_path, &state);
        running = streq(state, "running");
    } else if (kill(data->pid, 0) < 0) {
        if (errno != ESRCH)
            err(EXIT_FAILURE, "something strange happened with kill");
        running = false;
    }

    return running;
}

static void init_agent_environ(void)
{
    extern char **environ;
    char *path = NULL, *gnupghome = NULL;
    int i;

    for (i = 0; environ[i]; ++i) {
        if (strneq(environ[i], "PATH=", 5))
            path = environ[i];
        else if (strneq(environ[i], "GNUPGHOME=", 10))
            gnupghome = environ[i];
    }

    agent_env.arg.path = path ? path : "PATH=/usr/local/bin:/usr/bin/:/bin";

    if (!gnupghome)
        return;
    if (!multiuser_mode)
        agent_env.arg.gnupghome = gnupghome;
    else
        fprintf(stderr, "warning: running as root and GNUPGHOME is set; ignoring.\n");
}

static void parse_agentdata_line(char *val, struct agent_data_t *data)
{
    val[strcspn(val, ";")] = 0;

    size_t sep = strcspn(val, "=");
    if (val[sep] == '\0')
        return;

    if (strneq(val, "SSH_AUTH_SOCK", sep))
        strcpy(data->sock, &val[sep + 1]);
    else if (strneq(val, "SSH_AGENT_PID", sep))
        data->pid = strtol(&val[sep + 1], NULL, 10);
    else if (strneq(val, "GPG_AGENT_INFO", sep))
        strcpy(data->gpg, &val[sep + 1]);
}

static int parse_agentdata(int fd, struct agent_data_t *data)
{
    char b[BUFSIZ];
    ssize_t bytes_r;
    char *l;

    bytes_r = read(fd, b, sizeof(b));
    if (bytes_r <= 0)
        return bytes_r;

    b[bytes_r] = '\0';
    l = &b[0];

    while (l < &b[bytes_r]) {
        size_t nl = strcspn(l, "\n");

        l[nl] = 0;
        parse_agentdata_line(l, data);
        l += nl + 1;
    }

    if (data->sock[0] == 0) {
        fprintf(stderr, "Did not receive SSH_AUTH_SOCK from agent, bailing...\n");
        return -1;
    }

    if (data->pid == 0) {
        if (data->gpg[0] == 0) {
            fprintf(stderr, "Did not receive SSH_AGENT_PID from agent, bailing...\n");
            return -1;
        }

        size_t sep = strcspn(data->gpg, ":");
        if (data->gpg[sep] == '\0') {
            fprintf(stderr, "Malformed GPG_AGENT_INFO, bailing...\n");
            return -1;
        }

        data->pid = strtol(&data->gpg[sep + 1], NULL, 10);
    }

    return 0;
}

static _noreturn_ void exec_agent(const struct agent_t *agent, uid_t uid, gid_t gid)
{
    struct passwd *pwd;

    if (setresgid(gid, gid, gid) < 0 || setresuid(uid, uid, uid) < 0)
        err(EXIT_FAILURE, "unable to drop to uid=%u gid=%u\n", uid, gid);

    pwd = getpwuid(uid);
    if (pwd == NULL || pwd->pw_dir == NULL)
        err(EXIT_FAILURE, "failed to lookup passwd entry");

    /* setup the most minimal environment */
    safe_asprintf(&agent_env.arg.home, "HOME=%s", pwd->pw_dir);

    execve(agent->argv[0], agent->argv, agent_env.env);
    err(EXIT_FAILURE, "failed to start %s", agent->name);
}

static int run_agent(struct agent_node_t *node, uid_t uid, gid_t gid)
{
    struct agent_data_t *data = &node->d;
    const struct agent_t *agent = &Agent[data->type];
    int fd[2], stat = 0, rc = 0;
    _cleanup_free_ char *path = NULL;

    *data = (struct agent_data_t){
        .status = ENVOY_STARTED,
        .type   = data->type
    };

    printf("Starting %s for uid=%u gid=%u.\n", agent->name, uid, gid);
    fflush(stdout);

    if (pipe2(fd, O_CLOEXEC) < 0)
        err(EXIT_FAILURE, "failed to create pipe");

    pid_t pid = fork();
    switch (pid) {
    case -1:
        err(EXIT_FAILURE, "failed to fork");
        break;
    case 0:
        dup2(fd[1], STDOUT_FILENO);

        unblock_signals();
        start_transient_unit(bus, node->scope, node->slice, "Envoy agent monitoring scope", NULL);
        exec_agent(agent, uid, gid);
        break;
    default:
        break;
    }

    if (wait(&stat) < 1)
        err(EXIT_FAILURE, "failed to get process status");

    if (stat) {
        rc = -1;

        if (WIFEXITED(stat))
            fprintf(stderr, "%s exited with status %d.\n",
                    agent->name, WEXITSTATUS(stat));
        if (WIFSIGNALED(stat))
            fprintf(stderr, "%s terminated with signal %d.\n",
                    agent->name, WTERMSIG(stat));

        goto cleanup;
    }

    rc  = parse_agentdata(fd[0], data);
    if (rc < 0) {
        fprintf(stderr, "Failed to parse %s output\n", agent->name);
        goto cleanup;
    }

    if (get_unit_by_pid(bus, data->pid, &path) < 0) {
        fprintf(stderr, "Failed to find unit for %s\n"
                "Falling back to a naive (and less reliable) "
                "method of process management...\n",
                agent->name);
    } else {
        strcpy(data->unit_path, path);
    }

cleanup:
    close(fd[0]);
    close(fd[1]);

    if (rc < 0) {
        data->pid = 0;
        data->status = ENVOY_FAILED;
    }

    return rc;
}

static int get_socket(void)
{
    int fd, n;

    n = sd_listen_fds(0);
    if (n > 1)
        err(EXIT_FAILURE, "too many file descriptors recieved");
    else if (n == 1) {
        fd = SD_LISTEN_FDS_START;
        sd_activated = true;
    } else {
        union {
            struct sockaddr sa;
            struct sockaddr_un un;
        } sa;
        socklen_t sa_len;

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
            err(EXIT_FAILURE, "couldn't create socket");

        sa_len = init_envoy_socket(&sa.un);
        if (bind(fd, &sa.sa, sa_len) < 0)
            err(EXIT_FAILURE, "failed to bind");

        if (sa.un.sun_path[0] != '@')
            chmod(sa.un.sun_path, multiuser_mode ? 0777 : 0700);

        if (listen(fd, SOMAXCONN) < 0)
            err(EXIT_FAILURE, "failed to listen");
    }

    return fd;
}

static struct agent_node_t *get_agent_entry(struct agent_node_t **list, enum agent type, uid_t uid)
{
    struct agent_node_t *node;

    for (node = *list; node; node = node->next) {
        if (node->d.type == type && node->uid == uid)
            return node;
    }

    node = malloc(sizeof(struct agent_node_t));
    *node = (struct agent_node_t){
        .uid  = uid,
        .next = *list,
        .d    = (struct agent_data_t){ .type = type }
    };

    if (sd_activated)
        node->slice = multiuser_mode ? "system-envoy.slice" : "envoy.slice";
    safe_asprintf(&node->scope, "envoy-%s-monitor-%d.scope", Agent[type].name, uid);

    *list = node;
    return node;
}

static void send_agent(int fd, struct agent_data_t *agent, bool close_sock)
{
    if (write(fd, agent, sizeof(struct agent_data_t)) < 0)
        err(EXIT_FAILURE, "failed to write agent data");
    if (close_sock)
        close(fd);
}

static void send_message(int fd, enum status status, bool close_sock)
{
    struct agent_data_t d = { .status = status };
    send_agent(fd, &d, close_sock);
}

static void accept_conn(int fd)
{
    struct ucred cred;
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    struct agent_request_t req;
    static socklen_t sa_len = sizeof(struct sockaddr_un);
    static socklen_t cred_len = sizeof(struct ucred);

    int cfd = accept4(fd, &sa.sa, &sa_len, SOCK_CLOEXEC);
    if (cfd < 0)
        err(EXIT_FAILURE, "failed to accept connection");

    int nbytes_r = read(cfd, &req, sizeof(struct agent_request_t));
    if (nbytes_r < 0)
        err(EXIT_FAILURE, "couldn't read agent type to start");

    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0)
        err(EXIT_FAILURE, "couldn't obtain credentials from unix domain socket");

    if (server_uid != 0 && server_uid != cred.uid) {
        fprintf(stderr, "Connection from uid=%u rejected.\n", cred.uid);
        send_message(cfd, ENVOY_BADUSER, true);
        return;
    }

    enum agent agent = req.type == AGENT_DEFAULT ? default_type : req.type;
    struct agent_node_t *node = get_agent_entry(&agents, agent, cred.uid);
    bool running = unit_running(&node->d);

    if (node->d.pid == 0 || !running) {
        if (req.opts & AGENT_STATUS) {
            send_message(cfd, ENVOY_STOPPED, true);
            return;
        }

        if (node->d.pid != 0) {
            printf("Agent %s for uid=%u is has terminated. Restarting...\n",
                   Agent[node->d.type].name, cred.uid);
            fflush(stdout);
        }

        run_agent(node, cred.uid, cred.gid);
    }

    send_agent(cfd, &node->d, true);

    if (!(req.opts & AGENT_ENVIRON) && node->d.status == ENVOY_STARTED)
        node->d.status = ENVOY_RUNNING;
}

static int loop(int server_sock)
{
    int sfd = get_signalfd(SIGTERM, SIGINT, SIGQUIT, 0);
    if (sfd < 0)
        err(EXIT_FAILURE, "failed to create signalfd");

    struct pollfd fds[] = {
        { .fd = server_sock, .events = POLLIN },
        { .fd = sfd,         .events = POLLIN }
    };
    const size_t fd_count = sizeof(fds) / sizeof(fds[0]);

    while (true) {
        int ret = poll(fds, fd_count, -1);

        if (ret == 0) {
            continue;
        } else if (ret < 0) {
            if (errno == EINTR)
                continue;
            err(EXIT_FAILURE, "failed to poll");
        }

        if (fds[0].revents & POLLHUP)
            close(fds[0].fd);
        else if (fds[0].revents & POLLIN)
            accept_conn(server_sock);
        else if (fds[1].revents & POLLIN) {
            struct signalfd_siginfo si;
            ssize_t nbytes_r = read(sfd, &si, sizeof(si));
            if (nbytes_r < 0)
                err(EXIT_FAILURE, "failed to read signal");

            switch (si.ssi_signo) {
            case SIGINT:
            case SIGTERM:
            case SIGQUIT:
                cleanup(server_sock);
                exit(EXIT_SUCCESS);
            }
        }
    }

    return 0;
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
    int server_sock;

    static const struct option opts[] = {
        { "help",    no_argument,       0, 'h' },
        { "version", no_argument,       0, 'v' },
        { "agent",   required_argument, 0, 't' },
        { 0, 0, 0, 0 }
    };

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
            default_type = lookup_agent(optarg);
            if (default_type < 0)
                errx(EXIT_FAILURE, "unknown agent: %s", optarg);
            break;
        default:
            usage(stderr);
        }
    }

    server_uid = geteuid();
    multiuser_mode = server_uid == 0;

    init_agent_environ();
    server_sock = get_socket();
    bus = get_connection(multiuser_mode ? DBUS_BUS_SYSTEM : DBUS_BUS_SESSION);

    return loop(server_sock);
}

// vim: et:sts=4:sw=4:cino=(0
