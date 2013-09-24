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
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <pwd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <systemd/sd-daemon.h>

#include "lib/envoy.h"
#include "clique/systemd-unit.h"
#include "clique/systemd-scope.h"

struct agent_info_t {
    uid_t uid;
    struct agent_data_t d;
    struct agent_info_t *next;
};

static dbus_bus *bus = NULL;
static enum agent default_type = AGENT_SSH_AGENT;
static struct agent_info_t *agents = NULL;
static bool sd_activated = false;
static int epoll_fd, server_sock;

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

static void kill_agents(int signal)
{
    while (agents) {
        if (agents->d.unit_path[0]) {
            unit_kill(bus, agents->d.unit_path, signal);
        } else {
            kill(agents->d.pid, signal);
        }

        agents = agents->next;
    }
}

static void cleanup(void)
{
    close(epoll_fd);

    if (!sd_activated) {
        close(server_sock);
        unlink_envoy_socket();
    }

    kill_agents(SIGTERM);
}

static void sighandler(int signum)
{
    switch (signum) {
    case SIGINT:
    case SIGTERM:
        cleanup();
        exit(EXIT_SUCCESS);
    }
}

static bool unit_running(struct agent_data_t *data)
{
    bool running = true;

    if (data->unit_path[0]) {
        char *state;
        get_unit_state(bus, data->unit_path, &state);
        running = strcmp(state, "running") == 0;
    } else if (kill(data->pid, 0) < 0) {
        if (errno != ESRCH)
            err(EXIT_FAILURE, "something strange happened with kill");
        running = false;
    }

    return running;
}

static int safe_atoi(const char *p, size_t len)
{
    int value = 0;

    for (; len && *p; ++p, --len) {
        value *= 10;
        value += *p - '0';
    }

    return value;
}

static void init_agent_environ(void)
{
    extern char **environ;
    char *path = NULL, *gnupghome = NULL;
    int i;

    for (i = 0; environ[i]; ++i) {
        if (strncmp(environ[i], "PATH=", 5) == 0)
            path = environ[i];
        if (strncmp(environ[i], "GNUPGHOME=", 10) == 0)
            gnupghome = environ[i];
    }

    agent_env.arg.path = path ? path : "PATH=/usr/local/bin:/usr/bin/:/bin";

    if (!gnupghome)
        return;

    if (getuid() != 0) {
        agent_env.arg.gnupghome = gnupghome;
    } else {
        fprintf(stderr, "warning: running as root and GNUPGHOME is set; ignoring.\n");
    }
}

static pid_t gpg_info_extract_pid(const char *gpg)
{
    const char *div, *end;

    div = strchr(gpg, ':');
    if (div == NULL) {
        fprintf(stderr, "GPG_AGENT_INFO=%s doesn't contain the agent's pid\n", gpg);
        return 0;
    }

    end = strchr(++div, ':');
    if (div == NULL) {
        fprintf(stderr, "GPG_AGENT_INFO=%s doesn't contain protocol version\n", gpg);
        return 0;
    }

    return safe_atoi(div, end - div);
}

static void parse_agentdata_line(char *val, struct agent_data_t *info)
{
    char *eol, *var;

    eol = strchr(val, ';');
    if (eol)
        *eol = '\0';

    if (strchr(val, '=') == NULL)
        return;

    var = strsep(&val, "=");

    if (strcmp(var, "SSH_AUTH_SOCK") == 0)
        strcpy(info->sock, val);
    else if (strcmp(var, "SSH_AGENT_PID") == 0)
        info->pid = atoi(val);
    else if (strcmp(var, "GPG_AGENT_INFO") == 0)
        strcpy(info->gpg, val);
}

static int parse_agentdata(int fd, struct agent_data_t *data)
{
    char b[BUFSIZ];
    char *l, *nl;
    ssize_t bytes_r;

    bytes_r = read(fd, b, sizeof(b));
    if (bytes_r <= 0)
        return bytes_r;

    b[bytes_r] = '\0';
    l = &b[0];

    while (l < &b[bytes_r]) {
        nl = strchr(l, '\n');
        if (!nl)
            break;

        *nl = '\0';
        parse_agentdata_line(l, data);

        l = nl + 1;
    }

    if (data->pid == 0 && data->gpg) {
        data->pid = gpg_info_extract_pid(data->gpg);
    }

    return 0;
}

static void __attribute__((__noreturn__)) exec_agent(const struct agent_t *agent, uid_t uid, gid_t gid)
{
    dbus_bus *bus;
    dbus_message *m;
    char *scope, *slice = NULL;
    struct passwd *pwd;

    if (getuid() == 0 && uid != 0) {
        asprintf(&slice, "user-%d.slice", uid);
    }

    asprintf(&scope, "envoy-monitor-%d.scope", uid);

    dbus_open(DBUS_AUTO, &bus);
    scope_init(&m, scope, slice, "Envoy agent monitor", 0);
    int rc = scope_commit(bus, m, NULL);
    if (rc < 0) {
        err(EXIT_FAILURE, "failed to start transient scope for agent: %s", bus->error);
    }
    dbus_close(bus);

    free(scope);

    if (setresgid(gid, gid, gid) < 0 || setresuid(uid, uid, uid) < 0)
        err(EXIT_FAILURE, "unable to drop to uid=%u gid=%u\n", uid, gid);

    pwd = getpwuid(uid);
    if (pwd == NULL || pwd->pw_dir == NULL)
        err(EXIT_FAILURE, "failed to lookup passwd entry");

    /* setup the most minimal environment */
    if (asprintf(&agent_env.arg.home, "HOME=%s", pwd->pw_dir) < 0)
        err(EXIT_FAILURE, "failed to allocate memory");

    execve(agent->argv[0], agent->argv, agent_env.env);
    err(EXIT_FAILURE, "failed to start %s", agent->name);
}

static int run_agent(struct agent_data_t *data, uid_t uid, gid_t gid)
{
    const struct agent_t *agent = &Agent[data->type];
    int fd[2], stat = 0, rc = 0;

    data->status = ENVOY_STARTED;
    data->sock[0] = '\0';
    data->gpg[0] = '\0';
    data->unit_path[0] = '\0';

    printf("Starting %s for uid=%u gid=%u.\n", agent->name, uid, gid);
    fflush(stdout);

    if (pipe(fd) < 0)
        err(EXIT_FAILURE, "failed to create pipe");

    pid_t pid = fork();
    switch (pid) {
    case -1:
        err(EXIT_FAILURE, "failed to fork");
        break;
    case 0:
        dup2(fd[1], STDOUT_FILENO);
        close(fd[0]);
        close(fd[1]);

        exec_agent(agent, uid, gid);
        break;
    default:
        break;
    }

    if (wait(&stat) < 1)
        err(EXIT_FAILURE, "failed to get process status");

    if (stat) {
        rc = -1;
        data->pid = 0;
        data->status = ENVOY_FAILED;

        if (WIFEXITED(stat))
            fprintf(stderr, "%s exited with status %d.\n",
                    agent->name, WEXITSTATUS(stat));
        if (WIFSIGNALED(stat))
            fprintf(stderr, "%s terminated with signal %d.\n",
                    agent->name, WTERMSIG(stat));
    } else if (parse_agentdata(fd[0], data) < 0) {
        err(EXIT_FAILURE, "failed to parse %s output", agent->name);
    } else {
        char *scope, *path;

        asprintf(&scope, "envoy-monitor-%d.scope", uid);
        rc = get_unit_by_pid(bus, data->pid, &path);
        if (rc < 0) {
            fprintf(stderr, "Failed to find unit for %s: %s\n"
                    "Falling back to a naive (and less reliable) "
                    "method of process management...\n",
                    agent->name, bus->error);
        } else {
            strcpy(data->unit_path, path);
            free(path);
        }

        free(scope);
    }

    close(fd[0]);
    close(fd[1]);
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
            chmod(sa.un.sun_path, 0777);

        if (listen(fd, SOMAXCONN) < 0)
            err(EXIT_FAILURE, "failed to listen");
    }

    return fd;
}

static struct agent_info_t *lookup_agent_info(struct agent_info_t *agents, uid_t uid)
{
    struct agent_info_t *node;
    for (node = agents; node; node = node->next) {
        if (node->uid == uid)
            return node;
    }

    return NULL;
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

static void accept_conn(void)
{
    struct ucred cred;
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    static socklen_t sa_len = sizeof(struct sockaddr_un);
    static socklen_t cred_len = sizeof(struct ucred);
    uid_t server_uid = geteuid();

    int cfd = accept4(server_sock, &sa.sa, &sa_len, SOCK_CLOEXEC);
    if (cfd < 0)
        err(EXIT_FAILURE, "failed to accept connection");

    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0)
        err(EXIT_FAILURE, "couldn't obtain credentials from unix domain socket");

    if (server_uid != 0 && server_uid != cred.uid) {
        fprintf(stderr, "Connection from uid=%u rejected.\n", cred.uid);
        send_message(cfd, ENVOY_BADUSER, true);
        return;
    }

    struct agent_info_t *node = lookup_agent_info(agents, cred.uid);

    if (!node || node->d.pid == 0 || !unit_running(&node->d)) {
        struct epoll_event event = {
            .data.fd = cfd,
            .events  = EPOLLIN | EPOLLET
        };

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cfd, &event) < 0)
            err(EXIT_FAILURE, "failed to add socket to epoll");

        if (node)
            node->d.pid = 0;

        send_message(cfd, ENVOY_STOPPED, false);
    } else {
        send_agent(cfd, &node->d, true);
    }
}

static void handle_conn(int cfd)
{
    struct ucred cred;
    static socklen_t cred_len = sizeof(struct ucred);
    enum agent type;

    int nbytes_r = read(cfd, &type, sizeof(enum agent));
    if (nbytes_r < 0)
        err(EXIT_FAILURE, "couldn't read agent type to start");

    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0)
        err(EXIT_FAILURE, "couldn't obtain credentials from unix domain socket");

    struct agent_info_t *node = lookup_agent_info(agents, cred.uid);

    if (!node) {
        node = calloc(1, sizeof(struct agent_info_t));
        node->uid = cred.uid;
        node->next = agents;
        agents = node;
    } else {
        printf("Agent for uid=%u is has terminated. Restarting...\n", cred.uid);
        fflush(stdout);
    }

    node->d.type = type != AGENT_DEFAULT ? type : default_type;

    run_agent(&node->d, cred.uid, cred.gid);
    send_agent(cfd, &node->d, true);

    if (node->d.pid)
        node->d.status = ENVOY_RUNNING;
}

static int loop(void)
{
    struct epoll_event events[4], event = {
        .data.fd = server_sock,
        .events  = EPOLLIN | EPOLLET
    };

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_sock, &event) < 0)
        err(EXIT_FAILURE, "failed to add socket to epoll");

    while (true) {
        int i, n = epoll_wait(epoll_fd, events, 4, -1);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            err(EXIT_FAILURE, "epoll_wait failed");
        }

        for (i = 0; i < n; ++i) {
            struct epoll_event *evt = &events[i];

            if (evt->events & EPOLLERR || evt->events & EPOLLHUP)
                close(evt->data.fd);
            else if (evt->data.fd == server_sock)
                accept_conn();
            else
                handle_conn(evt->data.fd);
        }
    }

    return 0;
}

static void __attribute__((__noreturn__)) usage(FILE *out)
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
            if (default_type == LAST_AGENT)
                errx(EXIT_FAILURE, "unknown agent: %s", optarg);
            break;
        default:
            usage(stderr);
        }
    }

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0)
        err(EXIT_FAILURE, "failed to start epoll");

    dbus_open(DBUS_AUTO, &bus);
    server_sock = get_socket();
    init_agent_environ();

    signal(SIGTERM, sighandler);
    signal(SIGINT,  sighandler);

    return loop();
}

// vim: et:sts=4:sw=4:cino=(0
