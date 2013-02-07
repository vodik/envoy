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

struct agent_info_t {
    uid_t uid;
    struct agent_data_t d;
    struct agent_info_t *next;
};

static enum agent default_type = AGENT_DEFAULT;
static struct agent_info_t *agents = NULL;
static bool sd_activated = false;
static int epoll_fd, server_sock;
static uid_t server_uid;

static void cleanup(void)
{
    close(server_sock);
    unlink_envoy_socket();

    while (agents) {
        if (agents->d.pid <= 0)
            continue;
        kill(agents->d.pid, SIGTERM);
        agents = agents->next;
    }
}

static void sighandler(int signum)
{
    switch (signum) {
    case SIGINT:
    case SIGTERM:
        close(epoll_fd);
        if (!sd_activated)
            cleanup();
        exit(EXIT_SUCCESS);
    }
}

static void init_cgroup(void)
{
    if (mkdir("/sys/fs/cgroup/cpu/envoy", 0755) < 0 && errno != EEXIST)
        err(EXIT_FAILURE, "failed to create cgroup subsystem");

    FILE *fp = fopen("/sys/fs/cgroup/cpu/envoy/cgroup.procs", "w");
    if (!fp)
        err(EXIT_FAILURE, "failed to open cgroup info");
    fprintf(fp, "%d", getpid());
    fclose(fp);
}

static bool pid_in_cgroup(pid_t pid)
{
    bool found = false;
    pid_t cgroup_pid;

    FILE *fp = fopen("/sys/fs/cgroup/cpu/envoy/cgroup.procs", "r");
    if (!fp)
        err(EXIT_FAILURE, "failed to open cgroup info");

    while (fscanf(fp, "%d", &cgroup_pid) != EOF) {
        if (cgroup_pid == pid) {
            found = true;
            break;
        }
    }

    fclose(fp);
    return found;
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

    return 0;
}

static void __attribute__((__noreturn__)) exec_agent(const struct agent_t *agent, uid_t uid, gid_t gid)
{
    struct passwd *pwd = getpwuid(uid);
    if (pwd == NULL || pwd->pw_dir == NULL)
        err(EXIT_FAILURE, "failed to lookup passwd entry");

    if (setregid(gid, gid) < 0 || setreuid(uid, uid) < 0)
        err(EXIT_FAILURE, "unable to drop to uid=%u gid=%u\n", uid, gid);

    /* Setup the minimal environment needed for gpg-agent to run: HOME
     * and GPG_TTY. No special work is needed for ssh-agent.
     *
     * Note that setting GPG_TTY to /dev/null is intentional. This is
     * a placeholder value. Envoy will update gpg-agent with a proper
     * value at runtime. However it seems that the environmental
     * variable needs to be set now for the update mechanism to work.
     */
    if (setenv("HOME", pwd->pw_dir, true))
        err(EXIT_FAILURE, "failed to set HOME=%s\n", pwd->pw_dir);

    if (setenv("GPG_TTY", "/dev/null", true))
        err(EXIT_FAILURE, "failed to set GPG_TTY\n");

    execv(agent->argv[0], agent->argv);
    err(EXIT_FAILURE, "failed to start %s", agent->name);
}

static void run_agent(const struct agent_t *agent, uid_t uid, gid_t gid, struct agent_data_t *data)
{
    int fd[2], stat = 0;

    data->status = ENVOY_STARTED;
    data->sock[0] = '\0';
    data->gpg[0] = '\0';

    fprintf(stdout, "Starting %s for uid=%u gid=%u.\n", agent->name, uid, gid);

    if (pipe(fd) < 0)
        err(EXIT_FAILURE, "failed to create pipe");

    switch (fork()) {
    case -1:
        err(EXIT_FAILURE, "failed to fork");
        break;
    case 0:
        dup2(fd[1], STDOUT_FILENO);
        close(fd[0]);

        exec_agent(agent, uid, gid);
        break;
    default:
        close(fd[1]);
        break;
    }

    if (parse_agentdata(fd[0], data) < 0)
        err(EXIT_FAILURE, "failed to parse %s output", agent->name);

    close(fd[0]);

    if (wait(&stat) < 1)
        err(EXIT_FAILURE, "failed to get process status");

    if (stat) {
        data->pid = 0;
        data->status = ENVOY_FAILED;

        if (WIFEXITED(stat))
            fprintf(stderr, "%s exited with status %d.\n",
                    agent->name, WEXITSTATUS(stat));
        if (WIFSIGNALED(stat))
            fprintf(stderr, "%s terminated with signal %d.\n",
                    agent->name, WTERMSIG(stat));
    }
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

        if (listen(fd, SOMAXCONN) < 0)
            err(EXIT_FAILURE, "failed to listen");
    }

    return fd;
}

static struct agent_info_t *agent_by_uid(struct agent_info_t *agents, uid_t uid)
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
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    socklen_t sa_len;

    int cfd = accept4(server_sock, &sa.sa, &sa_len, SOCK_CLOEXEC);
    if (cfd < 0)
        err(EXIT_FAILURE, "failed to accept connection");

    struct ucred cred;
    socklen_t cred_len = sizeof(struct ucred);

    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0)
        err(EXIT_FAILURE, "couldn't obtain credentials from unix domain socket");

    if (server_uid != 0 && server_uid != cred.uid) {
        fprintf(stderr, "Connection from uid=%u rejected.\n", cred.uid);
        send_message(cfd, ENVOY_BADUSER, true);
        return;
    }

    struct agent_info_t *node = agent_by_uid(agents, cred.uid);

    if (!node || node->d.pid == 0 || !pid_in_cgroup(node->d.pid)) {
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
    socklen_t cred_len = sizeof(struct ucred);
    enum agent type;

    int nbytes_r = read(cfd, &type, sizeof(enum agent));
    if (nbytes_r < 0)
        err(EXIT_FAILURE, "couldn't read agent type to start");

    if (type == AGENT_DEFAULT)
        type = default_type;

    const struct agent_t *agent = &Agent[type];

    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0)
        err(EXIT_FAILURE, "couldn't obtain credentials from unix domain socket");

    struct agent_info_t *node = agent_by_uid(agents, cred.uid);

    if (!node) {
        node = calloc(1, sizeof(struct agent_info_t));
        node->uid = cred.uid;
        node->next = agents;
        agents = node;
    } else {
        fprintf(stdout, "Agent for uid=%u is has terminated. Restarting...\n",
                cred.uid);
    }

    node->d.type = type;
    run_agent(agent, cred.uid, cred.gid, &node->d);
    send_agent(cfd, &node->d, true);

    if (node->d.pid)
        node->d.status = ENVOY_RUNNING;

    fflush(stdout);
    close(cfd);
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
        " -a, --agent=AGENT     set the agent to start\n", out);

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
            default_type = find_agent(optarg);
            if (default_type == LAST_AGENT)
                errx(EXIT_FAILURE, "unknown agent: %s", optarg);
            break;
        default:
            usage(stderr);
        }
    }

    if (default_type == AGENT_DEFAULT)
        default_type = AGENT_SSH_AGENT;

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0)
        err(EXIT_FAILURE, "failed to start epoll");

    server_uid = geteuid();
    server_sock = get_socket();

    init_cgroup();

    signal(SIGTERM, sighandler);
    signal(SIGINT,  sighandler);

    return loop();
}

// vim: et:sts=4:sw=4:cino=(0
