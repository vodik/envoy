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
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>

struct agent_info_t {
    uid_t uid;
    struct agent_data_t d;
    struct agent_info_t *next;
};

static struct agent_info_t *agents = NULL;
static bool sd_activated;
static int server_sock;

static void cleanup(void)
{
    close(server_sock);

    while (agents) {
        if (agents->d.pid < 0)
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
        if (!sd_activated)
            cleanup();
        exit(EXIT_SUCCESS);
    }
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

static void start_agent(uid_t uid, gid_t gid, struct agent_data_t *data)
{
    int fd[2], stat = 0;

    data->first_run = true;
    sd_journal_print(LOG_INFO, "starting ssh-agent for uid=%ld gid=%ld",
                     (long)uid, (long)gid);

    if (pipe(fd) < 0)
        err(EXIT_FAILURE, "failed to create pipe");

    switch (fork()) {
    case -1:
        err(EXIT_FAILURE, "failed to fork");
        break;
    case 0:
        dup2(fd[1], STDOUT_FILENO);
        close(fd[0]);

        if (setgid(gid) < 0)
            err(EXIT_FAILURE, "unable to drop to group id %d\n", gid);

        if (setuid(uid) < 0)
            err(EXIT_FAILURE, "unable to drop to user id %d\n", uid);

        if (execlp("ssh-agent", "ssh-agent", NULL) < 0)
            err(EXIT_FAILURE, "failed to start ssh-agent");
        break;
    default:
        close(fd[1]);
        break;
    }

    if (parse_agentdata(fd[STDIN_FILENO], data) < 0)
        err(EXIT_FAILURE, "failed to parse ssh-agent output");

    if (wait(&stat) < 1)
        err(EXIT_FAILURE, "failed to get process status");

    if (stat) {
        data->pid = 0;

        if (WIFEXITED(stat))
            sd_journal_print(LOG_ERR, "ssh-agent exited with status %d",
                             WEXITSTATUS(stat));
        if (WIFSIGNALED(stat))
            sd_journal_print(LOG_ERR, "ssh-agent terminated with signal %d",
                             WTERMSIG(stat));
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

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
            err(EXIT_FAILURE, "couldn't create socket");

        memset(&sa, 0, sizeof(sa));
        sa.un.sun_family = AF_UNIX;
        memcpy(sa.un.sun_path + 1, &SOCK_PATH[1], sizeof(SOCK_PATH) + 1);

        if (bind(fd, &sa.sa, sizeof(SOCK_PATH) + 1) < 0)
            err(EXIT_FAILURE, "failed to bind");

        if (listen(fd, SOMAXCONN) < 0)
            err(EXIT_FAILURE, "failed to listen");
    }

    return fd;
}

int main(void)
{
    server_sock = get_socket();

    signal(SIGTERM, sighandler);
    signal(SIGINT,  sighandler);

    while (true) {
        union {
            struct sockaddr sa;
            struct sockaddr_un un;
        } sa;
        socklen_t sa_len;

        int cfd = accept(server_sock, &sa.sa, &sa_len);
        if (cfd < 0)
            err(EXIT_FAILURE, "failed to accept connection");

        if (fcntl(cfd, F_SETFD, FD_CLOEXEC) < 0)
            err(EXIT_FAILURE, "failed to set FD_CLOEXEC on client connection");

        struct ucred cred;
        socklen_t cred_len = sizeof(struct ucred);

        if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0)
            err(EXIT_FAILURE, "couldn't obtain credentials from unix domain socket");

        struct agent_info_t *node = agents;
        while (node) {
            if (node->uid == cred.uid)
                break;
            node = node->next;
        }

        if (!node || node->d.pid == 0 || kill(node->d.pid, 0) < 0) {
            if (node && node->d.pid) {
                if (errno != ESRCH)
                    err(EXIT_FAILURE, "something strange happened with kill");
                sd_journal_print(LOG_INFO, "ssh-agent for uid=%ld no longer running...",
                                 (long)cred.uid);
            } else if (!node) {
                node = malloc(sizeof(struct agent_info_t));
                node->uid = cred.uid;
                node->next = agents;
                agents = node;
            }

            start_agent(cred.uid, cred.gid, &node->d);
        }

        if (node->d.pid) {
            if (write(cfd, &node->d, sizeof(node->d)) < 0)
                err(EXIT_FAILURE, "failed to write agent data");
            node->d.first_run = false;
        }

        close(cfd);
    }

    return 0;
}

// vim: et:sts=4:sw=4:cino=(0
