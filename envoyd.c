#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <err.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>

#include "config.h"

struct agent_info_t {
    uid_t uid;
    pid_t pid;
    char *sock;

    struct agent_info_t *next;
};

struct agent_info_t *agents = NULL;
int fd;

static void sigterm()
{
    close(fd);
    unlink(SOCK_PATH);

    while (agents) {
        kill(agents->pid, SIGTERM);
        agents = agents->next;
    }

    exit(EXIT_SUCCESS);
}

static int xstrtol(const char *str, long *out)
{
    char *end = NULL;

    if (str == NULL || *str == '\0')
        return -1;
    errno = 0;

    *out = strtol(str, &end, 10);
    if (errno || str == end || (end && *end))
        return -1;

    return 0;
}

/* TODO: this is soo hacky its not even funny */
static void read_agent(int fd, struct agent_info_t *info)
{
    char b[BUFSIZ];
    int nread = 0;

    nread = read(fd, b, BUFSIZ);
    b[nread] = '\0';

    char *k, *t;
    k = strchr(b, '='); ++k;
    t = strchr(b, ';'); *t++ = '\0';

    info->sock = strdup(k);

    t = strchr(t, '\n'); ++t;
    k = strchr(t, '='); ++k;
    t = strchr(t, ';'); *t = '\0';

    long value;
    xstrtol(k, &value);

    info->pid = (pid_t)value;
    info->next = NULL;
}

static void start_agent(uid_t uid, gid_t gid, struct agent_info_t *info)
{
    int rc, fd[2];

    sd_journal_print(LOG_INFO, "starting ssh-agent for uid=%ld gid=%ld", uid, gid);

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

        rc = execlp("ssh-agent", "ssh-agent", NULL);
        exit(rc);
        break;
    default:
        close(fd[1]);
        break;
    }

    read_agent(fd[STDIN_FILENO], info);
    wait(NULL);
}

static void write_agent(int fd, struct agent_info_t *info)
{
    char buf[MSG_LEN], nbytes;

    nbytes = snprintf(buf, MSG_LEN, "export SSH_AUTH_SOCK=%s\n", info->sock);
    if (write(fd, buf, nbytes) < 0)
        err(EXIT_FAILURE, "failed to write message");

    nbytes = snprintf(buf, MSG_LEN, "export SSH_AGENT_PID=%d\n", info->pid);
    if (write(fd, buf, nbytes) < 0)
        err(EXIT_FAILURE, "failed to write message");
}

static int get_socket()
{
    int fd, n;

    n = sd_listen_fds(0);
    if (n > 1)
        err(EXIT_FAILURE, "too many file descriptors recieved");
    else if (n == 1)
        fd = SD_LISTEN_FDS_START;
    else {
        union {
            struct sockaddr sa;
            struct sockaddr_un un;
        } sa;

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
            err(EXIT_FAILURE, "couldn't create socket");

        memset(&sa, 0, sizeof(sa));
        sa.un.sun_family = AF_UNIX;
        strncpy(sa.un.sun_path, SOCK_PATH, sizeof(sa.un.sun_path));

        if (bind(fd, &sa.sa, sizeof(sa)) < 0)
            err(EXIT_FAILURE, "failed to bind");

        if (chmod(sa.un.sun_path, 0666) < 0)
            err(EXIT_FAILURE, "failed to set permissions");

        if (listen(fd, SOMAXCONN) < 0)
            err(EXIT_FAILURE, "failed to listen");
    }

    return fd;
}

int main(void)
{
    fd = get_socket();

    signal(SIGTERM, sigterm);
    signal(SIGINT,  sigterm);

    while (true) {
        union {
            struct sockaddr sa;
            struct sockaddr_un un;
        } sa;
        socklen_t sa_len = sizeof(sa);

        int cfd = accept(fd, &sa.sa, &sa_len);
        if (cfd < 0)
            err(EXIT_FAILURE, "failed to accept connection");

        struct ucred cred;
        socklen_t cred_len = sizeof(struct ucred);

        if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0)
            err(EXIT_FAILURE, "couldn't obtain credentials from unix domain socket");

        struct agent_info_t *node = agents;
        while (node) {
            if (node->uid == cred.uid)
                break;
        }

        if (!node || kill(node->pid, 0) < 0) {
            if (node && errno != ESRCH)
                err(EXIT_FAILURE, "something strange happened with kill");

            if (!node) {
                node = malloc(sizeof(struct agent_info_t));
                node->uid = cred.uid;
                node->next = agents;
                agents = node;
            } else
                free(node->sock);

            start_agent(cred.uid, cred.gid, node);
        }

        write_agent(cfd, node);
        close(cfd);
    }

    return 0;
}

// vim: et:sts=4:sw=4:cino=(0
