#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <err.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "config.h"

int main()
{
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    int fd, rc;

    fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        err(EXIT_FAILURE, "couldn't create socket");

    memset(&sa, 0, sizeof(sa));
    sa.un.sun_family = AF_UNIX;
    strncpy(sa.un.sun_path, SOCK_PATH, sizeof(sa.un.sun_path));

    rc = connect(fd, &sa.sa, sizeof(sa));
    if (rc < 0)
        err(EXIT_FAILURE, "failed to connect");

    int nread;
    char buf[BUFSIZ];

    nread = read(fd, buf, BUFSIZ);
    buf[nread] = 0;

    fputs(buf, stdout);
    close(fd);

    return 0;
}

// vim: et:sts=4:sw=4:cino=(0
