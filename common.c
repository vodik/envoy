#include "common.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/un.h>

static const char *socket_path = "@/vodik/envoy";

size_t init_envoy_socket(struct sockaddr_un *un)
{
    off_t off = 0; size_t len = 0;
    const char *socket = getenv("ENVOY_SOCKET");

    memset(un, 0, sizeof(*un));
    un->sun_family = AF_UNIX;

    if (!socket)
        socket = socket_path;
    if (socket[0] == '@')
        off = 1;

    len = strlen(socket);
    memcpy(&un->sun_path[off], &socket[off], len - off);

    return len + sizeof(un->sun_family);
}

// vim: et:sts=4:sw=4:cino=(0
