#include "common.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

static const char *def_socket_path = "@/vodik/envoy";

static const char *get_socket_path(void)
{
    const char *socket = getenv("ENVOY_SOCKET");
    return socket ? socket : def_socket_path;
}

size_t init_envoy_socket(struct sockaddr_un *un)
{
    const char *socket = get_socket_path();
    off_t off = 0;
    size_t len;

    *un = (struct sockaddr_un){ .sun_family = AF_UNIX };

    if (socket[0] == '@')
        off = 1;

    len = strlen(socket);
    memcpy(&un->sun_path[off], &socket[off], len - off);

    return len + sizeof(un->sun_family);
}

void unlink_envoy_socket(void)
{
    const char *socket = get_socket_path();
    if (socket[0] != '@')
        unlink(socket);
}

// vim: et:sts=4:sw=4:cino=(0
