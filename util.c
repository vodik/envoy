#include "util.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <err.h>
#include <pwd.h>

static char *home_dir_cache = NULL;

static char *joinpath_ap(const char *root, va_list ap)
{
    size_t len;
    char *ret, *p;
    const char *temp;

    va_list aq;
    va_copy(aq, ap);

    if (!root)
        return NULL;

    len = strlen(root);
    while ((temp = va_arg(ap, const char *))) {
        size_t temp_len = strlen(temp) + 1;
        if (temp_len > ((size_t) -1) - len) {
            return NULL;
        }

        len += temp_len;
    }

    ret = malloc(len + 1);
    if (ret) {
        p = stpcpy(ret, root);
        while ((temp = va_arg(aq, const char *))) {
            p++[0] = '/';
            p = stpcpy(p, temp);
        }
    }

    return ret;
}

char *joinpath(const char *root, ...)
{
    va_list ap;
    char *ret;

    va_start(ap, root);
    ret = joinpath_ap(root, ap);
    va_end(ap);

    return ret;
}

void safe_asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (vasprintf(strp, fmt, ap) < 0)
        err(EXIT_FAILURE, "failed to allocate memory");
    va_end(ap);
}

const char *get_home_dir(void)
{
    if (!home_dir_cache) {
        home_dir_cache = getenv("HOME");

        if (home_dir_cache && home_dir_cache[0])
            home_dir_cache = strdup(home_dir_cache);
        else {
            struct passwd *pwd = getpwuid(getuid());
            if (!pwd)
                err(EXIT_FAILURE, "failed to get pwd entry for user");
            home_dir_cache = strdup(pwd->pw_dir);
        }
    }

    return home_dir_cache;
}
