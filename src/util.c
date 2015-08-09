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
 * Copyright (C) Simon Gomizelj, 2015
 */

#include "util.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <err.h>
#include <pwd.h>
#include <signal.h>
#include <sys/signalfd.h>

static char *home_dir_cache = NULL;

char *joinpath(const char *root, ...)
{
    size_t len;
    char *ret, *p;
    const char *temp;
    va_list ap;

    if (!root)
        return NULL;

    len = strlen(root);

    va_start(ap, root);
    while ((temp = va_arg(ap, const char *))) {
        size_t temp_len = strlen(temp) + 1;
        if (temp_len > ((size_t) -1) - len) {
            va_end(ap);
            return NULL;
        }

        len += temp_len;
    }
    va_end(ap);

    ret = malloc(len + 1);
    if (ret) {
        p = stpcpy(ret, root);

        va_start(ap, root);
        while ((temp = va_arg(ap, const char *))) {
            p++[0] = '/';
            p = stpcpy(p, temp);
        }
        va_end(ap);
    }

    return ret;
}

int putenvf(const char *fmt, ...)
{
    /* we do not want to free the memory allocated for env because the
     * allocated memory literally becomes part of the environ data. */
    va_list ap;
    char *env;
    int ret;

    va_start(ap, fmt);
    ret = vasprintf(&env, fmt, ap);
    va_end(ap);

    return ret < 0 ? ret : putenv(env);
}

void safe_asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (vasprintf(strp, fmt, ap) < 0)
        err(EXIT_FAILURE, "failed to allocate memory");
    va_end(ap);
}

int unblock_signals(void)
{
    sigset_t mask;
    sigfillset(&mask);
    return sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

int get_signalfd(int signum, ...)
{
    va_list ap;
    sigset_t mask;

    sigemptyset(&mask);
    sigaddset(&mask, signum);

    va_start(ap, signum);
    while ((signum = va_arg(ap, int)))
        sigaddset(&mask, signum);
    va_end(ap);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        return -1;
    return signalfd(-1, &mask, SFD_CLOEXEC);
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

// vim: et:sts=4:sw=4:cino=(0
