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
 * Copyright (C) Simon Gomizelj, 2013
 */

#include "cgroups.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <mntent.h>
#include <sys/stat.h>

/* loosely adopted from systemd shared/mkdir.c */
static int mkdir_parents(const char *path, mode_t mode)
{
    struct stat st;
    const char *p, *e;

    /* return immedately if directory exists */
    if (stat(path, &st) >= 0) {
        if ((st.st_mode & S_IFMT) == S_IFDIR)
            return 0;
        else
            return -ENOTDIR;
    }

    /* create every parent directory in the path, except the last component */
    p = path + strspn(path, "/");
    for (;;) {
        int r;
        char *t;

        e = p + strcspn(p, "/");
        p = e + strspn(e, "/");

        t = strndup(path, e - path);
        if (!t)
            return -ENOMEM;

        r = mkdir(t, mode);
        free(t);

        if (r < 0 && errno != EEXIST) {
            return -errno;
        }

        /* Is this the last component? If so, then we're * done */
        if (*p == 0)
            return 0;
    }
}

/* loosely adopted from systemd shared/util.c */
static char *joinpath(const char *root, va_list ap)
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

static char *cg_get_mount(const char *subsystem)
{
    char *mnt = NULL;
    struct mntent mntent_r;
    FILE *file;
    char buf[BUFSIZ];

    file = setmntent("/proc/self/mounts", "r");
    if (!file)
        return NULL;

    while ((getmntent_r(file, &mntent_r, buf, sizeof(buf)))) {
        if (strcmp(mntent_r.mnt_type, "cgroup") != 0)
            continue;

        if (subsystem && !hasmntopt(&mntent_r, subsystem))
            continue;

        mnt = strdup(mntent_r.mnt_dir);
        break;
    };

    endmntent(file);
    return mnt;
}

static char *cg_path(const char *subsystem, va_list ap)
{
    char *root, *path;

    root = cg_get_mount(subsystem);
    path = joinpath(root, ap);

    free(root);
    return path;
}

char *cg_get_path(const char *subsystem, ...)
{
    va_list ap;
    char *path;

    va_start(ap, subsystem);
    path = cg_path(subsystem, ap);
    va_end(ap);

    return path;
}

int cg_open_subsystem(const char *subsystem)
{
    char *root = cg_get_mount(subsystem);
    if (root == NULL)
        return -1;

    int dirfd = open(root, O_RDONLY | O_CLOEXEC);
    free(root);

    if (dirfd < 0)
        return -1;
    return dirfd;
}

int cg_open_controller(const char *subsystem, ...)
{
    va_list ap;
    char *path;

    va_start(ap, subsystem);
    path = cg_path(subsystem, ap);
    va_end(ap);

    int ret = mkdir_parents(path, 0755);
    if (ret < 0)
        return -1;

    int dirfd = open(path, O_RDONLY | O_CLOEXEC);
    free(path);

    if (dirfd < 0)
        return -1;
    return dirfd;
}

int cg_destroy_controller(const char *subsystem, ...)
{
    va_list ap;
    char *path;

    va_start(ap, subsystem);
    path = cg_path(subsystem, ap);
    va_end(ap);

    int ret = rmdir(path);

    free(path);
    return ret;
}

int cg_open_subcontroller(int cg, const char *controller)
{
    if (mkdirat(cg, controller, 0755) < 0 && errno != EEXIST)
        return -1;

    int dirfd = openat(cg, controller, O_RDONLY | O_CLOEXEC);
    if (dirfd < 0)
        return -1;

    return dirfd;
}

int subsystem_set(int cg, const char *device, const char *value)
{
    int fd = openat(cg, device, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    ssize_t bytes_w = write(fd, value, strlen(value));
    close(fd);
    return bytes_w;
}

FILE *subsystem_open(int cg, const char *device, const char *mode)
{
    int fd = openat(cg, device, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return NULL;

    return fdopen(fd, mode);
}
