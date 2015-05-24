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

#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#define _unused_         __attribute__((unused))
#define _noreturn_       __attribute__((noreturn))
#define _printf_(a,b)    __attribute__((format (printf, a, b)))
#define _sentinel_       __attribute__((sentinel))
#define _cleanup_(x)     __attribute__((cleanup(x)))
#define _cleanup_free_   _cleanup_(freep)
#define _cleanup_close_  _cleanup_(closep)

static inline void freep(void *p) { free(*(void **)p); }
static inline void closep(int *fd) { if (*fd >= 0) close(*fd); }

static inline bool streq(const char *s1, const char *s2) { return strcmp(s1, s2) == 0; }
static inline bool strneq(const char *s1, const char *s2, size_t n) { return strncmp(s1, s2, n) == 0; }

char *joinpath(const char *root, ...) _sentinel_;
int putenvf(const char *fmt, ...) _printf_(1, 2);
void safe_asprintf(char **strp, const char *fmt, ...) _printf_(2, 3);

int unblock_signals(void);
int get_signalfd(int signum, ...) _sentinel_;

const char *get_home_dir(void);

// vim: et:sts=4:sw=4:cino=(0
