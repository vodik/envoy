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

#include "dbus.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <systemd/sd-bus.h>
#include "util.h"

static void _noreturn_ _printf_(3,4) err2(int ret, int eval, const char *fmt, ...)
{
    fprintf(stderr, "%s: ", program_invocation_short_name);
    if (fmt) {
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fprintf(stderr, ": ");
    }

    fprintf(stderr, "%s\n", strerror(-ret));
    exit(eval);
}

void start_transient_unit(sd_bus *bus, const char *name,
                          const char *slice, const char *desc)
{
    sd_bus_message *msg = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;

    int ret = sd_bus_message_new_method_call(bus, &msg,
                                             "org.freedesktop.systemd1",
                                             "/org/freedesktop/systemd1",
                                             "org.freedesktop.systemd1.Manager",
                                             "StartTransientUnit");
    if (ret < 0)
        err2(ret, EXIT_FAILURE, "failed to create new message");

    sd_bus_message_append(msg, "ss", name, "fail");

    sd_bus_message_open_container(msg, 'a', "(sv)");
    sd_bus_message_append(msg, "(sv)", "Description", "s", desc);
    sd_bus_message_append(msg, "(sv)", "SendSIGHUP", "b", true);
    sd_bus_message_append(msg, "(sv)", "PIDs", "au", 1, getpid());
    if (slice)
        sd_bus_message_append(msg, "(sv)", "Slice", "s", slice);
    sd_bus_message_close_container(msg);

    /* Auxiliary units */
    sd_bus_message_append(msg, "a(sa(sv))", 0);

    ret = sd_bus_call(bus, msg, 0, &error, NULL);
    if (ret < 0) {
        if (error.message) {
            fprintf(stderr, "%s", error.message);
            return;
        }
        err2(ret, EXIT_FAILURE, "failed to issue StartTransientUnit call");
    }


    sd_bus_message_unref(msg);
    sd_bus_error_free(&error);
}

char *get_unit(sd_bus *bus, const char *name)
{
    sd_bus_message *msg = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;

    int ret = sd_bus_call_method(bus, "org.freedesktop.systemd1",
                                 "/org/freedesktop/systemd1",
                                 "org.freedesktop.systemd1.Manager",
                                 "GetUnit", &error, &msg,
                                 "s", name);
    if (ret < 0) {
        if (error.message) {
            fprintf(stderr, "%s", error.message);
            return NULL;
        }
        err2(ret, EXIT_FAILURE, "failed to issue method call GetUnit %s", name);
    }

    char *path;
    ret = sd_bus_message_read(msg, "o", &path);
    if (ret < 0)
        err2(ret, EXIT_FAILURE, "failed to parse response message");

    sd_bus_message_unref(msg);
    sd_bus_error_free(&error);
    return strdup(path);
}

void stop_unit(sd_bus *bus, const char *path)
{
    sd_bus_message *msg = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;

    int ret = sd_bus_call_method(bus, "org.freedesktop.systemd1",
                                 path, "org.freedesktop.systemd1.Unit",
                                 "Stop", &error, &msg,
                                 "s", "fail");
    if (ret < 0) {
        if (error.message) {
            fprintf(stderr, "%s", error.message);
            return;
        }
        err2(ret, EXIT_FAILURE, "failed to issue method call Stop %s", path);
    }

    sd_bus_message_unref(msg);
    sd_bus_error_free(&error);
}

char *get_unit_state(sd_bus *bus, const char *path)
{
    sd_bus_message *msg = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;

    int ret = sd_bus_get_property(bus, "org.freedesktop.systemd1",
                                  path, "org.freedesktop.systemd1.Unit",
                                  "SubState", &error, &msg, "s");
    if (ret < 0) {
        if (error.message) {
            fprintf(stderr, "%s", error.message);
            return NULL;
        }
        err2(ret, EXIT_FAILURE, "failed to get property SubState");
    }

    char *state;
    ret = sd_bus_message_read(msg, "s", &state);
    if (ret < 0)
        err2(ret, EXIT_FAILURE, "failed to get property SubState");

    sd_bus_message_unref(msg);
    sd_bus_error_free(&error);
    return strdup(state);
}

sd_bus *get_connection(uid_t uid)
{
    sd_bus *bus = NULL;
    sd_bus_new(&bus);

    if (uid == 0) {
        sd_bus_set_address(bus, "unix:path=/run/systemd/private");
    } else {
        _cleanup_free_ char *path = NULL;
        asprintf(&path, "unix:path=/run/user/%d/systemd/private", uid);
        sd_bus_set_address(bus, path);
    }

    sd_bus_start(bus);
    return bus;
}
