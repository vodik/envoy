#include "dbus.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <dbus/dbus.h>

#include "util.h"

static inline void dbus_msg_unref(DBusMessage **msg)
{
    if (*msg)
        dbus_message_unref(*msg);
}

#define _cleanup_dbus_msg_  _cleanup_(dbus_msg_unref)

static void _noreturn_ _printf_(3,4) dbus_err(int eval, DBusError *err, const char *fmt, ...)
{
    fprintf(stderr, "%s: ", program_invocation_short_name);

    if (fmt) {
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fprintf(stderr, ": ");
    }

    fprintf(stderr, "%s\n", err->message);
    exit(eval);
}

static DBusMessage *dbus_send_message(DBusConnection *conn, DBusMessage *msg)
{
    DBusError err;
    DBusMessage *reply;

    dbus_error_init(&err);
    reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);
    if (!reply)
        dbus_err(EXIT_FAILURE, &err, "dbus error");

    dbus_connection_flush(conn);
    return reply;
}

static int dbus_reply_object_path(DBusMessage *reply, char **ret)
{
    DBusMessageIter args;

    if (!dbus_message_iter_init(reply, &args)) {
        warnx("message has no arguments");
        return -1;
    }

    switch (dbus_message_iter_get_arg_type(&args)) {
    case 'o':
        if (ret) {
            dbus_message_iter_get_basic(&args, ret);
            *ret = strdup(*ret);
        }
        return 0;
    default:
        warnx("message is of the wrong type");
        return -1;
    }
}

static void set_property(DBusMessageIter *props, const char *key, int type, const void *value)
{
    DBusMessageIter prop, var;
    const char type_str[] = { type, '\0' };

    dbus_message_iter_open_container(props, 'r', NULL, &prop);
    dbus_message_iter_append_basic(&prop, 's', &key);
    dbus_message_iter_open_container(&prop, 'v', type_str, &var);
    dbus_message_iter_append_basic(&var, type, &value);
    dbus_message_iter_close_container(&prop, &var);
    dbus_message_iter_close_container(props, &prop);
}

static void set_pids(DBusMessageIter *props)
{
    DBusMessageIter t, a, v;
    const char *key = "PIDs";
    const char *type_str = "au";
    const dbus_int32_t pids[] = { getpid() };
    const dbus_int32_t *p = pids;

    dbus_message_iter_open_container(props, DBUS_TYPE_STRUCT, NULL, &t);
    dbus_message_iter_append_basic(&t, DBUS_TYPE_STRING, &key);

    dbus_message_iter_open_container(&t, 'v', type_str, &v);
    dbus_message_iter_open_container(&v, 'a', "u", &a);
    dbus_message_iter_append_fixed_array(&a, 'u', &p, 1);
    dbus_message_iter_close_container(&v, &a);
    dbus_message_iter_close_container(&t, &v);

    dbus_message_iter_close_container(props, &t);
}

/* StartTransientUnit(in  s name,
                      in  s mode,
                      in  a(sv) properties,
                      in  a(sa(sv)) aux,
                      out o job); */
int start_transient_unit(DBusConnection *conn, const char *name,
                         const char *slice, const char *desc, char **ret)
{
    static const char *mode = "fail";

    _cleanup_dbus_msg_ DBusMessage *msg, *reply;
    DBusMessageIter args, props, aux;

    msg = dbus_message_new_method_call("org.freedesktop.systemd1",
                                       "/org/freedesktop/systemd1",
                                       "org.freedesktop.systemd1.Manager",
                                       "StartTransientUnit");
    if (!msg)
        errx(EXIT_FAILURE, "can't allocate new method call");

    dbus_message_append_args(msg, 's', &name, 's', &mode, 0);

    dbus_message_iter_init_append(msg, &args);

    dbus_message_iter_open_container(&args, 'a', "(sv)", &props);
    set_property(&props, "Description", 's', desc);
    if (slice)
        set_property(&props, "Slice", 's', slice);
    set_pids(&props);
    dbus_message_iter_close_container(&args, &props);

    dbus_message_iter_open_container(&args, 'a', "(sa(sv))", &aux);
    dbus_message_iter_close_container(&args, &aux);

    reply = dbus_send_message(conn, msg);
    return dbus_reply_object_path(reply, ret);
}

/* GetUnitByPID(in  u pid, */
/*              out o unit); */
int get_unit_by_pid(DBusConnection *conn, dbus_uint32_t pid, char **ret)
{
    _cleanup_dbus_msg_ DBusMessage *msg, *reply;

    if (pid == 0)
        pid = getpid();

    msg = dbus_message_new_method_call("org.freedesktop.systemd1",
                                       "/org/freedesktop/systemd1",
                                       "org.freedesktop.systemd1.Manager",
                                       "GetUnitByPID");

    dbus_message_append_args(msg, 'u', &pid, 0);
    reply = dbus_send_message(conn, msg);
    return dbus_reply_object_path(reply, ret);
}

/* Stop(in  s mode, */
/*      out o job); */
int stop_unit(DBusConnection *conn, const char *path, char **ret)
{
    _cleanup_dbus_msg_ DBusMessage *msg, *reply;
    static const char *mode = "fail";

    msg = dbus_message_new_method_call("org.freedesktop.systemd1",
                                       path,
                                       "org.freedesktop.systemd1.Unit",
                                       "Stop");

    dbus_message_append_args(msg, 's', &mode, 0);
    reply = dbus_send_message(conn, msg);
    return dbus_reply_object_path(reply, ret);
}

static int query_property(DBusConnection *conn, const char *path, const char *interface,
                          const char *property, const char type, void *ret)
{
    _cleanup_dbus_msg_ DBusMessage *msg, *reply;
    DBusMessageIter args, var;

    msg = dbus_message_new_method_call("org.freedesktop.systemd1", path,
                                       "org.freedesktop.DBus.Properties",
                                       "Get");

    dbus_message_append_args(msg, 's', &interface, 's', &property, 0);
    reply = dbus_send_message(conn, msg);

    dbus_message_iter_init(reply, &args);
    if (dbus_message_iter_get_arg_type(&args) != 'v') {
        warnx("message is of the wrong type");
        return -EINVAL;
    }

    dbus_message_iter_recurse(&args, &var);
    if (dbus_message_iter_get_arg_type(&var) != type) {
        warnx("message is of the wrong type");
        return -EINVAL;
    }

    dbus_message_iter_get_basic(&var, ret);
    return 0;
}

int get_unit_state(DBusConnection *conn, const char *path, char **ret)
{
    char *tmp;
    if (query_property(conn, path, "org.freedesktop.systemd1.Unit",
                       "SubState", 's', &tmp) < 0)
        return -EINVAL;

    if (ret)
        *ret = strdup(tmp);
    return 0;
}

DBusConnection *get_connection(DBusBusType type)
{
    DBusError err;
    DBusConnection *conn;

    dbus_error_init(&err);
    conn = dbus_bus_get(type, &err);
    if (dbus_error_is_set(&err))
        dbus_err(EXIT_FAILURE, &err, "connection error");
    dbus_error_free(&err);

    return conn;
}
