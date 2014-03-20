#pragma once

#include <dbus/dbus.h>

DBusConnection *get_connection(DBusBusType type);

int start_transient_unit(DBusConnection *conn, const char *name,
                         const char *desc, char **ret);
int get_unit_by_pid(DBusConnection *conn, dbus_uint32_t pid, char **ret);
int stop_unit(DBusConnection *conn, const char *path, char **ret);
int get_unit_state(DBusConnection *conn, const char *path, char **ret);
