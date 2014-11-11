#pragma once

#include <dbus/dbus.h>

DBusConnection *get_connection(DBusBusType type);

int start_transient_unit(DBusConnection *conn, const char *name,
                         const char *slice, const char *desc, char **ret);
int get_unit(DBusConnection *conn, const char *name, char **ret);
int stop_unit(DBusConnection *conn, const char *path, char **ret);
int get_unit_state(DBusConnection *conn, const char *path, char **ret);
