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
 * Copyright (C) Simon Gomizelj, 2012
 */

#pragma once

#include <dbus/dbus.h>

DBusConnection *get_connection(DBusBusType type);

int start_transient_unit(DBusConnection *conn, const char *name,
                         const char *slice, const char *desc, char **ret);
int get_unit(DBusConnection *conn, const char *name, char **ret);
int stop_unit(DBusConnection *conn, const char *path, char **ret);
int get_unit_state(DBusConnection *conn, const char *path, char **ret);
