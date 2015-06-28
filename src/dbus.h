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

#include <systemd/sd-bus.h>

void start_transient_unit(sd_bus *bus, const char *name,
                          const char *slice, const char *desc);
char *get_unit(sd_bus *bus, const char *name);
void stop_unit(sd_bus *bus, const char *path);
char *get_unit_state(sd_bus *bus, const char *path);
sd_bus *get_connection(uid_t uid);
