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

#ifndef CGROUPS_H
#define CGROUPS_H

#include <stdio.h>

char *cg_get_path(const char *subsystem, ...);
int cg_open_subsystem(const char *subsystem);
int cg_open_controller(const char *subsystem, ...);
int cg_destroy_controller(const char *subsystem, ...);
int cg_open_subcontroller(int cg, const char *controller);
int subsystem_set(int cg, const char *device, const char *value);
FILE *subsystem_open(int cg, const char *device, const char *mode);

#endif

// vim: et:sts=4:sw=4:cino=(0
