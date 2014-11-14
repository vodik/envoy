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

struct gpg_t;

enum keyflags {
    KEY_DISABLED   = 1,
    KEY_SSHCONTROL = 1 << 1,
    KEY_CONFIRM    = 1 << 2,
};

struct fingerprint_t {
    char *fingerprint;
    enum keyflags flags;
    struct fingerprint_t *next;
};

struct gpg_t *gpg_agent_connection(const char *sock, const char *home);
void gpg_close(struct gpg_t *gpg);

int gpg_reload_agent(struct gpg_t *gpg);
int gpg_update_tty(struct gpg_t *gpg);
int gpg_preset_passphrase(struct gpg_t *gpg, const char *fingerprint, int timeout, const char *password);
struct fingerprint_t *gpg_keyinfo(struct gpg_t *gpg);

void free_fingerprints(struct fingerprint_t *frpt);

#define _cleanup_gpg_ __attribute__((cleanup(gpg_closep)))
static inline void gpg_closep(struct gpg_t **p) { if (*p) gpg_close(*p); }

// vim: et:sts=4:sw=4:cino=(0
