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

#ifndef GPG_PROTOCOL_H
#define GPG_PROTOCOL_H

struct fingerprint_t {
    char *fingerprint;
    struct fingerprint_t *next;
};


int gpg_agent_connection(const char *sock);
int gpg_update_tty(int fd);
struct fingerprint_t *gpg_keyinfo(int fd);

int gpg_preset_passphrase(int fd, const char *fingerprint, int timeout, const char *password);

void free_fingerprints(struct fingerprint_t *frpt);

#endif

// vim: et:sts=4:sw=4:cino=(0
