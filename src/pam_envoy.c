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

#define PAM_SM_SESSION
#define PAM_SM_AUTH

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "agents.h"
#include "socket.h"
#include "gpg-protocol.h"
#include "util.h"

#define PAM_LOG_ERR   LOG_AUTHPRIV | LOG_ERR
#define PAM_LOG_WARN  LOG_AUTHPRIV | LOG_WARNING

static _printf_(2, 3) int pam_setenv(pam_handle_t *ph, const char *fmt, ...)
{
    va_list ap;
    int nbytes;
    _cleanup_free_ char *line = NULL;

    va_start(ap, fmt);
    nbytes = vasprintf(&line, fmt, ap);
    va_end(ap);

    if (nbytes < 0)
        return -1;

    pam_putenv(ph, line);
    return 0;
}

static int set_privileges(bool drop, uid_t *uid, gid_t *gid)
{
    uid_t tmp_uid = geteuid();
    gid_t tmp_gid = getegid();

    if (drop && tmp_uid == *uid)
        return false;

    if (setegid(*gid) < 0 || seteuid(*uid) < 0) {
        if (drop) {
            syslog(PAM_LOG_ERR, "pam-envoy: failed to set privileges to uid=%d gid=%d: %s",
                   *uid, *gid, strerror(errno));
        }
        return false;
    }

    *uid = tmp_uid;
    *gid = tmp_gid;
    return true;
}

static int pam_get_agent(struct agent_data_t *data, enum agent id, uid_t uid, gid_t gid)
{
    bool dropped = set_privileges(true, &uid, &gid);

    int ret = envoy_get_agent(id, data, AGENT_ENVIRON);
    if (ret < 0)
        syslog(PAM_LOG_ERR, "failed to fetch agent: %s", strerror(errno));

    switch (data->status) {
    case ENVOY_STOPPED:
    case ENVOY_STARTED:
    case ENVOY_RUNNING:
        break;
    case ENVOY_FAILED:
        syslog(PAM_LOG_ERR, "agent failed to start, check envoyd's log");
    case ENVOY_BADUSER:
        syslog(PAM_LOG_ERR, "connection rejected, user is unauthorized to use this agent");
    }

    if (dropped)
        set_privileges(false, &uid, &gid);

    return ret;
}

/* PAM entry point for session creation */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *ph, int _unused_ flags,
                                   int argc, const char **argv)
{
    struct agent_data_t data;
    const struct passwd *pwd;
    const char *user;
    enum agent id = AGENT_DEFAULT;
    int ret;

    ret = pam_get_user(ph, &user, NULL);
    if (ret != PAM_SUCCESS) {
        syslog(PAM_LOG_ERR, "pam-envoy: couldn't get the user name: %s",
               pam_strerror(ph, ret));
        return PAM_SERVICE_ERR;
    }

    pwd = getpwnam(user);
    if (!pwd) {
        syslog(PAM_LOG_ERR, "pam-envoy: error looking up user information: %s",
               strerror(errno));
        return PAM_SERVICE_ERR;
    }

    if (argc > 1) {
        syslog(PAM_LOG_WARN, "pam-envoy: too many arguments");
        return PAM_SUCCESS;
    } else if (argc == 1) {
        id = lookup_agent(argv[0]);
    }

    if (pam_get_agent(&data, id, pwd->pw_uid, pwd->pw_gid) < 0) {
        syslog(PAM_LOG_WARN, "pam-envoy: failed to get agent for user");
        return PAM_SUCCESS;
    }

    if (data.type == AGENT_GPG_AGENT) {
        _cleanup_gpg_ struct gpg_t *agent = gpg_agent_connection(data.gpg, pwd->pw_dir);
        gpg_update_tty(agent);
    }

    if (data.gpg[0]) {
        pam_setenv(ph, "GPG_AGENT_INFO=%s", data.gpg);
    }

    pam_setenv(ph, "SSH_AUTH_SOCK=%s", data.sock);

    return PAM_SUCCESS;
}

/* PAM entry point for session cleanup */
PAM_EXTERN int pam_sm_close_session(pam_handle_t _unused_ *ph, int _unused_ flags,
                                    int _unused_ argc, const char _unused_ **argv)
{
    return PAM_IGNORE;
}

/* PAM entry point for authentication verification */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t _unused_ *ph, int _unused_ flags,
                                   int _unused_ argc, const char _unused_ **argv)
{
    struct agent_data_t data;
    const struct passwd *pwd;
    const char *user, *password;
    enum agent id = AGENT_DEFAULT;
    int ret;

    ret = pam_get_user(ph, &user, NULL);
    if (ret != PAM_SUCCESS) {
        syslog(PAM_LOG_ERR, "pam-envoy: couldn't get the user name: %s",
               pam_strerror(ph, ret));
        return PAM_SERVICE_ERR;
    }

    pwd = getpwnam(user);
    if (!pwd) {
        syslog(PAM_LOG_ERR, "pam-envoy: error looking up user information: %s",
               strerror(errno));
        return PAM_SERVICE_ERR;
    }

    /* Look up the password */
    ret = pam_get_item(ph, PAM_AUTHTOK, (const void**)&password);
    if (ret != PAM_SUCCESS || password == NULL) {
        if (ret == PAM_SUCCESS)
            syslog(PAM_LOG_WARN, "pam-envoy: no password is available for user");
        else
            syslog(PAM_LOG_WARN, "pam-envoy: no password is available for user: %s",
                   pam_strerror(ph, ret));
        return PAM_SUCCESS;
    }

    if (pam_get_agent(&data, id, pwd->pw_uid, pwd->pw_gid) < 0) {
        syslog(PAM_LOG_WARN, "pam-envoy: failed to get agent for user");
        return PAM_SUCCESS;
    }

    if (data.type == AGENT_GPG_AGENT && agent_running(&data)) {
        _cleanup_gpg_ struct gpg_t *agent = gpg_agent_connection(data.gpg, pwd->pw_dir);

        if (password) {
            const struct fingerprint_t *fpt = gpg_keyinfo(agent);
            for (; fpt; fpt = fpt->next) {
                if (gpg_preset_passphrase(agent, fpt->fingerprint, -1, password) < 0)
                    syslog(PAM_LOG_ERR, "failed to unlock '%s'", fpt->fingerprint);
            }
        }
    }

    return PAM_SUCCESS;
}

/* PAM entry point for setting user credentials (that is, to actually
 * establish the authenticated user's credentials to the service
 * provider) */
PAM_EXTERN int pam_sm_setcred(pam_handle_t _unused_ *ph, int _unused_ flags,
                              int _unused_ argc, const char _unused_ **argv)
{
    return PAM_IGNORE;
}

/* PAM entry point for authentication token (password) changes */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t _unused_ *ph, int _unused_ flags,
                                int _unused_ argc, const char _unused_ **argv)
{
    return PAM_IGNORE;
}

// vim: et:sts=4:sw=4:cino=(0
