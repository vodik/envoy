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

#define PAM_SM_SESSION

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

#include "lib/envoy.h"

#define UNUSED           __attribute__((unused))
#define PAM_LOG_ERR      LOG_AUTHPRIV | LOG_ERR
#define PAM_LOG_WARNING  LOG_AUTHPRIV | LOG_WARNING

static int __attribute__((format (printf, 2, 3))) pam_setenv(pam_handle_t *ph, const char *fmt, ...)
{
    va_list ap;
    int nbytes;
    char *line = NULL;

    va_start(ap, fmt);
    nbytes = vasprintf(&line, fmt, ap);
    va_end(ap);

    if (nbytes < 0)
        return -1;

    pam_putenv(ph, line);
    free(line);
    return 0;
}

static bool pam_get_agent(struct agent_data_t *data, uid_t uid, gid_t gid)
{
    if (setegid(gid) < 0 || seteuid(uid) < 0) {
        syslog(PAM_LOG_ERR, "pam-envoy: failed to drop privileges to start agent for uid=%d: %s",
               uid, strerror(errno));
        return false;
    }

    int ret = envoy_agent(data, AGENT_DEFAULT, true);
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

    if (setegid(0) < 0 || seteuid(0) < 0) {
        syslog(PAM_LOG_ERR, "pam-envoy: failed to restore privileges after starting agent: %s",
               strerror(errno));
    }

    return ret;
}

/* PAM entry point for session creation */
int pam_sm_open_session(pam_handle_t *ph, int UNUSED flags,
                        int UNUSED argc, const char UNUSED **argv)
{
    struct agent_data_t data;
    const struct passwd *pwd;
    const char *user;
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

    if (!pam_get_agent(&data, pwd->pw_uid, pwd->pw_gid)) {
        syslog(PAM_LOG_WARNING, "pam-envoy: failed to get agent for user");
        return PAM_SUCCESS;
    }

    if (data.type == AGENT_GPG_AGENT) {
        pam_setenv(ph, "GPG_AGENT_INFO=%s", data.gpg);
    }

    pam_setenv(ph, "SSH_AUTH_SOCK=%s", data.sock);
    pam_setenv(ph, "SSH_AGENT_PID=%d", data.pid);

    return PAM_SUCCESS;
}

/* PAM entry point for session cleanup */
int pam_sm_close_session(pam_handle_t UNUSED *ph, int UNUSED flags,
                         int UNUSED argc, const char UNUSED **argv)
{
    return PAM_IGNORE;
}

/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t UNUSED *ph, int UNUSED flags,
                        int UNUSED argc, const char UNUSED **argv)
{
    return PAM_IGNORE;
}

/* PAM entry point for setting user credentials (that is, to actually
 * establish the authenticated user's credentials to the service
 * provider) */
int pam_sm_setcred(pam_handle_t UNUSED *ph, int UNUSED flags,
                   int UNUSED argc, const char UNUSED **argv)
{
    return PAM_IGNORE;
}

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t UNUSED *ph, int UNUSED flags,
                     int UNUSED argc, const char UNUSED **argv)
{
    return PAM_IGNORE;
}

// vim: et:sts=4:sw=4:cino=(0
