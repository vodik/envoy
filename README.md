## envoy

A simple wrapper around `ssh-agent`, `gpg-agent` and `ssh-add`.

I wrote this tool originally to better manage the lifetime of
`ssh-agent` under systemd.  I used to start it in `.zshrc` was would
clobber systemd's session tracking with old sessions. For example, if
`ssh-agent` was started inside a ssh connection, the system would
continue to see the ssh login persist after the connection was closed
because the agent would stay running.

Envoy comes with in two parts. There is a daemon server processes,
`envoyd`, supervises the agent processes.  On a incoming connection
it'll make sure an agent is running for the connecting user and it'll
cache the returned environmental variables. The `envoy` command connects
to this server and request these environmental variables and do various
operations with them.

### Setup

To setup envoy, first enable the socket unit. For example, for
`ssh-agent`:

    # systemctl enable envoy@ssh-agent.socket

Then add the following to your shell's rc file.

    envoy [file ...]
    source <(envoy -p)

### Usage

    usage: envoy [options] [files ...]
    Options:
     -h, --help       display this help
     -v, --version    display version
     -a, --add        add private key identities
     -k, --clear      force identities to expire (gpg-agent only)
     -K, --kill       kill the running agent
     -l, --list       list fingerprints of all loaded identities
     -p, --print      print out environmental arguments

`envoy` without any command line flags acts like `envoy -a` **only** if
its the "first run"; if `envoy` is responsible for spawning a new agent.
Otherwise nothing happens.

### Using gpg-agent

Envoy with `gpg-agent` works slightly differently. Keys are never
implicitly added with `gpg-agent`. Instead a explicit call to either
`envoy -a` or `ssh-add` is needed after the agent is running to trigger
`gpg-agent` to track those identities. There's no need for an explicit
`~/.gnupg/gpg-agent.conf`, but it may be used to configure gpg-agent to
behave as preferred.

Calling `envoy`, however, also updates `gpg-agent` with the current tty
and, if running, about X. This may cause some strange behaviour when
using the ncurses pinentry. The pinentry will appear on the tty on which
`envoy` was last run. This is a limitation of `gpg-agent` itself.
