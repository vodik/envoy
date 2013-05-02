## envoy

Envoy helps you to manage ssh keys in similar fashion to [keychain], but
done in c, takes advantage of cgroups and systemd.

The daemon, `envoyd`, starts the agent of choice in a sanitized
environment and caches the associated environmental variables in
memory. The agent is started on demand and it's lifetime is tracked
through cgroups for accuracy.

The `envoy` command connects to the daemon and gets all the information
associated with the current running agent. It can then do things like
add new keys to the agent or output shell code to inject these variables
into a shell.

  [keychain]: http://www.funtoo.org/wiki/Keychain

### Setup

To setup envoy, first enable the socket:

    # systemctl enable envoy.socket

Then add the following to your shell's rc file.

    envoy -t ssh-agent [key ...]     # gpg-agent also supported
    source <(envoy -p)

### Usage

    usage: envoy [options] [key ...]
    Options:
     -h, --help            display this help
     -v, --version         display version
     -a, --add             add private key identities
     -k, --clear           force identities to expire (gpg-agent only)
     -K, --kill            kill the running agent
     -l, --list            list fingerprints of all loaded identities
     -p, --print           print out environmental arguments
     -t, --agent=AGENT     set the prefered to start

Note that when passing in keys, if they reside in `~/.ssh/`, just
providing the filename is sufficient.

### Envoy with ssh-agent

When invoking `envoy` causes `ssh-agent` to start, on that first run
any keys passed to `envoy` will be added to the agent. Without any
arguments, it'll try to add `.ssh/id_rsa`, `.ssh/id_dsa`, and
`.ssh/id_ecdsa` automatically.

### Using gpg-agent

Keys are never implicitly added with `gpg-agent`. Instead, keys have to
be explicitly added through either `envoy -a` or `ssh-add`. The agent
will then continue track those identities automatically without having
to be specified in the future.

The agent will also still respect `~/.gnupg/gpg-agent.conf`. For
example, to disable scdaemon, put `disable-scdaemon` in that file.

Note that invoking envoy also updates gpg-agent with the current status,
if available, of the tty and X. It is the same effect of running `echo
UPDATESTARTUPTTY | gpg-connect-agent`. This may cause some odd behaviour
with the pinentry. The pinentry may appear in an inappropriate place if
this data becomes stale. This is a limitation of gpg-agent itself.

### Wrappers with envoy

Envoy has two simple built-in wrappers. Supporting both `ssh` and
`scp`, you need to set something like this up:

    export PATH="$HOME/bin:$PATH"
    ln -s /usr/bin/envoy ~/bin/ssh

The `~/bin/ssh` binary will automatically connect to the preferred agent
and then execute `/usr/bin/ssh`. This does an excellent job of working
around the gpg-agent issues above since it guarantees gpg-agent will
have the correct information before running ssh.
