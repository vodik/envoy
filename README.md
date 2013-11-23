## envoy

Envoy helps you to manage ssh keys in similar fashion to [keychain], but
done in c, takes advantage of cgroups and systemd.

The daemon, `envoyd`, starts the agent of choice in a sanitized
environment and caches the associated environmental variables in memory.
The agent is started on demand and it's lifetime is tracked through
cgroups for accuracy. `envoyd` is typically started as root and can thus
serve all the users on the system at once. It checks the credentials of
the incoming connection and starts the agent under that uid/guid. If its
started as a user it will only be able to serve that particular user's
requests.

The `envoy` command connects to the daemon and gets all the information
associated with the current running agent. It can then do things like
add new keys to the agent or output shell code to inject these variables
into a shell.

This effectively allows a user to share a single long-running
authentication agent between all shells and sessions in a clean and
managed fashion that doesn't clutter user login sessions.

  [keychain]: http://www.funtoo.org/wiki/Keychain

### Setup

To setup envoy, first enable the socket:

    # systemctl enable envoy@ssh-agent.socket

Then add the following to your shell's rc file.

    envoy -t ssh-agent [key ...]     # gpg-agent also supported
    source <(envoy -p)

The envoyd daemon will also run just fine under a user session, just
note that it won't be able to serve multiple users at once in this
configuration.

### Usage

    usage: envoy [options] [key ...]
    Options:
     -h, --help            display this help
     -v, --version         display version
     -a, --add             add private key identities
     -k, --clear           force identities to expire (gpg-agent only)
     -K, --kill            kill the running agent
     -l, --list            list fingerprints of all loaded identities
     -u, --unlock=[PASS]   unlock the agent's keyring (gpg-agent only)
     -p, --print           print out sh environmental arguments
     -f, --fish            print out fish environmental arguments
     -t, --agent=AGENT     set the prefered to start

Note that when passing in keys, if they reside in `~/.ssh/`, then just
providing the filename is sufficient.

### Envoy with ssh-agent

When invoking `envoy` causes `ssh-agent` to start, on that first run
any keys passed to `envoy` will be added to the agent. Without any
arguments, it'll try to add `.ssh/id_rsa`, `.ssh/id_dsa`, and
`.ssh/id_ecdsa` automatically.

### Envoy with gpg-agent

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

### Envoy's pam integration

Envoy provides a pam module to load the agent into the environment at
login instead of relying on `envoy -p`. To use it, edit
`/etc/pam.d/login` and add:

    session   optional    pam_envoy.so

Its also possible provide an optional argument to choose which agent
type to start:

    session   optional    pam_envoy.so    gpg-agent

Envoy can also optionally unlock gpg-agent's keyring automatically with
your password, but in order to do so it needs an auth token. To enable
this, add:

    auth      optional    pam_envoy.so
    session   optional    pam_envoy.so

Note that this replies on gpg-agent's passphrase presetting support. To
enable this, ensure `allow-preset-passphrase` is also in
`~/.gnupg/gpg-agent.conf`.

### Wrappers with envoy

Envoy has support for wrapping commands through `envoy-exec`. The
utility will connect to the daemon, setup the environment, and launch
the provided command. For example:

    envoy-exec ssh git@github.com

It is also possible to symlink `envoy-exec` to another name to provide
a terser wrapper.

    export PATH="$HOME/bin:$PATH"
    ln -s /usr/bin/envoy-exec ~/bin/ssh

This will make `ssh` behave as if its been invoked as `envoy-exec ssh`.

### Cgroups support

Having been unable to find a simple cgroups library targeted at
embedding, I wrote my own. `cgroups.c` has been borrowed from my own
project [here][cgroups].

Any bugs with the cgroups support or confusions with terminology (I'm
pretty sure my terminology is way off) should be reported there.

  [cgroups]: https://github.com/vodik/clique
