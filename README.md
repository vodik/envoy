## envoy

Envoy helps you to manage ssh keys in similar fashion to [keychain], but
done in c and taking advantage of cgroups, unix domain sockets, and
systemd. It's a wrapper around `ssh-agent`, `ssh-add` and `gpg-agent`.

`envoyd` is a daemon that supervises the various agents. On an incoming
connection it'll start an agent if one isn't running and return that
status of that user's running agent. It uses cgroups internally to track
the lifetime of the agents it manages.

The `envoy` command connects to this server and request these
environmental variables and do various operations with them.

  [keychain]: http://www.funtoo.org/wiki/Keychain

### Setup

To setup envoy, first enable the socket:

    # systemctl enable envoy.socket

Then add the following to your shell's rc file.

    envoy -t ssh-agent [file ...]     # or -t gpg-agent
    source <(envoy -p)

### Usage

    usage: envoy [options] [files ...]
    Options:
     -h, --help            display this help
     -v, --version         display version
     -a, --add             add private key identities
     -k, --clear           force identities to expire (gpg-agent only)
     -K, --kill            kill the running agent
     -l, --list            list fingerprints of all loaded identities
     -p, --print           print out environmental arguments
     -t, --agent=AGENT     set the prefered to start

`envoy` without any command line flags acts like `envoy -a` **only** if
it starts a new agent. Otherwise nothing happens.

### Using gpg-agent

Envoy's gpg-agent support works slightly differently. Keys are never
implicitly added with gpg-agent. Instead, keys have to be explicitly
added through either `envoy -a` or `ssh-add`. gpg-agent will then track
those identities. There's also no need for `~/.gnupg/gpg-agent.conf`,
but it will still be read to configure gpg-agent to behave as preferred.

**NOTE:** Calling envoy also updates gpg-agent with the current status,
if available, of the tty and X. This may cause some strange behaviours
with the pinentry. The pinentry may appear in an inappropriate place if
this data becomes stale. This is a limitation of gpg-agent itself.

### Wrapping `ssh`

Envoy has a simple built-in ssh wrapper. This wrapper sets up the
environment and then passes all arguments directly to `/usr/bin/ssh`. To
use it, do something like this:

    export PATH="$HOME/bin:$PATH"
    cd ~/bin
    ln -s /usr/bin/envoy ssh

This does an excellent job of working around the gpg-agent issues above
since it guarantees gpg-agent will have the correct information before
running ssh.
