## envoy

A simple `ssh-agent`/`gpg-agent` and `ssh-add` wrapper and keychain.

I wrote this tool to better manage the lifetime of `ssh-agent` under
systemd.  Starting it in `.zshrc` was clobbering systemd's session
tracking with old sessions.

### Usage

```
systemctl enable envoy@ssh-agent.socket
```

Then add the following to `.zshrc`/`.bashrc`:

```
envoy [files ...]
eval $(envoy -p)
```
