## envoy

A simple `ssh-agent` and `ssh-add` wrapper. I wrote this tool to better
manage the lifetime of `ssh-agent` under systemd. Starting it in
`.zshrc` was clobbering systemd's session tracking with old sessions.

### Usage

```
systemctl enable envoy.socket
```

Then add the following to `.zshrc`/`.bashrc`:

```
envoy [files ...]
eval $(envoy -p)
```
