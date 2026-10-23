# snitch

[![Test](https://github.com/jeronimoalbi/snitch/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/jeronimoalbi/snitch/actions/workflows/test.yml)
[![Audit](https://github.com/jeronimoalbi/snitch/actions/workflows/audit.yml/badge.svg?branch=master)](https://github.com/jeronimoalbi/snitch/actions/workflows/audit.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A GTK4 prompt for [OpenSnitch](https://github.com/evilsocket/opensnitch). It
reads the defaults you already saved in the official Qt UI.

<p align="center">
  <img src="docs/screenshots/dialog.png" alt="snitch prompt dialog" width="70%">
</p>

> Snitch is an unofficial project and isn't affiliated with OpenSnitch.

## Install

You need the OpenSnitch daemon (`opensnitchd`) running, plus GTK 4 and
libadwaita. Only one prompt program can talk to the daemon, so stop
`opensnitch-ui` first.

**Arch Linux** (needs `gtk4`, `libadwaita`, `gtk4-layer-shell`, `opensnitch`):

```sh
cd contrib/arch && makepkg -si          # the tagged release
cd contrib/arch/local && makepkg -si    # the committed HEAD, as snitch-git
```

**From source** (Rust 1.92+, GTK 4, libadwaita 1.4+, gtk4-layer-shell,
`protoc`):

```sh
cargo build --release
sudo install -Dm755 target/release/snitch /usr/bin/snitch
```

## Start it

Snitch runs as a **systemd user service**, so it can open windows in your
session. The Arch package installs the service; otherwise add it:

```sh
install -Dm644 contrib/systemd/snitch.service ~/.config/systemd/user/snitch.service
systemctl --user daemon-reload
```

Then stop the Qt prompt and start snitch:

```sh
systemctl --user disable --now opensnitch-ui.service  # if it runs as a service
pkill opensnitch-ui                                   # otherwise
systemctl --user enable --now snitch.service
```

Run `curl https://example.com`: a dialog should appear, unless a rule already
covers it. `snitch --demo` shows the dialog with a pretend connection without
touching the firewall.

## Using the dialog

- **Apply to**: what the rule matches: the program, its command line, the
  port, IP address or host name, a user, or a process. `*.example.com` or
  `192.168.1.0/24` cover a whole group.
- **Duration**: once, 30 seconds to 12 hours, until reboot, or forever
  ("forever" rules are saved on disk).
- **Allow** lets it through. **Drop** discards the traffic (the program times
  out); the arrow switches to **Reject**, which refuses at once.
- **Eye button**: process details (path, arguments, parents, environment).
- **⋮ button**: extra conditions that must all match (IP, port, user, checksum).
- **Countdown**: the default button shows the seconds left, e.g. `Drop (30)`;
  at zero the default is applied. Touching a control stops it.

Closing the window applies your default action. Escape does nothing, so a prompt
can't be dismissed by accident.

A "forever" rule is a file in `/etc/opensnitchd/rules/`, such as
`allow-always-simple-usr-bin-curl.json`. To undo it, delete the file (needs
root); restart the daemon if it doesn't notice.

## Defaults

Snitch has no preferences window. It reads `[global]` in
`~/.config/opensnitch/settings.conf` (the Qt UI's file) for every prompt, so
there is nothing to restart. Edit it, use the Qt preferences, or use the
[GNOME extension](contrib/gnome-extension/README.md).

- `default_action`: `0` Drop (default), `1` Allow, `2` Reject.
- `default_duration`: `0` once, `1` 30s, `2` 5m, `3` 15m, `4` 30m, `5` 1h,
  `6` 12h (default), `7` until reboot, `8` forever.
- `default_timeout`: seconds before the default applies (default 30). `0` never
  shows the dialog and applies the default at once.
- `default_target`: what "Apply to" starts on: `0` program (default), `1`
  command line, `2` port, `3` IP, `4` user, `5` process.
- `default_popup_position`: `0` centre (default), `1` top right, `2` bottom
  right, `3` top left, `4` bottom left. Works on compositors with layer-shell
  (Hyprland, Sway, KDE) and, on GNOME, through the extension; not on X11.

> **Careful.** A timed-out prompt gets the default action *with the default
> duration*. "Reject" plus "forever" turns a missed prompt into a permanent
> block, and if it was your DNS resolver, your network stops. For first tests
> use `default_action=1` and `default_duration=0` (allow, once).

## More things snitch does

- **Checksum warning.** If a saved rule pins a program's MD5 and the running
  program differs, the dialog shows a red **WARNING, bad checksum**. **More
  info** opens a page with both checksums where you can pin the new one
  (**Update rule** or **Update all**). It needs `"Rules": {"EnableChecksums":
  true}` in `/etc/opensnitchd/default-config.json`, and only checks rules made
  with the "Checksum" advanced option. Snitch learns the rules when it connects;
  restart it if you edit rules meanwhile.
- **Timeout notification.** When the default is applied, a desktop notification
  says so, e.g. **Connection dropped**. GNOME's Do Not Disturb silences it.
- **Top-bar switch for GNOME.** An optional
  [extension](contrib/gnome-extension/README.md) shows whether the firewall is
  on and lets you pause it, start or stop snitch and edit the defaults.
- **Logs.** Each question and answer goes to the journal
  (`journalctl --user -u snitch -f`). Command-line arguments are never logged.

## If something goes wrong

- **Nothing asks and everything connects.** The daemon has no working prompt
  program and applies its own default (allow, unless you changed it). Check
  `systemctl --user status snitch` and `journalctl --user -u snitch -n 20`. You
  should see `daemon … connected, N rules`; if only `listening`, check that
  `opensnitchd` runs and its `Server.Address` in
  `/etc/opensnitchd/default-config.json` matches snitch's address (see
  Command-line options).
- **`another UI is already listening`.** `opensnitch-ui` holds the socket:
  `pkill opensnitch-ui`, then start snitch.
- **`refused a connection from uid …`.** Something other than the daemon used
  the socket. If it was the daemon, it isn't running as root: start snitch with
  `--allow-uid <that user id>`.
- **A rule blocks something it shouldn't.** Delete its file from
  `/etc/opensnitchd/rules/`.

## Security

The daemon runs as root and trusts its prompt program, which can change rules or
turn the firewall off. So snitch takes care:

- **Only the daemon may connect.** Calls are accepted only from root. Any other
  process, including your own, is refused and logged. A TCP address
  (`--socket host:port`) can't tell who connects, so snitch warns and accepts
  any local process; use `--allow-uid` only for development.
- **Pausing needs authorisation.** The D-Bus switch turns the firewall on
  freely, but turning it off must pass polkit, so a program of yours can't do it
  silently. A paused firewall is turned back on when snitch or the daemon
  reconnects.
- **Names can't widen a rule.** Patterns built from a program's path or a host
  name are escaped, and the AppImage and Snap patterns are only offered for the
  exact path shape those systems use. A program called `x|.*` can't turn
  "Allow" into a rule that matches everything.
- **Names and icons are not borrowed.** A binary called `firefox` in `/tmp` or
  your home is shown with its own name and path, not Firefox's. Only programs in
  `/usr`, `/opt`, `/bin`, `/sbin`, `/lib`, `/lib64` or `/snap` are matched to
  desktop entries.

## Command-line options

Plain `snitch` starts it normally.

- `--demo`: show the dialog with a fake connection; nothing is sent or saved.
- `--demo-scenario <name>`: demo with a scenario: `curl` (default), `appimage`,
  `snap`, `dns`, `lan`, `icmp`, `unknown` or `badchecksum`.
- `--socket <address>`: address to listen on instead of the saved one.
- `--settings <path>`: Qt settings file (default
  `~/.config/opensnitch/settings.conf`).
- `--allow-uid <uid>`: let this user, besides root, act as the daemon
  (repeatable).
- `-h`, `--help`: show help.

Without `--socket`, snitch listens on `server_address` from the Qt settings, or
`unix:///tmp/osui.sock`. It must match `Server.Address` in the daemon's config.
`host:port` is possible but not recommended (see Security).

## License

MIT. See `LICENSE`.
