# snitch

A GTK4 / libadwaita replacement for the OpenSnitch Qt **connection prompt**.

- Listens on the same gRPC socket as `opensnitch-ui` and asks you what to do with each new connection.
- Shows a dialog equivalent to the Qt one.
- Follows the defaults saved by the Qt UI (`~/.config/opensnitch/settings.conf`, read-only).

> Only one UI can own the socket. Stop `opensnitch-ui` (and `opensnitch-zenity`) before starting `snitch`.

## Usage

```sh
snitch                          # listen for the daemon and prompt for connections
snitch --demo                   # preview the dialog and print the resulting rule as JSON
snitch --demo-scenario appimage # preview a specific scenario
```

### Options

| Option                   | Description                                                                                  |
|--------------------------|----------------------------------------------------------------------------------------------|
| `--demo`                 | Show the dialog with a fake connection; nothing is sent or saved                             |
| `--demo-scenario <name>` | Demo with a given scenario (implies `--demo`)                                                |
| `--socket <address>`     | Address to listen on (default: `server_address` from the Qt settings, else `unix:///tmp/osui.sock`) |
| `--settings <path>`      | Qt settings file (default: `~/.config/opensnitch/settings.conf`)                             |
| `-h`, `--help`           | Show help                                                                                    |

### Demo scenarios

| Scenario   | Shows                                        |
|------------|----------------------------------------------|
| `curl`     | A regular program connecting to a host (default) |
| `appimage` | An AppImage path (`/tmp/.mount_*`)           |
| `snap`     | A snap package path                          |
| `dns`      | A DNS lookup (UDP port 53)                   |
| `lan`      | A connection to a local network address      |
| `icmp`     | A connection without a port (ping)          |
| `unknown`  | A process the daemon could not identify      |
| `badchecksum` | A program whose checksum differs from saved rules (warning and update page) |

### Socket addresses

The address must match `Server.Address` in `/etc/opensnitchd/default-config.json`.

| Form                  | Example                  |
|-----------------------|--------------------------|
| Unix socket           | `unix:///tmp/osui.sock`  |
| Abstract unix socket  | `unix-abstract:snitch`   |
| TCP                   | `127.0.0.1:50051`        |

## Settings honoured

Read from the `[global]` section of the Qt UI settings:

| Key                                        | Effect                                                                 |
|--------------------------------------------|------------------------------------------------------------------------|
| `default_action`                           | Default action (drop, allow, reject) and the one the countdown applies |
| `default_duration`                         | Preselected duration                                                   |
| `default_target`                           | Preselected "apply to" entry                                           |
| `default_timeout`                          | Seconds before the default applies; `0` disables the popup            |
| `default_popup_position`                   | Screen corner (needs a compositor with layer-shell, see below)         |
| `default_popup_advanced`                   | Start with the advanced view open                                      |
| `default_popup_advanced_dstip`, `_dstport`, `_uid`, `_checksum` | Pre-checked advanced options                        |
| `server_address`                           | Address to listen on                                                   |

The settings are re-read on every prompt, so changes made in the Qt preferences apply immediately.

## Checksum warning

When a saved rule pins a program's MD5 and the running binary has a different one, the dialog shows a red **WARNING, bad checksum** line. Its **More info** link opens a page that shows the current and expected checksums and lets you pin the new one in the rules that disagree.

| Button        | Effect                                           |
|---------------|--------------------------------------------------|
| Update rule   | Updates the rule selected in the list            |
| Update all    | Updates every listed rule                        |

- Requires `"Rules": {"EnableChecksums": true}` in `/etc/opensnitchd/default-config.json`; without it the daemon sends no checksums and nothing is compared.
- Only list rules that combine the program path and a `process.hash.md5` condition are checked, which is what the "Checksum" advanced option creates.
- Snitch learns the saved rules from the daemon when it connects (the rule files are readable only by root). If you edit rules while it runs, restart `snitch` to refresh them.
- Updates are sent to the daemon as a rule change, and it saves them to its rule files.

## Install

### Build

Requires Rust, GTK 4, libadwaita and gtk4-layer-shell, plus `protoc`.

```sh
cargo build --release
sudo install -Dm755 target/release/snitch /usr/bin/snitch
```

### Run as a service

The unit in `contrib/systemd/snitch.service` is a **systemd user service**, so it runs inside your graphical session where it can open windows.

```sh
install -Dm644 contrib/systemd/snitch.service ~/.config/systemd/user/snitch.service
systemctl --user daemon-reload
systemctl --user enable --now snitch.service
```

If you currently use the Qt UI, stop it first so `snitch` can take the socket:

```sh
systemctl --user disable --now opensnitch-ui.service   # if you run it as a service
pkill opensnitch-ui                                    # otherwise
```

## Compositor support

| Environment                  | Popup position setting | Window                            |
|------------------------------|------------------------|-----------------------------------|
| Hyprland, Sway, KDE (Wayland)| Honoured               | Overlay layer, anchored to corner |
| GNOME (Wayland), X11         | Ignored                | Normal window, placed by compositor |

## Not implemented yet

- Writing settings back to the Qt settings file.
