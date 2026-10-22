# snitch

A GTK4 / libadwaita replacement for the OpenSnitch Qt **connection prompt**.

Snitch listens on the same gRPC socket as `opensnitch-ui` and asks you what to do with each new connection.

It also uses the defaults saved by the Qt UI (`~/.config/opensnitch/settings.conf`, read-only).

![snitch prompt dialog](docs/screenshots/dialog.png)

## Usage

```sh
snitch                          # listen for the daemon and prompt for connections
snitch --demo                   # preview the dialog and print the resulting rule as JSON
snitch --demo-scenario appimage # preview a specific scenario
```

> Only one UI can own the socket, stop `opensnitch-ui` before starting `snitch`.

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

### Arch Linux

The package in `contrib/arch` builds a tagged release and installs the binary, the systemd user unit and the license.

```sh
cd contrib/arch
makepkg -si
```

| Kind          | Packages                                                       |
|---------------|----------------------------------------------------------------|
| Runtime       | `gtk4`, `libadwaita`, `gtk4-layer-shell`, `opensnitch`         |
| Build only    | `cargo`, `protobuf`                                            |

The unit is installed to `/usr/lib/systemd/user/`, so skip the copy step below and go straight to enabling it.

#### From a local checkout

To install before a release exists, `contrib/arch/local` builds the **committed** `HEAD` of your checkout as `snitch-git`. Commit your changes first, since uncommitted files are not included.

```sh
cd contrib/arch/local
makepkg -si
```

The version is `<Cargo version>.r<commit count>.g<short hash>`, so every new commit builds as an upgrade. It provides and conflicts with `snitch`, so only one of the two can be installed.

### Build from source

Requires Rust, GTK 4, libadwaita and gtk4-layer-shell, plus `protoc`.

```sh
cargo build --release
sudo install -Dm755 target/release/snitch /usr/bin/snitch
```

### Run as a service

The unit in `contrib/systemd/snitch.service` is a **systemd user service**, so it runs inside your graphical session where it can open windows.

```sh
# Not needed with the Arch package, which installs the unit for you:
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
