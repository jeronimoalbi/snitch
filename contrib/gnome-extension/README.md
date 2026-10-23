# Snitch for GNOME Shell

An eye in the top bar for the [snitch](../../README.md) prompt program, which
must be running. Open eye: OpenSnitch asks about connections. Closed eye: it is
paused. Crossed out: snitch isn't running or the daemon isn't connected.

A click opens a menu with:

- **Firewall on**: turn it on or off. Off asks for your password (see below).
- **Stop snitch**: off while snitch runs; on stops it, off again starts it.
  Either way, and also when snitch stops by itself, a notification tells you.
  While snitch is stopped nothing asks you: the daemon applies its own default.
- **Start snitch on login**: enables or disables `snitch.service`.
- **Keep prompt on top**: on by default. GNOME lets no program stay on top
  by itself, so the extension does it for snitch's windows. It doesn't take
  keyboard focus, so it can't catch what you are typing. Saved in
  `~/.config/snitch/gnome-extension.ini`.
- **Prompt defaults**: action, duration, what to apply to, time to answer,
  position and the advanced checks, as in the Qt preferences. GNOME lets a
  program place no window itself, so the extension moves the prompt to the
  chosen corner when it appears.

## Install

Needs snitch `0.9.0` or newer and GNOME Shell 51 (others untried).

```sh
cp -r contrib/gnome-extension \
  ~/.local/share/gnome-shell/extensions/snitch@jeronimoalbi.github.io
```

Log out and back in, then
`gnome-extensions enable snitch@jeronimoalbi.github.io`.

## Turning the firewall off needs your password

Snitch offers its on/off switch to every program that runs as you, so a program
you didn't mean to run could silence your firewall. Therefore turning it **off**
asks for your password through
[polkit](https://polkit.pages.freedesktop.org/polkit/); turning it on doesn't.
Every change shows a notification, and a pause ends when snitch or the daemon
reconnects.

To skip the password, put this in `/etc/polkit-1/rules.d/50-snitch.rules`:

```js
polkit.addRule(function(action, subject) {
    if (action.id == "io.github.jeronimoalbi.Snitch.disable-interception" &&
        subject.local && subject.active && subject.isInGroup("wheel")) {
        return polkit.Result.YES;
    }
});
```

**Any program running as a member of that group can then pause your firewall
silently**, which is what OpenSnitch is there to catch. Skip it unless you
accept that.

## Prompt defaults

Read from and saved to the OpenSnitch settings file (the one snitch reads, so
`--settings` is followed; by default `~/.config/opensnitch/settings.conf`).
Use the arrows to change a choice: it is saved at once and applies to the next
prompt. Only keys in `[global]` are touched; the rest of the file stays as it
was. If snitch isn't running, the options are greyed out so the menu never
edits a file snitch doesn't use.

## Troubleshooting

Crossed-out eye: check `systemctl --user status snitch`. Extension errors are in
`journalctl -f /usr/bin/gnome-shell`.

## For developers

Snitch offers `io.github.jeronimoalbi.Snitch` at
`/io/github/jeronimoalbi/Snitch` on the session bus. Properties: `Version`
(currently 1), `Interception` (`on`/`off`/`unknown`), `Connected`,
`SettingsPath`. Methods: `Enable()` and `Disable()` (polkit-checked).

```sh
gdbus call --session --dest io.github.jeronimoalbi.Snitch \
  --object-path /io/github/jeronimoalbi/Snitch \
  --method org.freedesktop.DBus.Properties.Get \
  io.github.jeronimoalbi.Snitch Interception
```
