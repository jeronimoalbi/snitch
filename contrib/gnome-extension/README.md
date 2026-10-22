# Snitch for GNOME Shell

An eye in the top bar that shows whether OpenSnitch is asking about
connections, and turns it on or off with a click.

| Icon        | Meaning                                                 |
|-------------|---------------------------------------------------------|
| Open eye    | The firewall is on and asks about new connections       |
| Closed eye  | The firewall is paused: connections are not intercepted |
| Crossed out | Snitch isn't running or the daemon isn't connected      |

It is a small front end for the [snitch](../../README.md) prompt program, which
must be running. The extension does not talk to the OpenSnitch daemon itself.

## Install

You need a snitch newer than 0.9.0 (one that offers the D-Bus service) and GNOME
Shell 51. Other versions may work, but they have not been tried; add them
to `shell-version` in `metadata.json` once you have.

```sh
cp -r contrib/gnome-extension \
  ~/.local/share/gnome-shell/extensions/snitch@jeronimoalbi.github.io
```

Log out and back in (GNOME on Wayland only finds new extensions at login), then:

```sh
gnome-extensions enable snitch@jeronimoalbi.github.io
```

## Turning the firewall off needs your password

This is on purpose. Snitch offers its on/off switch to every program that runs
as you, and a program you did not mean to run could use it to switch your
firewall off without a sound. So:

- **Turning it on** is one click. That can only make things stricter.
- **Turning it off** asks for your password, through the same prompt GNOME shows
  for other system changes. Snitch asks
  [polkit](https://polkit.pages.freedesktop.org/polkit/), which checks who is
  asking, not just that someone is.
- Every change, in either direction, shows a notification, so a pause you did
  not start does not go unnoticed.
- A pause does not outlive snitch: when snitch or the daemon (re)connects, the
  firewall is turned back on.

### Skip the password

If you pause the firewall often, you can tell polkit to say yes without asking.
Put this in `/etc/polkit-1/rules.d/50-snitch.rules` (it needs root):

```js
polkit.addRule(function(action, subject) {
    if (action.id == "io.github.jeronimoalbi.Snitch.disable-interception" &&
        subject.local && subject.active && subject.isInGroup("wheel")) {
        return polkit.Result.YES;
    }
});
```

Be clear about what that gives up: **any program running as a member of that
group can then turn your firewall off silently** (you would still see the
notification afterwards). That is the same trust you give a program you run
yourself, but it also covers a program that you did not mean to run, which is
what OpenSnitch is there to catch. Leave the rule out unless you accept that.

## If the icon is crossed out

Snitch isn't running or the daemon isn't connected. Check
`systemctl --user status snitch`, then see "If something goes wrong" in the main
README. Errors from the extension are in `journalctl -f /usr/bin/gnome-shell`.

## Releases

The extension has its own version and its own tags, like
`gnome-extension-v0.1.0`, separate from the snitch releases (`v0.9.0`).

## For developers

Snitch offers this interface on the session bus, as
`io.github.jeronimoalbi.Snitch` at `/io/github/jeronimoalbi/Snitch`:

| Member         | Description                                       |
|----------------|---------------------------------------------------|
| `Version`      | Interface version, currently 1                    |
| `Interception` | `on`, `off` or `unknown`                          |
| `Connected`    | The daemon is connected to snitch                 |
| `Enable()`     | Turn the firewall on                              |
| `Disable()`    | Turn the firewall off, after polkit authorises it |

```sh
gdbus call --session --dest io.github.jeronimoalbi.Snitch \
  --object-path /io/github/jeronimoalbi/Snitch \
  --method org.freedesktop.DBus.Properties.Get \
  io.github.jeronimoalbi.Snitch Interception
```
