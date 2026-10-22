# Snitch for GNOME Shell

An eye in the top bar that shows whether OpenSnitch is asking about
connections. A click opens a menu to turn it on or off, to choose whether
snitch starts when you log in and to change what the prompt starts with.

| Icon        | Meaning                                                 |
|-------------|---------------------------------------------------------|
| Open eye    | The firewall is on and asks about new connections       |
| Closed eye  | The firewall is paused: connections are not intercepted |
| Crossed out | Snitch isn't running or the daemon isn't connected      |

| Menu item             | What it does                                    |
|-----------------------|-------------------------------------------------|
| Status line           | Says what the icon means                        |
| Firewall on           | Turns the firewall on or off (off asks for your |
|                       | password, see below)                            |
| Stop snitch           | Off while snitch runs; on stops it, and turning |
|                       | it off again starts it                          |
| Start snitch on login | Turns the autostart of snitch on or off         |
| Prompt defaults       | Opens the prompt options, see below             |

It is a small front end for the [snitch](../../README.md) prompt program, which
must be running. The extension does not talk to the OpenSnitch daemon itself.

## Install

You need snitch 0.9.0 or newer (the first with the D-Bus service) and GNOME
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

- **Turning it on** needs no password. That can only make things stricter.
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

## Prompt defaults

The same options as in the OpenSnitch preferences, so you don't have to open
the Qt window. They are read from and saved to the OpenSnitch settings file,
by default `~/.config/opensnitch/settings.conf`, the file the Qt UI uses.

| Option                    | What it sets                                |
|---------------------------|---------------------------------------------|
| Default action            | Deny, allow or reject; also what is applied |
|                           | when the time to answer runs out            |
| Duration                  | How long the rule lasts, from once to       |
|                           | forever                                     |
| Apply to                  | What the rule matches: the executable, the  |
|                           | command line, the port, the IP...           |
| Time to answer            | Seconds before the default action is applied|
| Open the advanced view    | Start with the advanced options showing     |
| Check destination IP...   | Which advanced checks start ticked          |

Use the arrows to change a choice. Each change is saved at once and applies to
the next prompt; there is nothing to restart. Only these keys of the file are
touched, in the `[global]` section. Everything else the Qt UI keeps there, such
as window sizes, stays as it was.

Some things to know:

- The position of the prompt is not offered: GNOME doesn't let a program place
  its own windows, so the setting has no effect here.
- Snitch tells the extension which file it reads, so `--settings` is followed.
  While snitch isn't running (or is too old to say), the options are greyed
  out, so the menu never shows or changes a file snitch doesn't use.
- The menu shows the file as it is each time it opens, so a change made in the
  Qt UI shows up there.
- "Time to answer" stepping never offers `0` (never ask, apply the default).
  With a default action of allow that would silently allow everything. If the
  file already says `0`, the menu shows it as it is.

## If the icon is crossed out

Snitch isn't running or the daemon isn't connected. Check
`systemctl --user status snitch`, then see "If something goes wrong" in the main
README. Errors from the extension are in `journalctl -f /usr/bin/gnome-shell`.

## For developers

Snitch offers this interface on the session bus, as
`io.github.jeronimoalbi.Snitch` at `/io/github/jeronimoalbi/Snitch`:

| Member         | Description                                       |
|----------------|---------------------------------------------------|
| `Version`      | Interface version, currently 1                    |
| `Interception` | `on`, `off` or `unknown`                          |
| `Connected`    | The daemon is connected to snitch                 |
| `SettingsPath` | The OpenSnitch settings file snitch reads         |
| `Enable()`     | Turn the firewall on                              |
| `Disable()`    | Turn the firewall off, after polkit authorises it |

```sh
gdbus call --session --dest io.github.jeronimoalbi.Snitch \
  --object-path /io/github/jeronimoalbi/Snitch \
  --method org.freedesktop.DBus.Properties.Get \
  io.github.jeronimoalbi.Snitch Interception
```
