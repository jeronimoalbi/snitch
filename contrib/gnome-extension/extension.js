// Snitch: an eye in the top bar for the snitch prompt program.
//
// Open eye: OpenSnitch asks about connections. Closed eye: it is paused.
// Crossed out: snitch isn't running or the daemon isn't connected, so the
// state is not known. A click opens a menu to turn the firewall on or off and
// to choose whether snitch starts on login. Turning the firewall off needs
// authorisation, which snitch asks polkit for.

import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import GObject from 'gi://GObject';
import St from 'gi://St';

import { Extension } from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';

Gio._promisify(Gio.DBusConnection.prototype, 'call', 'call_finish');

const BUS_NAME = 'io.github.jeronimoalbi.Snitch';
const OBJECT_PATH = '/io/github/jeronimoalbi/Snitch';
// The interface version this extension understands (see src/bus.rs).
const INTERFACE_VERSION = 1;

const INTERFACE_XML = `
<node>
  <interface name="io.github.jeronimoalbi.Snitch">
    <property name="Version" type="u" access="read"/>
    <property name="Interception" type="s" access="read"/>
    <property name="Connected" type="b" access="read"/>
    <method name="Enable"/>
    <method name="Disable"/>
  </interface>
</node>`;

const SnitchProxy = Gio.DBusProxy.makeProxyWrapper(INTERFACE_XML);

const UNIT = 'snitch.service';

// What the user's systemd says about the unit's autostart.
// `on` and `off` can be changed; anything else cannot, and says why.
function autostartFrom(unitFileState) {
    switch (unitFileState) {
        case 'enabled':
        case 'enabled-runtime':
            return { on: true, reason: null };
        case 'disabled':
            return { on: false, reason: null };
        case 'static':
            return { on: false, reason: 'The unit has no [Install] section.' };
        case 'masked':
        case 'masked-runtime':
            return { on: false, reason: 'The unit is masked.' };
        default:
            return { on: false, reason: 'snitch.service is not installed.' };
    }
}

// Calls a method of the user's systemd and returns the reply's values.
async function systemd(method, parameters, replyType) {
    const reply = await Gio.DBus.session.call(
        'org.freedesktop.systemd1', '/org/freedesktop/systemd1',
        'org.freedesktop.systemd1.Manager', method, parameters,
        replyType ? new GLib.VariantType(replyType) : null,
        Gio.DBusCallFlags.NONE, 10000, null);
    return reply.recursiveUnpack();
}

const STATES = {
    on: {
        icon: 'view-reveal-symbolic',
        label: 'Firewall is on',
    },
    off: {
        icon: 'view-conceal-symbolic',
        label: 'Firewall is paused',
    },
    unknown: {
        icon: 'action-unavailable-symbolic',
        label: 'Snitch is not running or the daemon is not connected',
    },
};

const Indicator = GObject.registerClass(
    class Indicator extends PanelMenu.Button {
        _init() {
            // 0.5 centres the menu under the icon; 0.0 would anchor its left edge.
            super._init(0.5, 'Snitch', false);

            this._icon = new St.Icon({
                icon_name: STATES.unknown.icon,
                style_class: 'system-status-icon',
            });
            this.add_child(this._icon);

            this._busy = false;
            this._state = 'unknown';
            this._proxy = null;
            this._proxyIds = [];
            this._autostart = autostartFrom(null);

            this._status = new PopupMenu.PopupMenuItem('', { reactive: false });
            this._firewall = new PopupMenu.PopupSwitchMenuItem('Enable firewall', false);
            this._firewall.connect('toggled', (_item, on) => this._setFirewall(on));
            this._start = new PopupMenu.PopupMenuItem('Start snitch now');
            this._start.connect('activate', () => this._startSnitch());
            this._login = new PopupMenu.PopupSwitchMenuItem('Start snitch on login', false);
            this._login.connect('toggled', (_item, on) => this._setAutostart(on));
            this._loginNote = new PopupMenu.PopupMenuItem('', { reactive: false });

            const menu = this.menu;
            menu.addMenuItem(this._status);
            menu.addMenuItem(this._firewall);
            menu.addMenuItem(this._start);
            menu.addMenuItem(this._login);
            menu.addMenuItem(this._loginNote);
            // The unit can change outside the extension, so look again each time.
            menu.connect('open-state-changed', (_menu, open) => {
                if (open) {
                    this._readAutostart();
                }
            });

            this._connectProxy();
            this._sync();
            this._readAutostart();
        }

        _connectProxy() {
            new SnitchProxy(Gio.DBus.session, BUS_NAME, OBJECT_PATH, (proxy, error) => {
                if (error) {
                    console.error(`snitch: cannot reach D-Bus: ${error.message}`);
                    return;
                }
                if (this._destroyed) {
                    return;
                }
                this._proxy = proxy;
                this._proxyIds = [
                    proxy.connect('g-properties-changed', () => this._sync()),
                    proxy.connect('notify::g-name-owner', () => this._sync()),
                ];
                this._sync();
            });
        }

        // Shows what snitch reports; anything unexpected counts as unknown.
        _sync() {
            const proxy = this._proxy;
            let state = 'unknown';
            if (proxy && proxy.g_name_owner && proxy.Version === INTERFACE_VERSION &&
                proxy.Connected && proxy.Interception in STATES) {
                state = proxy.Interception;
            }
            this._state = state;
            this._icon.icon_name = STATES[state].icon;
            this.accessible_name = STATES[state].label;

            this._status.label.text = STATES[state].label;
            this._firewall.setToggleState(state === 'on');
            this._firewall.setSensitive(state !== 'unknown' && !this._busy);
            // Starting only makes sense when snitch is not there at all.
            this._start.visible = !(proxy && proxy.g_name_owner);
        }

        _showAutostart() {
            const { on, reason } = this._autostart;
            this._login.setToggleState(on);
            this._login.setSensitive(reason === null && !this._busy);
            this._loginNote.visible = reason !== null;
            this._loginNote.label.text = reason ?? '';
        }

        async _readAutostart() {
            try {
                const [state] = await systemd(
                    'GetUnitFileState', new GLib.Variant('(s)', [UNIT]), '(s)');
                this._autostart = autostartFrom(state);
            } catch (error) {
                this._autostart = autostartFrom(null);
            }
            if (!this._destroyed) {
                this._showAutostart();
            }
        }

        async _setAutostart(on) {
            if (this._busy) {
                return;
            }
            this._busy = true;
            try {
                if (on) {
                    await systemd('EnableUnitFiles',
                        new GLib.Variant('(asbb)', [[UNIT], false, true]), null);
                } else {
                    await systemd('DisableUnitFiles',
                        new GLib.Variant('(asb)', [[UNIT], false]), null);
                }
                await systemd('Reload', null, null);
            } catch (error) {
                Main.notifyError('Snitch', Gio.DBusError.strip_remote_error(error) ?? `${error}`);
            } finally {
                this._busy = false;
                // What systemd says now is the truth, whatever happened above.
                await this._readAutostart();
                if (!this._destroyed) {
                    this._sync();
                }
            }
        }

        async _startSnitch() {
            try {
                await systemd('StartUnit',
                    new GLib.Variant('(ss)', [UNIT, 'replace']), '(o)');
            } catch (error) {
                Main.notifyError('Snitch', Gio.DBusError.strip_remote_error(error) ?? `${error}`);
            }
        }

        async _setFirewall(on) {
            if (this._busy || this._state === 'unknown') {
                return;
            }
            this._busy = true;
            this._sync();
            try {
                if (on) {
                    await this._proxy.EnableAsync();
                } else {
                    // Shows the password prompt before snitch acts.
                    await this._proxy.DisableAsync();
                }
            } catch (error) {
                const message = Gio.DBusError.strip_remote_error(error) ?? `${error}`;
                Main.notifyError('Snitch', message);
            } finally {
                this._busy = false;
                if (!this._destroyed) {
                    // Shows what snitch reports, which undoes a refused switch.
                    this._sync();
                    this._showAutostart();
                }
            }
        }

        destroy() {
            this._destroyed = true;
            if (this._proxy) {
                for (const id of this._proxyIds) {
                    this._proxy.disconnect(id);
                }
            }
            this._proxyIds = [];
            this._proxy = null;
            super.destroy();
        }
    });

export default class SnitchExtension extends Extension {
    enable() {
        this._indicator = new Indicator();
        Main.panel.addToStatusArea(this.uuid, this._indicator);
    }

    disable() {
        this._indicator?.destroy();
        this._indicator = null;
    }
}
