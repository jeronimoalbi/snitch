// Snitch: an eye in the top bar for the snitch prompt program.
//
// Open eye: OpenSnitch asks about connections. Closed eye: it is paused.
// Crossed out: snitch isn't running or the daemon isn't connected, so the
// state is not known. A click switches between the first two. Turning the
// firewall off needs authorisation, which snitch asks polkit for.

import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GObject from 'gi://GObject';
import St from 'gi://St';

import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';

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

const STATES = {
    on: {
        icon: 'view-reveal-symbolic',
        label: 'Firewall on. Click to turn it off.',
    },
    off: {
        icon: 'view-conceal-symbolic',
        label: 'Firewall off. Click to turn it on.',
    },
    unknown: {
        icon: 'action-unavailable-symbolic',
        label: 'Snitch is not running or the daemon is not connected.',
    },
};

const Indicator = GObject.registerClass(
class Indicator extends PanelMenu.Button {
    _init() {
        // No menu: a click toggles the firewall.
        super._init(0.0, 'Snitch', true);

        this._icon = new St.Icon({
            icon_name: STATES.unknown.icon,
            style_class: 'system-status-icon',
        });
        this.add_child(this._icon);

        this._busy = false;
        this._state = 'unknown';
        this._proxy = null;
        this._proxyIds = [];

        this.connect('button-press-event', () => {
            this._toggle();
            return Clutter.EVENT_STOP;
        });
        this.connect('touch-event', () => {
            this._toggle();
            return Clutter.EVENT_STOP;
        });
        this.connect('key-press-event', (_actor, event) => {
            const key = event.get_key_symbol();
            if (key === Clutter.KEY_Return || key === Clutter.KEY_space) {
                this._toggle();
                return Clutter.EVENT_STOP;
            }
            return Clutter.EVENT_PROPAGATE;
        });

        this._connectProxy();
        this._sync();
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
    }

    async _toggle() {
        if (this._busy) {
            return;
        }
        if (this._state === 'unknown') {
            Main.notify('Snitch', STATES.unknown.label);
            return;
        }
        this._busy = true;
        try {
            if (this._state === 'on') {
                // Shows the password prompt before snitch acts.
                await this._proxy.DisableAsync();
            } else {
                await this._proxy.EnableAsync();
            }
        } catch (error) {
            const message = Gio.DBusError.strip_remote_error(error) ?? `${error}`;
            Main.notifyError('Snitch', message);
        } finally {
            this._busy = false;
            if (!this._destroyed) {
                this._sync();
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
