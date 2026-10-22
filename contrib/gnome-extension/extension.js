// Snitch: an eye in the top bar for the snitch prompt program.
//
// Open eye: OpenSnitch asks about connections. Closed eye: it is paused.
// Crossed out: snitch isn't running or the daemon isn't connected, so the
// state is not known. A click opens a menu to turn the firewall on or off and
// to choose whether snitch starts on login. Turning the firewall off needs
// authorisation, which snitch asks polkit for.

import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import GObject from 'gi://GObject';
import St from 'gi://St';

import { Extension } from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';

import { loadSettings, saveSetting } from './settings.js';

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
    <property name="SettingsPath" type="s" access="read"/>
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

// The choices of the prompt options. The values are what the OpenSnitch
// settings file stores: an index for the first three, seconds for the timeout.
const ACTIONS = [
    { value: 0, label: 'Deny' },
    { value: 1, label: 'Allow' },
    { value: 2, label: 'Reject' },
];
const DURATIONS = ['once', '30 seconds', '5 minutes', '15 minutes', '30 minutes',
    '1 hour', '12 hours', 'until reboot', 'forever']
    .map((label, value) => ({ value, label }));
const TARGETS = ['This executable', 'This command line', 'Destination port',
    'Destination IP', 'This user', 'This process']
    .map((label, value) => ({ value, label }));
const TIMEOUTS = [5, 10, 15, 20, 30, 45, 60, 120]
    .map(value => ({ value, label: `${value} seconds` }));

// The advanced options the prompt can start with checked.
const PROMPT_SWITCHES = [
    ['advanced', 'Open the advanced view'],
    ['dstIp', 'Check destination IP'],
    ['dstPort', 'Check destination port'],
    ['uid', 'Check user ID'],
    ['checksum', 'Check checksum'],
];

// A menu row to pick one of a few values with the arrows on either side.
const Stepper = GObject.registerClass(
    class Stepper extends PopupMenu.PopupBaseMenuItem {
        _init(title, options, onChange) {
            super._init({ activate: false });
            this._options = options;
            this._onChange = onChange;
            this._selected = 0;

            this.add_child(new St.Label({
                text: title,
                x_expand: true,
                y_align: Clutter.ActorAlign.CENTER,
            }));
            this._value = new St.Label({
                y_align: Clutter.ActorAlign.CENTER,
                style: 'min-width: 8em; text-align: center;',
            });
            this.add_child(this._button('go-previous-symbolic', -1));
            this.add_child(this._value);
            this.add_child(this._button('go-next-symbolic', 1));
            this._show();
        }

        _button(icon, step) {
            const button = new St.Button({
                style_class: 'button',
                can_focus: true,
                child: new St.Icon({ icon_name: icon, style_class: 'popup-menu-icon' }),
            });
            button.connect('clicked', () => {
                const count = this._options.length;
                this._selected = (this._selected + step + count) % count;
                this._show();
                this._onChange(this._options[this._selected].value);
            });
            return button;
        }

        _show() {
            this._value.text = this._options[this._selected].label;
        }

        // Shows `value`. One that is not among the choices (the file can hold
        // any number of seconds) is added, so it is shown as it is.
        setValue(value) {
            let index = this._options.findIndex(o => o.value === value);
            if (index < 0) {
                const label = value === 0 ? 'never ask' : `${value} seconds`;
                this._options = [...this._options, { value, label }]
                    .sort((a, b) => a.value - b.value);
                index = this._options.findIndex(o => o.value === value);
            }
            this._selected = index;
            this._show();
        }
    });

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
            this._running = new PopupMenu.PopupSwitchMenuItem('Snitch running', false);
            this._running.connect('toggled', (_item, on) => this._setRunning(on));
            // Whether snitch had the bus name at the last look; null until known.
            this._owned = null;
            // What a switch click asked for, shown until snitch catches up.
            this._wanted = null;
            this._wantedTimer = 0;
            this._login = new PopupMenu.PopupSwitchMenuItem('Start snitch on login', false);
            this._login.connect('toggled', (_item, on) => this._setAutostart(on));
            this._loginNote = new PopupMenu.PopupMenuItem('', { reactive: false });

            this._prompt = new PopupMenu.PopupSubMenuMenuItem('Prompt defaults');
            this._steppers = {
                action: new Stepper('Default action', ACTIONS,
                    value => this._savePrompt('action', value)),
                duration: new Stepper('Duration', DURATIONS,
                    value => this._savePrompt('duration', value)),
                target: new Stepper('Apply to', TARGETS,
                    value => this._savePrompt('target', value)),
                timeout: new Stepper('Time to answer', TIMEOUTS,
                    value => this._savePrompt('timeout', value)),
            };
            this._switches = {};
            for (const stepper of Object.values(this._steppers)) {
                this._prompt.menu.addMenuItem(stepper);
            }
            this._prompt.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
            for (const [name, title] of PROMPT_SWITCHES) {
                const item = new PopupMenu.PopupSwitchMenuItem(title, false);
                item.connect('toggled', (_item, on) => this._savePrompt(name, on));
                this._switches[name] = item;
                this._prompt.menu.addMenuItem(item);
            }
            this._promptNote = new PopupMenu.PopupMenuItem('', { reactive: false });
            this._prompt.menu.addMenuItem(this._promptNote);
            this._saving = Promise.resolve();
            this._promptPath = null;

            const menu = this.menu;
            menu.addMenuItem(this._status);
            menu.addMenuItem(this._firewall);
            menu.addMenuItem(this._running);
            menu.addMenuItem(this._login);
            menu.addMenuItem(this._loginNote);
            menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
            menu.addMenuItem(this._prompt);
            // The unit and the settings file can change outside the extension
            // (the Qt UI writes the file too), so look again each time.
            menu.connect('open-state-changed', (_menu, open) => {
                if (open) {
                    this._readAutostart();
                    this._readPrompt();
                }
            });

            this._connectProxy();
            this._sync();
            this._readAutostart();
            this._readPrompt();
        }

        // The settings file snitch uses, or null while that is not known: snitch
        // not running, or too old to say. Never guessed, so the menu can't show
        // or change a file snitch doesn't read.
        _settingsPath() {
            const proxy = this._proxy;
            const path = proxy && proxy.g_name_owner ? proxy.SettingsPath : null;
            return typeof path === 'string' && path !== '' ? path : null;
        }

        async _readPrompt() {
            const path = this._settingsPath();
            this._promptPath = path;
            let values = null;
            let problem = 'Snitch is not running, or too old to say which file it uses';
            if (path !== null) {
                try {
                    values = await loadSettings(path);
                } catch (error) {
                    problem = 'Cannot read the OpenSnitch settings';
                    console.error(`snitch: cannot read ${path}: ${error.message}`);
                }
            }
            // Snitch may have restarted with another file while reading.
            if (this._destroyed || path !== this._settingsPath()) {
                return;
            }
            const editable = values !== null;
            this._promptNote.label.text = editable ? 'Applies to the next prompt' : problem;
            for (const [name, stepper] of Object.entries(this._steppers)) {
                stepper.setSensitive(editable);
                if (editable) {
                    stepper.setValue(values[name]);
                }
            }
            for (const [name, item] of Object.entries(this._switches)) {
                item.setSensitive(editable);
                if (editable) {
                    item.setToggleState(values[name]);
                }
            }
        }

        // Saves one option. Saves run one after the other, so quick clicks end
        // with the last value in the file.
        _savePrompt(name, value) {
            this._saving = this._saving.then(async () => {
                // Only the file that is shown; if snitch has moved to another, the
                // change is dropped and the menu shows the new file.
                const path = this._settingsPath();
                try {
                    if (path === null || path !== this._promptPath) {
                        throw new Error('snitch now uses another settings file');
                    }
                    await saveSetting(name, value, path);
                } catch (error) {
                    Main.notifyError('Snitch', `Cannot save the setting: ${error.message}`);
                    // Show what the file says, which undoes the change.
                    await this._readPrompt();
                }
            });
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

            const owned = Boolean(proxy && proxy.g_name_owner);
            if (proxy && this._owned !== null && owned !== this._owned) {
                this._announceRunning(owned);
            }
            if (proxy) {
                this._owned = owned;
            }
            if (this._wanted === owned) {
                this._clearWanted();
            }
            this._running.setToggleState(this._wanted ?? owned);
            this._running.setSensitive(proxy !== null && !this._busy);
            // The file can change when snitch (re)starts.
            if (this._settingsPath() !== this._promptPath) {
                this._readPrompt();
            }
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

        // Tells the user when snitch starts or stops, whoever did it: the
        // switch, systemctl, or a crash.
        _announceRunning(running) {
            if (running) {
                Main.notify('Snitch started', 'OpenSnitch asks about new connections.');
            } else {
                Main.notify('Snitch stopped',
                    'Nothing asks about connections now. The OpenSnitch daemon ' +
                    'applies its own default action.');
            }
        }

        _clearWanted() {
            this._wanted = null;
            if (this._wantedTimer) {
                GLib.source_remove(this._wantedTimer);
                this._wantedTimer = 0;
            }
        }

        async _setRunning(on) {
            if (this._busy || !this._proxy) {
                return;
            }
            this._busy = true;
            this._wanted = on;
            this._sync();
            try {
                await systemd(on ? 'StartUnit' : 'StopUnit',
                    new GLib.Variant('(ss)', [UNIT, 'replace']), '(o)');
                // The job is queued; the name appears or goes a moment later.
                // If it doesn't within a while, show what is true.
                this._wantedTimer = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 10, () => {
                    this._wantedTimer = 0;
                    this._wanted = null;
                    this._sync();
                    return GLib.SOURCE_REMOVE;
                });
            } catch (error) {
                this._wanted = null;
                Main.notifyError('Snitch', Gio.DBusError.strip_remote_error(error) ?? `${error}`);
            } finally {
                this._busy = false;
                if (!this._destroyed) {
                    this._sync();
                }
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
            this._clearWanted();
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
