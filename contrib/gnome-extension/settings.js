// Reads and writes the prompt options snitch takes from the OpenSnitch Qt UI
// settings file (`~/.config/opensnitch/settings.conf`).
//
// The file is a QSettings INI that also holds window layouts and other things
// that are not ours, so a change only replaces or adds one `key=value` line in
// `[global]` and leaves every other byte alone. Snitch reads the file again for
// each prompt, so a change applies to the next one.

import Gio from 'gi://Gio';
import GLib from 'gi://GLib';

Gio._promisify(Gio.File.prototype, 'load_contents_async', 'load_contents_finish');
Gio._promisify(Gio.File.prototype, 'replace_contents_async', 'replace_contents_finish');

const SECTION = 'global';

// Each option: its key in the file, the value snitch assumes when the key is
// missing (keep in step with `Settings::default` in src/settings.rs), and how
// the value is written.
export const OPTIONS = {
    action: { key: 'default_action', fallback: 0, kind: 'number', max: 2 },
    duration: { key: 'default_duration', fallback: 6, kind: 'number', max: 8 },
    target: { key: 'default_target', fallback: 0, kind: 'number', max: 5 },
    timeout: { key: 'default_timeout', fallback: 30, kind: 'number' },
    position: { key: 'default_popup_position', fallback: 0, kind: 'number', max: 4 },
    advanced: { key: 'default_popup_advanced', fallback: false, kind: 'flag' },
    dstIp: { key: 'default_popup_advanced_dstip', fallback: false, kind: 'flag' },
    dstPort: { key: 'default_popup_advanced_dstport', fallback: false, kind: 'flag' },
    uid: { key: 'default_popup_advanced_uid', fallback: false, kind: 'flag' },
    checksum: { key: 'default_popup_advanced_checksum', fallback: false, kind: 'flag' },
};

export function settingsPath() {
    return GLib.build_filenamev([GLib.get_user_config_dir(), 'opensnitch', 'settings.conf']);
}

// Splits `text` into lines, keeping each line's ending so it can be put back.
function splitLines(text) {
    return text.match(/[^\n]*\n|[^\n]+$/g) ?? [];
}

// `[name]` of a section header line, or null.
function sectionOf(line) {
    const match = /^\s*\[([^\]]*)\]\s*$/.exec(line);
    return match ? match[1] : null;
}

// The `[global]` values by key.
function globalValues(text) {
    const values = new Map();
    let inside = false;
    for (const line of splitLines(text)) {
        const name = sectionOf(line);
        if (name !== null) {
            inside = name === SECTION;
        } else if (inside && !/^\s*[;#]/.test(line)) {
            const split = line.indexOf('=');
            if (split > 0) {
                values.set(line.slice(0, split).trim(), line.slice(split + 1).trim());
            }
        }
    }
    return values;
}

// Every option with the value in `text`, or snitch's assumption when the key is
// missing or not valid (the same clamping as src/settings.rs).
export function readSettings(text) {
    const values = globalValues(text);
    const result = {};
    for (const [name, option] of Object.entries(OPTIONS)) {
        const raw = values.get(option.key);
        if (option.kind === 'flag') {
            result[name] = raw === undefined ? option.fallback : raw === 'true';
        } else {
            const number = /^\d+$/.test(raw ?? '') ? Number(raw) : option.fallback;
            result[name] = Math.min(number, option.max ?? Number.MAX_SAFE_INTEGER);
        }
    }
    return result;
}

// `text` with `key` set to `value` in `[global]`: the line is replaced where it
// is, or added at the end of the section (which is added when missing).
export function withSetting(text, key, value) {
    const lines = splitLines(text);
    const wanted = `${key}=${value}`;
    let inside = false;
    let lastInside = -1;
    let found = -1;
    let sectionSeen = false;
    lines.forEach((line, index) => {
        const name = sectionOf(line);
        if (name !== null) {
            inside = name === SECTION;
            sectionSeen ||= inside;
        }
        if (!inside) {
            return;
        }
        if (name === null && line.trim() !== '') {
            lastInside = index;
        }
        const split = line.indexOf('=');
        if (found < 0 && name === null && split > 0 && !/^\s*[;#]/.test(line) &&
            line.slice(0, split).trim() === key) {
            found = index;
        }
    });

    const ending = text.includes('\r\n') ? '\r\n' : '\n';
    if (found >= 0) {
        lines[found] = `${wanted}${/\r?\n$/.exec(lines[found])?.[0] ?? ''}`;
    } else if (sectionSeen) {
        // Directly after the last entry, not before the blank line that
        // separates this section from the next.
        const at = lastInside >= 0 ? lastInside : lines.findIndex(l => sectionOf(l) === SECTION);
        if (!/\n$/.test(lines[at])) {
            lines[at] += ending;
        }
        lines.splice(at + 1, 0, `${wanted}${ending}`);
    } else {
        if (lines.length > 0 && !/\n$/.test(lines[lines.length - 1])) {
            lines[lines.length - 1] += ending;
        }
        if (lines.length > 0) {
            lines.push(ending);
        }
        lines.push(`[${SECTION}]${ending}`, `${wanted}${ending}`);
    }
    return lines.join('');
}

// How a value is written in the file.
export function format(option, value) {
    return option.kind === 'flag' ? (value ? 'true' : 'false') : `${value}`;
}

const decoder = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();

// The current options, or snitch's assumptions when there is no file yet.
export async function loadSettings(path = settingsPath()) {
    const file = Gio.File.new_for_path(path);
    try {
        const [contents] = await file.load_contents_async(null);
        return readSettings(decoder.decode(contents));
    } catch (error) {
        if (error.matches?.(Gio.IOErrorEnum, Gio.IOErrorEnum.NOT_FOUND)) {
            return readSettings('');
        }
        throw error;
    }
}

// Sets one option in the file. The file is replaced in one piece, and only if
// nobody else changed it since it was read, so a change the Qt UI saved at the
// same moment is not lost: the read and edit are then done again.
export async function saveSetting(name, value, path = settingsPath()) {
    const option = OPTIONS[name];
    if (!option) {
        throw new Error(`unknown option ${name}`);
    }
    const file = Gio.File.new_for_path(path);
    for (let attempt = 0; attempt < 3; attempt++) {
        let text = '';
        let etag = null;
        try {
            const [contents, tag] = await file.load_contents_async(null);
            text = decoder.decode(contents);
            etag = tag;
        } catch (error) {
            if (!error.matches?.(Gio.IOErrorEnum, Gio.IOErrorEnum.NOT_FOUND)) {
                throw error;
            }
            GLib.mkdir_with_parents(GLib.path_get_dirname(path), 0o700);
        }
        const updated = withSetting(text, option.key, format(option, value));
        try {
            await file.replace_contents_async(
                encoder.encode(updated), etag, false,
                etag === null ? Gio.FileCreateFlags.PRIVATE : Gio.FileCreateFlags.NONE, null);
            return;
        } catch (error) {
            if (!error.matches?.(Gio.IOErrorEnum, Gio.IOErrorEnum.WRONG_ETAG)) {
                throw error;
            }
        }
    }
    throw new Error('the settings file keeps changing, try again');
}

// The extension's own preferences, apart from the OpenSnitch file. A plain
// key file, because a copied extension can't ship a compiled GSettings schema.
const PREFERENCES = 'snitch/gnome-extension.ini';

function preferencesPath() {
    return GLib.build_filenamev([GLib.get_user_config_dir(), PREFERENCES]);
}

// Whether the prompt windows are kept above others; on unless turned off.
export function loadKeepOnTop(path = preferencesPath()) {
    const file = new GLib.KeyFile();
    try {
        file.load_from_file(path, GLib.KeyFileFlags.NONE);
        return file.get_boolean('prompt', 'keep_on_top');
    } catch (error) {
        return true;
    }
}

export function saveKeepOnTop(on, path = preferencesPath()) {
    const file = new GLib.KeyFile();
    file.set_boolean('prompt', 'keep_on_top', on);
    GLib.mkdir_with_parents(GLib.path_get_dirname(path), 0o700);
    file.save_to_file(path);
}
