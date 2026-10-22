//! Reader for the OpenSnitch Qt UI settings (`~/.config/opensnitch/settings.conf`).
//!
//! The file is a plain QSettings INI. Only the keys that influence the prompt
//! dialog are interpreted; everything else is ignored.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Default `unix:` address the daemon connects to.
pub const DEFAULT_ADDRESS: &str = "unix:///tmp/osui.sock";

/// Prompt-related options saved by the Qt UI preferences dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Index of the default action: 0 = drop (deny), 1 = allow, 2 = reject.
    pub default_action: usize,
    /// Index into [`crate::rule::DURATIONS`].
    pub default_duration: usize,
    /// Index of the default "apply to" target (0 executable .. 5 PID).
    pub default_target: usize,
    /// Seconds before the default action is applied; 0 disables the popup.
    pub timeout: u32,
    /// 0 center, 1 top right, 2 bottom right, 3 top left, 4 bottom left.
    pub popup_position: u32,
    /// Start with the advanced view expanded.
    pub advanced: bool,
    /// Pre-check "destination IP".
    pub advanced_dstip: bool,
    /// Pre-check "destination port".
    pub advanced_dstport: bool,
    /// Pre-check "user ID".
    pub advanced_uid: bool,
    /// Pre-check "checksum".
    pub advanced_checksum: bool,
    /// Address the UI gRPC server should listen on, if configured.
    pub server_address: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_action: 0,
            default_duration: 6,
            default_target: 0,
            timeout: 30,
            popup_position: 0,
            advanced: false,
            advanced_dstip: false,
            advanced_dstport: false,
            advanced_uid: false,
            advanced_checksum: false,
            server_address: None,
        }
    }
}

impl Settings {
    /// Location of the Qt UI settings file, honoring `XDG_CONFIG_HOME`.
    pub fn default_path() -> PathBuf {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".config")))
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("opensnitch").join("settings.conf")
    }

    /// Loads the settings from `path`; a missing or unreadable file gives defaults.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(err) => {
                tracing::debug!("settings {}: {err}, using defaults", path.display());
                Self::default()
            }
        }
    }

    /// Parses the INI `text`, falling back to defaults for absent or invalid keys.
    pub fn parse(text: &str) -> Self {
        let values = parse_ini(text);
        let def = Self::default();
        let get = |key: &str| values.get(&format!("global/{key}")).map(String::as_str);
        let num = |key: &str, d: usize| get(key).and_then(|v| v.parse().ok()).unwrap_or(d);
        let flag = |key: &str, d: bool| get(key).map_or(d, |v| v == "true");

        Self {
            default_action: num("default_action", def.default_action).min(2),
            default_duration: num("default_duration", def.default_duration).min(8),
            default_target: num("default_target", def.default_target).min(5),
            timeout: u32::try_from(num("default_timeout", def.timeout as usize))
                .unwrap_or(def.timeout),
            popup_position: u32::try_from(num("default_popup_position", 0))
                .unwrap_or(0)
                .min(4),
            advanced: flag("default_popup_advanced", false),
            advanced_dstip: flag("default_popup_advanced_dstip", false),
            advanced_dstport: flag("default_popup_advanced_dstport", false),
            advanced_uid: flag("default_popup_advanced_uid", false),
            advanced_checksum: flag("default_popup_advanced_checksum", false),
            server_address: get("server_address")
                .filter(|v| !v.is_empty())
                .map(String::from),
        }
    }

    /// True when popups are disabled (the Qt UI stores that as a zero timeout).
    pub fn popups_disabled(&self) -> bool {
        self.timeout == 0
    }
}

/// Flattens an INI file into `section/key -> value` pairs.
fn parse_ini(text: &str) -> HashMap<String, String> {
    let mut section = String::new();
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_string();
        } else if let Some((key, value)) = line.split_once('=')
            && !line.starts_with(';')
            && !line.starts_with('#')
        {
            out.insert(
                format!("{section}/{}", key.trim()),
                value.trim().to_string(),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "[global]\ndefault_action=2\ndefault_duration=8\ndefault_target=0\n\
        default_timeout=30\ndefault_popup_position=1\ndefault_popup_advanced=true\n\
        server_address=unix:///tmp/osui.sock\n\n[promptDialog]\ngeometry=@ByteArray(\\x1)\n";

    #[test]
    fn parses_global_keys() {
        let s = Settings::parse(SAMPLE);
        assert_eq!(s.default_action, 2);
        assert_eq!(s.default_duration, 8);
        assert_eq!(s.timeout, 30);
        assert_eq!(s.popup_position, 1);
        assert!(s.advanced);
        assert!(!s.advanced_uid);
        assert_eq!(s.server_address.as_deref(), Some("unix:///tmp/osui.sock"));
    }

    #[test]
    fn missing_keys_use_defaults() {
        assert_eq!(Settings::parse(""), Settings::default());
    }

    #[test]
    fn ignores_other_sections_and_clamps() {
        let s = Settings::parse("[other]\ndefault_action=1\n[global]\ndefault_duration=99\n");
        assert_eq!(s.default_action, 0);
        assert_eq!(s.default_duration, 8);
    }

    #[test]
    fn zero_timeout_disables_popups() {
        assert!(Settings::parse("[global]\ndefault_timeout=0\n").popups_disabled());
    }
}
