//! The "apply to" choices offered by the prompt, ported from the Qt UI
//! (`ui/opensnitch/dialogs/prompt/utils.py`).
//!
//! Each [`Target`] carries the rule operator it produces, so the dialog only
//! has to show the label and the rule builder only has to read the operator.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::proto::Connection;

/// Operator type strings understood by the daemon.
pub mod kind {
    pub const SIMPLE: &str = "simple";
    pub const REGEXP: &str = "regexp";
    pub const NETWORK: &str = "network";
    pub const LIST: &str = "list";
}

/// Operand strings understood by the daemon.
pub mod operand {
    pub const PROCESS_PATH: &str = "process.path";
    pub const PROCESS_COMMAND: &str = "process.command";
    pub const PROCESS_ID: &str = "process.id";
    pub const PROCESS_HASH_MD5: &str = "process.hash.md5";
    pub const USER_ID: &str = "user.id";
    pub const DEST_IP: &str = "dest.ip";
    pub const DEST_HOST: &str = "dest.host";
    pub const DEST_PORT: &str = "dest.port";
    pub const DEST_NETWORK: &str = "dest.network";
}

const APPIMAGE_PREFIX: &str = "/tmp/.mount_";

/// Network aliases from the Qt UI's `network_aliases.json`.
const ALIASES: &[(&str, &[&str])] = &[
    (
        "LAN",
        &[
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "::1/128",
            "fc00::/7",
        ],
    ),
    ("MULTICAST", &["224.0.0.0/4", "ff00::/8"]),
];

/// What a [`Target`] matches on; the rule builder needs it for special cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    ProcPath,
    ProcArgs,
    ProcId,
    UserId,
    DstIp,
    DstPort,
    DstNetwork,
    DstHost,
    RegexHost,
    RegexIp,
    AppImage,
    Snap,
}

/// A rule operator: `type`, `operand` and `data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Op {
    pub kind: &'static str,
    pub operand: &'static str,
    pub data: String,
}

impl Op {
    fn simple(operand: &'static str, data: impl Into<String>) -> Self {
        Self {
            kind: kind::SIMPLE,
            operand,
            data: data.into(),
        }
    }
}

/// One entry of an "apply to" combo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Text shown in the combo.
    pub label: String,
    pub field: Field,
    /// Operator produced when this target is selected.
    pub op: Op,
    /// Disabled entries are shown but cannot be selected.
    pub enabled: bool,
}

impl Target {
    fn new(label: impl Into<String>, field: Field, op: Op) -> Self {
        Self {
            label: label.into(),
            field,
            op,
            enabled: true,
        }
    }
}

/// Sentinel the daemon sends for an unknown PID or UID (`-1` as `uint32`).
const UNKNOWN: u32 = u32::MAX;

/// Space-joined command line of the connection.
pub fn command_line(con: &Connection) -> String {
    con.process_args.join(" ")
}

/// Escapes `text` so that a regular expression matches it literally.
///
/// This is the set Go's `regexp.QuoteMeta` escapes, the engine the daemon uses.
/// Everything that comes from a program or the network (paths, host names) must
/// go through it: unescaped, a name like `x|.*` would turn a rule into one that
/// matches every program.
pub fn regex_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if "\\.+*?()|[]{}^$".contains(ch) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// A target whose operator is built from the connection, not from its label.
///
/// The label is shown to the user, so control characters are dropped from it.
/// The operator keeps the exact text.
fn target(field: Field, label: impl AsRef<str>, op: Op) -> Target {
    Target::new(crate::view::printable(label.as_ref()), field, op)
}

fn network_op(data: impl Into<String>) -> Op {
    Op {
        kind: kind::NETWORK,
        operand: operand::DEST_NETWORK,
        data: data.into(),
    }
}

fn regexp_op(operand: &'static str, data: String) -> Op {
    Op {
        kind: kind::REGEXP,
        operand,
        data,
    }
}

/// The six fixed entries, in the order the Qt preferences use for the default target.
fn fixed_targets(con: &Connection) -> Vec<Target> {
    let exe = Op::simple(operand::PROCESS_PATH, &con.process_path);
    // Without a command line the executable is the best that can be matched.
    let command = if con.process_args.first().is_none_or(String::is_empty) {
        exe.clone()
    } else {
        Op::simple(operand::PROCESS_COMMAND, command_line(con))
    };
    let mut exe_target = target(Field::ProcPath, "from this executable", exe);
    exe_target.enabled = con.process_id != UNKNOWN;
    let mut uid = target(
        Field::UserId,
        format!("from user {}", con.user_id),
        Op::simple(operand::USER_ID, con.user_id.to_string()),
    );
    uid.enabled = con.user_id != UNKNOWN;
    vec![
        exe_target,
        target(Field::ProcArgs, "from this command line", command),
        target(
            Field::DstPort,
            format!("to port {}", con.dst_port),
            Op::simple(operand::DEST_PORT, con.dst_port.to_string()),
        ),
        target(
            Field::DstIp,
            format!("to {}", con.dst_ip),
            Op::simple(operand::DEST_IP, &con.dst_ip),
        ),
        uid,
        target(
            Field::ProcId,
            "from this PID",
            Op::simple(operand::PROCESS_ID, con.process_id.to_string()),
        ),
    ]
}

/// Name of the network alias (LAN, MULTICAST) `ip` belongs to, if any.
pub fn network_alias(ip: &str) -> Option<&'static str> {
    let ip: IpAddr = ip.parse().ok()?;
    ALIASES
        .iter()
        .find(|(_, nets)| nets.iter().any(|net| in_cidr(ip, net)))
        .map(|(name, _)| *name)
}

/// True when `ip` is inside the `addr/prefix` network `cidr`.
fn in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((addr, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(net), Ok(prefix)) = (addr.parse::<IpAddr>(), prefix.parse::<u32>()) else {
        return false;
    };
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) if prefix <= 32 => {
            mask_v4(ip, prefix) == mask_v4(net, prefix)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) if prefix <= 128 => {
            mask_v6(ip, prefix) == mask_v6(net, prefix)
        }
        _ => false,
    }
}

fn mask_v4(ip: Ipv4Addr, prefix: u32) -> Ipv4Addr {
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    Ipv4Addr::from(u32::from(ip) & mask)
}

fn mask_v6(ip: Ipv6Addr, prefix: u32) -> Ipv6Addr {
    let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
    Ipv6Addr::from(u128::from(ip) & mask)
}

fn network_targets(con: &Connection) -> Vec<Target> {
    let mut out = Vec::new();
    if let Some(alias) = network_alias(&con.dst_ip) {
        out.push(target(
            Field::DstNetwork,
            format!("to {alias}"),
            network_op(alias),
        ));
    }
    let ip = con.dst_ip.parse::<IpAddr>().ok();
    let prefixes: &[u32] = match ip {
        Some(IpAddr::V4(_)) => &[24, 16, 8],
        Some(IpAddr::V6(_)) => &[64, 128],
        None => &[],
    };
    for &prefix in prefixes {
        let net = match ip {
            Some(IpAddr::V4(ip)) => mask_v4(ip, prefix).to_string(),
            Some(IpAddr::V6(ip)) => mask_v6(ip, prefix).to_string(),
            None => continue,
        };
        out.push(target(
            Field::DstNetwork,
            format!("to {net}/{prefix}"),
            network_op(format!("{net}/{prefix}")),
        ));
    }
    out
}

/// Host entry plus one wildcard entry per parent domain (down to two labels).
///
/// Host names come from DNS answers, so they are untrusted: the wildcard
/// regexps are built from the escaped name.
fn host_targets(con: &Connection) -> Vec<Target> {
    if con.dst_host.is_empty() || con.dst_host == con.dst_ip {
        return Vec::new();
    }
    let mut out = vec![target(
        Field::DstHost,
        &con.dst_host,
        Op::simple(operand::DEST_HOST, &con.dst_host),
    )];
    let parts: Vec<&str> = con.dst_host.split('.').skip(1).collect();
    for i in 0..parts.len().saturating_sub(1) {
        let domain = parts[i..].join(".");
        // "to *.yahoo.com" -> ^(|.*\.)yahoo\.com$
        let data = format!("^(|.*\\.){}$", regex_escape(&domain));
        out.push(target(
            Field::RegexHost,
            format!("to *.{domain}"),
            regexp_op(operand::DEST_HOST, data),
        ));
    }
    out
}

/// `to 1.*`, `to 1.2.*`, `to 1.2.3.*` for an IPv4 destination.
fn ip_regexp_targets(con: &Connection) -> Vec<Target> {
    let parts: Vec<&str> = con.dst_ip.split('.').collect();
    (1..parts.len())
        .map(|i| {
            let prefix = parts[..i].join(".");
            // "to 1.2.*" -> 1\.2\..*
            let data = format!("{}.*", regex_escape(&format!("{prefix}.")));
            target(
                Field::RegexIp,
                format!("to {prefix}.*"),
                regexp_op(operand::DEST_IP, data),
            )
        })
        .collect()
}

/// The AppImage pattern for `/tmp/.mount_<6 chars><suffix>/.../<bin>`.
///
/// Anyone can create such a directory, so the pattern is only offered when the
/// mount name has the shape AppImage creates, and every part of it is escaped.
/// The pattern then matches that program's mounts and nothing broader.
fn appimage_target(con: &Connection) -> Option<Target> {
    let rest = con.process_path.strip_prefix(APPIMAGE_PREFIX)?;
    let (mount, inner) = rest.split_once('/')?;
    // 6 characters of the app's name, then a random alphanumeric suffix.
    let split = mount.char_indices().nth(6).map(|(i, _)| i)?;
    let (head, tail) = mount.split_at(split);
    let bin = inner.rsplit('/').next().filter(|b| !b.is_empty())?;
    let head_ok = head
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !head_ok || !tail.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let data = format!(
        "^{}{}[0-9A-Za-z]+/(.*/)?{}$",
        regex_escape(APPIMAGE_PREFIX),
        regex_escape(head),
        regex_escape(bin)
    );
    Some(target(
        Field::AppImage,
        format!("from {APPIMAGE_PREFIX}{head}*/{bin}"),
        regexp_op(operand::PROCESS_PATH, data),
    ))
}

/// The snap pattern for `/snap/<name>/<revision>/...`, with the revision as a wildcard.
///
/// Only offered for a valid snap name and a numeric revision; every part is escaped.
fn snap_target(con: &Connection) -> Option<Target> {
    let rest = con.process_path.strip_prefix("/snap/")?;
    let mut parts = rest.split('/');
    let (app, revision) = (parts.next()?, parts.next()?);
    let inner: Vec<&str> = parts.collect();
    let app_ok = !app.is_empty()
        && app
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_'));
    let revision_ok = !revision.is_empty() && revision.chars().all(|c| c.is_ascii_digit());
    if !app_ok || !revision_ok || inner.is_empty() || inner.iter().any(|c| c.is_empty()) {
        return None;
    }
    let escaped: Vec<String> = inner.iter().map(|c| regex_escape(c)).collect();
    let data = format!("^/snap/{}/[0-9]+/{}$", regex_escape(app), escaped.join("/"));
    Some(target(
        Field::Snap,
        format!("from /snap/{app}/*/{}", inner.join("/")),
        regexp_op(operand::PROCESS_PATH, data),
    ))
}

/// Entries of the main "apply to" combo.
pub fn what_targets(con: &Connection) -> Vec<Target> {
    let mut out = fixed_targets(con);
    out.extend(appimage_target(con));
    out.extend(snap_target(con));
    out.extend(network_targets(con));
    out.extend(host_targets(con));
    out.extend(ip_regexp_targets(con));
    out
}

/// Entries of the "destination IP" combo shown in the advanced view.
pub fn ip_targets(con: &Connection) -> Vec<Target> {
    let mut out = host_targets(con);
    out.push(target(
        Field::DstIp,
        format!("to {}", con.dst_ip),
        Op::simple(operand::DEST_IP, &con.dst_ip),
    ));
    out.extend(ip_regexp_targets(con));
    out.extend(network_targets(con));
    out
}

/// Index of the entry to preselect, following the Qt UI's `set_default_target`.
pub fn default_target_index(targets: &[Target], con: &Connection, saved: usize) -> usize {
    let find = |field: Field| targets.iter().position(|t| t.field == field);
    // These patterns are only in the list when the path has the expected shape.
    if let Some(idx) = find(Field::AppImage).or_else(|| find(Field::Snap)) {
        return idx;
    }
    let known_pid = con.process_id > 0 && con.process_id != UNKNOWN;
    let has_name = !con.process_path.is_empty();
    let has_args = con.process_args.iter().any(|a| !a.is_empty());
    match saved {
        5 if known_pid => 5,
        2..=4 => saved,
        _ if known_pid && has_name && has_args => saved,
        _ if known_pid && has_name => 0,
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn con() -> Connection {
        Connection {
            protocol: "tcp".into(),
            dst_ip: "93.184.216.34".into(),
            dst_host: "www.example.co.uk".into(),
            dst_port: 443,
            user_id: 1000,
            process_id: 4242,
            process_path: "/usr/bin/curl".into(),
            process_args: vec!["curl".into(), "https://example.com".into()],
            ..Default::default()
        }
    }

    fn labels(t: &[Target]) -> Vec<&str> {
        t.iter().map(|t| t.label.as_str()).collect()
    }

    #[test]
    fn main_combo_order_matches_qt() {
        let t = what_targets(&con());
        assert_eq!(
            labels(&t),
            [
                "from this executable",
                "from this command line",
                "to port 443",
                "to 93.184.216.34",
                "from user 1000",
                "from this PID",
                "to 93.184.216.0/24",
                "to 93.184.0.0/16",
                "to 93.0.0.0/8",
                "www.example.co.uk",
                "to *.example.co.uk",
                "to *.co.uk",
                "to 93.*",
                "to 93.184.*",
                "to 93.184.216.*",
            ]
        );
    }

    #[test]
    fn host_regexp_operator() {
        let t = what_targets(&con());
        let op = &t
            .iter()
            .find(|t| t.label == "to *.example.co.uk")
            .unwrap()
            .op;
        assert_eq!((op.kind, op.operand), (kind::REGEXP, operand::DEST_HOST));
        assert_eq!(op.data, r"^(|.*\.)example\.co\.uk$");
    }

    #[test]
    fn ip_regexp_and_network_operators() {
        let t = what_targets(&con());
        let re = &t.iter().find(|t| t.label == "to 93.184.*").unwrap().op;
        assert_eq!(re.data, r"93\.184\..*");
        let net = &t.iter().find(|t| t.label == "to 93.184.0.0/16").unwrap().op;
        assert_eq!(
            (net.kind, net.data.as_str()),
            (kind::NETWORK, "93.184.0.0/16")
        );
    }

    #[test]
    fn lan_ip_gets_alias_and_ipv6_networks() {
        let mut c = con();
        c.dst_ip = "192.168.1.20".into();
        assert!(labels(&what_targets(&c)).contains(&"to LAN"));
        assert_eq!(network_alias("224.0.0.251"), Some("MULTICAST"));
        assert_eq!(network_alias("::1"), Some("LAN"));
        assert_eq!(network_alias("8.8.8.8"), None);
        c.dst_ip = "2001:db8::1".into();
        let t = what_targets(&c);
        assert!(labels(&t).contains(&"to 2001:db8::/64"));
        assert!(labels(&t).contains(&"to 2001:db8::1/128"));
    }

    #[test]
    fn appimage_and_snap_patterns() {
        let mut c = con();
        c.process_path = "/tmp/.mount_fooAbC1/usr/bin/foo".into();
        let t = what_targets(&c);
        let idx = default_target_index(&t, &c, 0);
        assert_eq!(t[idx].field, Field::AppImage);
        assert_eq!(t[idx].label, "from /tmp/.mount_fooAbC*/foo");
        assert_eq!(
            t[idx].op.data,
            r"^/tmp/\.mount_fooAbC[0-9A-Za-z]+/(.*/)?foo$"
        );

        c.process_path = "/snap/firefox/123/usr/lib/firefox".into();
        let t = what_targets(&c);
        let idx = default_target_index(&t, &c, 0);
        assert_eq!(t[idx].label, "from /snap/firefox/*/usr/lib/firefox");
        assert_eq!(t[idx].op.data, r"^/snap/firefox/[0-9]+/usr/lib/firefox$");
    }

    /// What is left of a regexp once every escaped character is removed, to look
    /// for operators (like `|`) that would change what it matches.
    fn unescaped(regexp: &str) -> String {
        let mut out = String::new();
        let mut chars = regexp.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                chars.next();
            } else {
                out.push(ch);
            }
        }
        out
    }

    fn target_of(targets: &[Target], field: Field) -> Option<&Target> {
        targets.iter().find(|t| t.field == field)
    }

    #[test]
    fn regex_escape_escapes_every_metacharacter() {
        for ch in "\\.+*?()|[]{}^$".chars() {
            assert_eq!(regex_escape(&ch.to_string()), format!("\\{ch}"));
        }
        assert_eq!(
            regex_escape("plain-text_1/\u{e9} x"),
            "plain-text_1/\u{e9} x"
        );
    }

    /// The attack that motivated escaping. A program named `x|.*` in a directory
    /// that looks like an AppImage mount used to give a rule ending in `|.*$`,
    /// which matches every path, and AppImage is the default selection.
    #[test]
    fn hostile_appimage_name_cannot_widen_the_rule() {
        let mut c = con();
        c.process_path = "/tmp/.mount_abcdef1/usr/bin/x|.*".into();
        let t = what_targets(&c);
        let appimage = target_of(&t, Field::AppImage).expect("the pattern is offered");
        assert_eq!(
            appimage.op.data,
            r"^/tmp/\.mount_abcdef[0-9A-Za-z]+/(.*/)?x\|\.\*$"
        );
        assert!(
            !unescaped(&appimage.op.data).contains('|'),
            "no alternation"
        );
        assert!(!unescaped(&appimage.op.data).contains("x.*"), "no wildcard");
    }

    #[test]
    fn appimage_pattern_needs_the_shape_appimage_creates() {
        let offered = |path: &str| {
            let mut c = con();
            c.process_path = path.into();
            target_of(&what_targets(&c), Field::AppImage).is_some()
        };
        assert!(offered("/tmp/.mount_abcdef1/usr/bin/x"));
        assert!(offered("/tmp/.mount_Cur-or1A2b3c/x"));
        assert!(
            !offered("/tmp/.mount_ab|.*f1/usr/bin/x"),
            "regexp in the name"
        );
        assert!(!offered("/tmp/.mount_abc(de1/bin/x"), "parenthesis");
        assert!(
            !offered("/tmp/.mount_Joplin-xAbcde/bin/x"),
            "suffix not alphanumeric"
        );
        assert!(!offered("/tmp/.mount_abcdef/bin/x"), "no random suffix");
        assert!(!offered("/tmp/.mount_abcdef1/"), "no program");
        assert!(!offered("/tmp/.mount_abcdef1"), "no inner path");
    }

    #[test]
    fn hostile_mount_name_defaults_to_the_executable() {
        let mut c = con();
        c.process_path = "/tmp/.mount_a|.*bcd1/usr/bin/x".into();
        let t = what_targets(&c);
        assert!(target_of(&t, Field::AppImage).is_none());
        let idx = default_target_index(&t, &c, 0);
        assert_eq!(t[idx].field, Field::ProcPath);
    }

    #[test]
    fn snap_pattern_needs_a_valid_name_and_revision() {
        let offered = |path: &str| {
            let mut c = con();
            c.process_path = path.into();
            target_of(&what_targets(&c), Field::Snap).is_some()
        };
        assert!(offered("/snap/firefox/4793/usr/lib/firefox/firefox"));
        assert!(!offered("/snap/ab|c/1/usr/bin/x"), "regexp in the name");
        assert!(
            !offered("/snap/firefox/current/usr/bin/x"),
            "revision not a number"
        );
        assert!(!offered("/snap/firefox/12"), "no program");
        assert!(
            !offered("/snapx/firefox/12/bin/x"),
            "not the /snap directory"
        );
        assert!(!offered("/snap/firefox/12//x"), "empty path component");
    }

    #[test]
    fn snap_program_names_are_escaped() {
        let mut c = con();
        c.process_path = "/snap/app/12/bin/a|b".into();
        let t = what_targets(&c);
        let snap = target_of(&t, Field::Snap).expect("offered");
        assert_eq!(snap.op.data, r"^/snap/app/[0-9]+/bin/a\|b$");
    }

    /// Host names come from DNS answers. This one has a space and regexp
    /// syntax. The rule used to be built from the last word of the label, which
    /// here is only a fragment of the name.
    #[test]
    fn hostile_host_name_is_escaped_in_the_wildcard_rule() {
        let mut c = con();
        c.dst_host = "www.a b.c|d".into();
        let t = what_targets(&c);
        let wildcard = target_of(&t, Field::RegexHost).expect("offered");
        assert_eq!(wildcard.label, "to *.a b.c|d");
        assert_eq!(wildcard.op.data, r"^(|.*\.)a b\.c\|d$");
        let exact = target_of(&t, Field::DstHost).expect("offered");
        assert_eq!(
            exact.op.data, "www.a b.c|d",
            "the exact rule keeps the raw name"
        );
    }

    #[test]
    fn labels_drop_control_characters_but_operators_keep_the_exact_text() {
        let mut c = con();
        c.dst_host = "a\nb.example.com".into();
        let t = what_targets(&c);
        let host = target_of(&t, Field::DstHost).expect("offered");
        assert!(!host.label.contains('\n'));
        assert_eq!(host.op.data, "a\nb.example.com");
    }

    #[test]
    fn command_line_falls_back_to_path_when_empty() {
        let mut c = con();
        c.process_args.clear();
        let t = what_targets(&c);
        assert_eq!(t[1].op.operand, operand::PROCESS_PATH);
    }

    #[test]
    fn default_target_rules() {
        let c = con();
        let t = what_targets(&c);
        assert_eq!(default_target_index(&t, &c, 1), 1);
        assert_eq!(default_target_index(&t, &c, 3), 3);
        let mut unknown = con();
        unknown.process_path.clear();
        unknown.process_id = 0;
        assert_eq!(default_target_index(&t, &unknown, 0), 2);
    }

    #[test]
    fn ip_combo_starts_with_host_entries() {
        let t = ip_targets(&con());
        assert_eq!(t[0].label, "www.example.co.uk");
        assert!(labels(&t).contains(&"to 93.184.216.34"));
    }
}
