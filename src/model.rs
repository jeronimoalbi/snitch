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
const SNAP_PREFIX: &str = "/snap";

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

/// The operator for `field`, computed from the connection and the combo `label`.
fn operator_for(field: Field, label: &str, con: &Connection) -> Op {
    let last_word = || label.rsplit(' ').next().unwrap_or_default().to_string();
    match field {
        Field::ProcPath => Op::simple(operand::PROCESS_PATH, &con.process_path),
        Field::ProcArgs if con.process_args.first().is_none_or(String::is_empty) => {
            Op::simple(operand::PROCESS_PATH, &con.process_path)
        }
        Field::ProcArgs => Op::simple(operand::PROCESS_COMMAND, command_line(con)),
        Field::ProcId => Op::simple(operand::PROCESS_ID, con.process_id.to_string()),
        Field::UserId => Op::simple(operand::USER_ID, con.user_id.to_string()),
        Field::DstPort => Op::simple(operand::DEST_PORT, con.dst_port.to_string()),
        Field::DstIp => Op::simple(operand::DEST_IP, &con.dst_ip),
        Field::DstHost => Op::simple(operand::DEST_HOST, label),
        Field::DstNetwork => Op {
            kind: kind::NETWORK,
            operand: operand::DEST_NETWORK,
            data: last_word(),
        },
        Field::RegexHost => {
            // "to *.yahoo.com" -> ^(|.*\.)yahoo\.com$
            let domain = last_word().trim_start_matches("*.").replace('.', "\\.");
            Op {
                kind: kind::REGEXP,
                operand: operand::DEST_HOST,
                data: format!("^(|.*\\.){domain}$"),
            }
        }
        Field::RegexIp => {
            // "to 1.2.*" -> 1\.2\..*
            let data = last_word().replace('.', "\\.").replace('*', ".*");
            Op {
                kind: kind::REGEXP,
                operand: operand::DEST_IP,
                data,
            }
        }
        Field::AppImage => {
            let (dir, bin) = split_path(&con.process_path);
            let dir: String = dir
                .replace('.', "\\.")
                .chars()
                .take(APPIMAGE_PREFIX.len() + 1 + 6)
                .collect();
            Op {
                kind: kind::REGEXP,
                operand: operand::PROCESS_PATH,
                data: format!("^{dir}[0-9A-Za-z]+\\/.*{bin}$"),
            }
        }
        Field::Snap => {
            let parts: Vec<&str> = con.process_path.split('/').collect();
            let app = parts.get(2).copied().unwrap_or_default();
            let rest = parts.get(4..).unwrap_or_default().join("\\/");
            let prefix = parts.get(1).copied().unwrap_or_default();
            Op {
                kind: kind::REGEXP,
                operand: operand::PROCESS_PATH,
                data: format!("^\\/{prefix}\\/{app}\\/[0-9]+\\/{rest}$"),
            }
        }
    }
}

/// Splits a path into `(directory, file name)` like Python's `dirname`/`basename`.
fn split_path(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn target(field: Field, label: String, con: &Connection) -> Target {
    let op = operator_for(field, &label, con);
    Target::new(label, field, op)
}

/// The six fixed entries, in the order the Qt preferences use for the default target.
fn fixed_targets(con: &Connection) -> Vec<Target> {
    let mut exe = target(Field::ProcPath, "from this executable".into(), con);
    exe.enabled = con.process_id != UNKNOWN;
    let mut uid = target(Field::UserId, format!("from user {}", con.user_id), con);
    uid.enabled = con.user_id != UNKNOWN;
    vec![
        exe,
        target(Field::ProcArgs, "from this command line".into(), con),
        target(Field::DstPort, format!("to port {}", con.dst_port), con),
        target(Field::DstIp, format!("to {}", con.dst_ip), con),
        uid,
        target(Field::ProcId, "from this PID".into(), con),
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
        out.push(target(Field::DstNetwork, format!("to {alias}"), con));
    }
    let prefixes: &[u32] = match con.dst_ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => &[24, 16, 8],
        Ok(IpAddr::V6(_)) => &[64, 128],
        Err(_) => &[],
    };
    for &prefix in prefixes {
        let net = match con.dst_ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => mask_v4(ip, prefix).to_string(),
            Ok(IpAddr::V6(ip)) => mask_v6(ip, prefix).to_string(),
            Err(_) => continue,
        };
        out.push(target(Field::DstNetwork, format!("to {net}/{prefix}"), con));
    }
    out
}

/// Host entry plus one wildcard entry per parent domain (down to two labels).
fn host_targets(con: &Connection) -> Vec<Target> {
    if con.dst_host.is_empty() || con.dst_host == con.dst_ip {
        return Vec::new();
    }
    let mut out = vec![target(Field::DstHost, con.dst_host.clone(), con)];
    let parts: Vec<&str> = con.dst_host.split('.').skip(1).collect();
    for i in 0..parts.len().saturating_sub(1) {
        out.push(target(
            Field::RegexHost,
            format!("to *.{}", parts[i..].join(".")),
            con,
        ));
    }
    out
}

/// `to 1.*`, `to 1.2.*`, `to 1.2.3.*` for an IPv4 destination.
fn ip_regexp_targets(con: &Connection) -> Vec<Target> {
    let parts: Vec<&str> = con.dst_ip.split('.').collect();
    (1..parts.len())
        .map(|i| {
            target(
                Field::RegexIp,
                format!("to {}.*", parts[..i].join(".")),
                con,
            )
        })
        .collect()
}

/// Entries of the main "apply to" combo.
pub fn what_targets(con: &Connection) -> Vec<Target> {
    let mut out = fixed_targets(con);
    if con.process_path.starts_with(APPIMAGE_PREFIX) {
        let (dir, bin) = split_path(&con.process_path);
        let dir: String = dir.chars().take(APPIMAGE_PREFIX.len() + 6).collect();
        out.push(target(Field::AppImage, format!("from {dir}*/{bin}"), con));
    } else if con.process_path.starts_with(SNAP_PREFIX) {
        let parts: Vec<&str> = con.process_path.split('/').collect();
        if parts.len() > 4 {
            let label = format!("from {SNAP_PREFIX}/{}/*/{}", parts[2], parts[4..].join("/"));
            out.push(target(Field::Snap, label, con));
        }
    }
    out.extend(network_targets(con));
    out.extend(host_targets(con));
    out.extend(ip_regexp_targets(con));
    out
}

/// Entries of the "destination IP" combo shown in the advanced view.
pub fn ip_targets(con: &Connection) -> Vec<Target> {
    let mut out = host_targets(con);
    out.push(target(Field::DstIp, format!("to {}", con.dst_ip), con));
    out.extend(ip_regexp_targets(con));
    out.extend(network_targets(con));
    out
}

/// Index of the entry to preselect, following the Qt UI's `set_default_target`.
pub fn default_target_index(targets: &[Target], con: &Connection, saved: usize) -> usize {
    let find = |field: Field| targets.iter().position(|t| t.field == field);
    let packaged = if con.process_path.starts_with(APPIMAGE_PREFIX) {
        find(Field::AppImage)
    } else if con.process_path.starts_with(SNAP_PREFIX) {
        find(Field::Snap)
    } else {
        None
    };
    if let Some(idx) = packaged {
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
        assert_eq!(t[idx].op.data, r"^/tmp/\.mount_fooAbC[0-9A-Za-z]+\/.*foo$");

        c.process_path = "/snap/firefox/123/usr/lib/firefox".into();
        let t = what_targets(&c);
        let idx = default_target_index(&t, &c, 0);
        assert_eq!(t[idx].label, "from /snap/firefox/*/usr/lib/firefox");
        assert_eq!(
            t[idx].op.data,
            r"^\/snap\/firefox\/[0-9]+\/usr\/lib\/firefox$"
        );
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
