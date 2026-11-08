//! Fake connections for `snitch --demo`, to preview the dialog without a daemon,
//! and fake rules for `snitch --demo-rules`, to preview the rules window.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::checksum::Mismatch;
use crate::link::Link;
use crate::model::{kind, operand};
use crate::proto::{
    Connection, Notification, NotificationReply, NotificationReplyCode, Operator, Rule, StringInt,
};

/// Names accepted by `--demo-scenario`.
pub const SCENARIOS: &[&str] = &[
    "curl",
    "appimage",
    "snap",
    "dns",
    "lan",
    "icmp",
    "unknown",
    "badchecksum",
];

fn tree(entries: &[(&str, u32)]) -> Vec<StringInt> {
    entries
        .iter()
        .map(|(key, value)| StringInt {
            key: (*key).to_string(),
            value: *value,
        })
        .collect()
}

fn base() -> Connection {
    let uid = std::env::var("UID")
        .ok()
        .and_then(|u| u.parse().ok())
        .unwrap_or(1000);
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "/".into());
    Connection {
        protocol: "tcp".into(),
        src_ip: "192.168.1.23".into(),
        src_port: 48122,
        dst_ip: "93.184.216.34".into(),
        dst_host: "www.example.com".into(),
        dst_port: 443,
        user_id: uid,
        process_id: 4242,
        process_cwd: cwd,
        process_checksums: [(
            "process.hash.md5".to_string(),
            "9e107d9d372bb6826bd81d3542a419d6".to_string(),
        )]
        .into(),
        process_env: [
            ("HOME".to_string(), "/home/user".to_string()),
            ("LANG".to_string(), "en_US.UTF-8".to_string()),
        ]
        .into(),
        ..Default::default()
    }
}

/// The connection for scenario `name`, or `None` if it doesn't exist.
pub fn scenario(name: &str) -> Option<Connection> {
    let mut con = base();
    match name {
        "curl" => {
            con.process_path = "/usr/bin/curl".into();
            con.process_args = vec![
                "curl".into(),
                "-sS".into(),
                "https://www.example.com/index.html".into(),
            ];
            con.process_tree = tree(&[
                ("/usr/bin/curl", 4242),
                ("/usr/bin/zsh", 1337),
                ("/usr/lib/systemd/systemd", 1),
            ]);
        }
        "appimage" => {
            con.process_path = "/tmp/.mount_Cursor1A2b3c/usr/bin/cursor".into();
            con.process_args = vec![
                "/tmp/.mount_Cursor1A2b3c/usr/bin/cursor".into(),
                "--no-sandbox".into(),
            ];
            con.dst_host = "api.telemetry.example.org".into();
        }
        "snap" => {
            con.process_path = "/snap/firefox/4793/usr/lib/firefox/firefox".into();
            con.process_args = vec!["/snap/firefox/4793/usr/lib/firefox/firefox".into()];
            con.dst_host = "detectportal.firefox.com".into();
            con.dst_ip = "2.19.198.27".into();
        }
        "dns" => {
            con.process_path = "/usr/bin/dig".into();
            con.process_args = vec!["dig".into(), "www.example.com".into()];
            con.protocol = "udp".into();
            con.dst_ip = "1.1.1.1".into();
            con.dst_port = 53;
        }
        "lan" => {
            con.process_path = "/usr/bin/ssh".into();
            con.process_args = vec!["ssh".into(), "nas.local".into()];
            con.dst_ip = "192.168.1.50".into();
            con.dst_host = "nas.local".into();
            con.dst_port = 22;
        }
        "icmp" => {
            con.process_path = "/usr/bin/ping".into();
            con.process_args = vec!["ping".into(), "1.1.1.1".into()];
            con.protocol = "icmp".into();
            con.dst_ip = "1.1.1.1".into();
            con.dst_host = String::new();
            con.dst_port = 0;
        }
        "badchecksum" => {
            con.process_path = "/usr/bin/curl".into();
            con.process_args = vec!["curl".into(), "https://www.example.com".into()];
        }
        "unknown" => {
            con.process_path = String::new();
            con.process_id = 0;
            con.process_checksums.clear();
            con.dst_host = String::new();
        }
        _ => return None,
    }
    Some(con)
}

/// The checksum mismatch to show for scenario `name`.
pub fn mismatch(name: &str) -> Mismatch {
    if name == "badchecksum" {
        Mismatch {
            rule_names: vec![
                "allow-always-list-usr-bin-curl-process-hash-md5".into(),
                "deny-always-list-usr-bin-curl-443-process-hash-md5".into(),
            ],
            expected: vec![
                "0123456789abcdef0123456789abcdef".into(),
                "fedcba9876543210fedcba9876543210".into(),
            ],
        }
    } else {
        Mismatch::default()
    }
}

fn condition(kind: &str, operand: &str, data: &str) -> Operator {
    Operator {
        r#type: kind.to_string(),
        operand: operand.to_string(),
        data: data.to_string(),
        ..Default::default()
    }
}

fn sample(name: &str, action: &str, duration: &str, operator: Operator, created: i64) -> Rule {
    Rule {
        created,
        name: name.to_string(),
        enabled: true,
        action: action.to_string(),
        duration: duration.to_string(),
        operator: Some(operator),
        ..Default::default()
    }
}

/// Rules for the demo window: one of each shape, a value the form doesn't
/// list, and a name that must not be taken for markup.
pub fn rules(now: i64) -> Vec<Rule> {
    let curl = condition(kind::SIMPLE, operand::PROCESS_PATH, "/usr/bin/curl");
    let mut list = condition(kind::LIST, kind::LIST, "");
    list.list = vec![
        curl.clone(),
        condition(kind::SIMPLE, operand::DEST_PORT, "443"),
    ];
    let host = condition(kind::REGEXP, operand::DEST_HOST, r"^(|.*\.)example\.com$");
    let lan = condition(kind::NETWORK, operand::DEST_NETWORK, "LAN");
    let range = condition("range", operand::DEST_PORT, "6000-6010");
    let mut off = sample("deny-always-example", "deny", "always", host, now);
    off.enabled = false;
    vec![
        sample("allow-always-simple-curl", "allow", "always", curl, now),
        sample("allow-always-list-curl-443", "allow", "always", list, now),
        off,
        sample("reject-5m-lan", "reject", "5m", lan, now),
        sample("hand-written-range", "allow", "until restart", range, now),
        sample(
            "<b>not-markup</b>",
            "allow",
            "always",
            condition(kind::SIMPLE, operand::PROCESS_PATH, "/tmp/<i>x&"),
            now,
        ),
    ]
}

/// Stands in for the daemon on `link`, accepting every change.
pub fn accept_everything(link: Arc<Link>, runtime: &tokio::runtime::Handle) {
    let (outbox, mut inbox) = mpsc::channel(8);
    link.attach(outbox);
    runtime.spawn(async move {
        while let Some(Ok(Notification { id, .. })) = inbox.recv().await {
            link.handle_reply(NotificationReply {
                id,
                code: NotificationReplyCode::Ok as i32,
                data: String::new(),
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_rules_have_unique_names() {
        let rules = rules(1);
        let names: std::collections::HashSet<&str> =
            rules.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names.len(), rules.len());
    }

    #[test]
    fn every_scenario_exists() {
        for name in SCENARIOS {
            assert!(scenario(name).is_some(), "{name}");
        }
        assert!(scenario("nope").is_none());
    }
}
