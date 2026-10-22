//! Building the daemon `Rule` from the user's choices, ported from
//! `PromptDialog._send_rule` in the Qt UI.

use crate::model::{self, Field, Op, Target, kind, operand};
use crate::proto::{Connection, Operator, Rule};
use crate::settings::Settings;

/// Duration combo entries: `(label, value sent to the daemon)`.
pub const DURATIONS: [(&str, &str); 9] = [
    ("once", "once"),
    ("30s", "30s"),
    ("5m", "5m"),
    ("15m", "15m"),
    ("30m", "30m"),
    ("1h", "1h"),
    ("12h", "12h"),
    ("until reboot", "until restart"),
    ("forever", "always"),
];

/// Seconds a time-limited duration (`30s`, `5m`, `1h`...) lasts.
pub fn duration_secs(duration: &str) -> Option<i64> {
    let (number, unit) = [("s", 1), ("m", 60), ("h", 3600)]
        .into_iter()
        .find_map(|(suffix, unit)| duration.strip_suffix(suffix).map(|n| (n, unit)))?;
    number.parse::<i64>().ok()?.checked_mul(unit)
}

/// True when a time-limited rule has run out.
pub fn is_expired(rule: &Rule, now: i64) -> bool {
    duration_secs(&rule.duration).is_some_and(|secs| rule.created.saturating_add(secs) <= now)
}

/// What to do with the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Drop,
    Allow,
    Reject,
}

impl Action {
    /// Maps the settings index (0 drop, 1 allow, 2 reject).
    pub fn from_index(idx: usize) -> Self {
        match idx {
            1 => Self::Allow,
            2 => Self::Reject,
            _ => Self::Drop,
        }
    }

    /// Action string the daemon expects (drop is sent as `deny`).
    pub fn as_rule_action(self) -> &'static str {
        match self {
            Self::Drop => "deny",
            Self::Allow => "allow",
            Self::Reject => "reject",
        }
    }

    /// Button label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Drop => "Drop",
            Self::Allow => "Allow",
            Self::Reject => "Reject",
        }
    }
}

/// Everything the user selected in the dialog.
#[derive(Debug, Clone, Copy)]
pub struct Choice<'a> {
    pub action: Action,
    pub duration_idx: usize,
    /// Selected entry of the main "apply to" combo.
    pub target: &'a Target,
    /// Selected entry of the advanced "destination IP" combo.
    pub ip_target: &'a Target,
    pub check_ip: bool,
    pub check_port: bool,
    pub check_uid: bool,
    pub check_sum: bool,
    /// MD5 of the process, empty when unknown.
    pub checksum: &'a str,
}

/// Lowercase, ASCII-only, dash-separated form of `text` (like python-slugify).
pub fn slugify(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

fn to_operator(op: &Op) -> Operator {
    Operator {
        r#type: op.kind.to_string(),
        operand: op.operand.to_string(),
        data: op.data.clone(),
        sensitive: false,
        list: Vec::new(),
    }
}

/// Maximum rule name length, so `<name>.json` stays a valid file name.
const MAX_NAME: usize = 200;

/// Builds the rule for `choice`; `None` when the main operator has no data.
pub fn build_rule(con: &Connection, choice: &Choice, created: i64) -> Option<Rule> {
    let main = &choice.target.op;
    if main.data.is_empty() {
        return None;
    }
    let duration = DURATIONS.get(choice.duration_idx).map_or("always", |d| d.1);
    let action = choice.action.as_rule_action();
    let is_list_checked =
        choice.check_uid || choice.check_port || choice.check_ip || choice.check_sum;

    let shape = if is_list_checked { "list" } else { "simple" };
    let mut name = slugify(&format!(
        "{} {shape} {}",
        slugify(&format!("{action} {duration}")),
        main.data
    ));
    name.truncate(128);

    let mut extra: Vec<Op> = Vec::new();
    let append = |name: &mut String, part: &str| *name = slugify(&format!("{name} {part}"));

    let mut alias_selected = false;
    if choice.target.field == Field::DstNetwork && model::network_alias(&con.dst_ip).is_some() {
        extra.push(Op {
            kind: kind::SIMPLE,
            operand: operand::PROCESS_PATH,
            data: con.process_path.clone(),
        });
        let base = con.process_path.rsplit('/').next().unwrap_or_default();
        append(&mut name, base);
        alias_selected = true;
    }
    if choice.check_ip && choice.target.field != Field::DstIp {
        extra.push(choice.ip_target.op.clone());
        append(&mut name, &choice.ip_target.op.data);
    }
    if choice.check_port && choice.target.field != Field::DstPort {
        extra.push(Op {
            kind: kind::SIMPLE,
            operand: operand::DEST_PORT,
            data: con.dst_port.to_string(),
        });
        append(&mut name, &con.dst_port.to_string());
    }
    if choice.check_uid && choice.target.field != Field::UserId {
        extra.push(Op {
            kind: kind::SIMPLE,
            operand: operand::USER_ID,
            data: con.user_id.to_string(),
        });
        append(&mut name, &con.user_id.to_string());
    }
    if choice.check_sum && !choice.checksum.is_empty() {
        extra.push(Op {
            kind: kind::SIMPLE,
            operand: operand::PROCESS_HASH_MD5,
            data: choice.checksum.to_string(),
        });
        append(&mut name, operand::PROCESS_HASH_MD5);
    }

    let mut is_list = is_list_checked;
    // A relative or /proc command line can't be trusted: also match the binary path.
    if main.operand == operand::PROCESS_COMMAND {
        let first = model::command_line(con)
            .split(' ')
            .next()
            .unwrap_or_default()
            .to_string();
        if !first.starts_with('/') || first.starts_with("/proc") {
            is_list = true;
            extra.push(Op {
                kind: kind::SIMPLE,
                operand: operand::PROCESS_PATH,
                data: con.process_path.clone(),
            });
        }
    }

    let operator = if is_list || alias_selected {
        extra.push(main.clone());
        Operator {
            r#type: kind::LIST.to_string(),
            operand: kind::LIST.to_string(),
            data: String::new(),
            sensitive: false,
            list: extra.iter().map(to_operator).collect(),
        }
    } else {
        to_operator(main)
    };

    name.truncate(MAX_NAME);
    Some(Rule {
        created,
        name,
        enabled: true,
        action: action.to_string(),
        duration: duration.to_string(),
        operator: Some(operator),
        ..Default::default()
    })
}

/// Gives `rule` a name no known rule uses, like the Qt UI: `-0` to `-99` is
/// appended while the name is taken. A rule identical to the one holding the
/// name keeps it, since the daemon then just replaces it with the same content.
/// Expired rules don't hold their name any more.
pub fn make_name_unique(rule: &mut Rule, known: &[Rule], now: i64) {
    let holder = |name: &str| known.iter().find(|r| r.name == name && !is_expired(r, now));
    match holder(&rule.name) {
        None => return,
        Some(r)
            if (&r.action, &r.duration, &r.operator)
                == (&rule.action, &rule.duration, &rule.operator) =>
        {
            return;
        }
        Some(_) => {}
    }
    let free = (0..100)
        .map(|i| format!("{}-{i}", rule.name))
        .find(|name| holder(name).is_none());
    if let Some(name) = free {
        rule.name = name;
    }
}

/// The rule the dialog would send untouched: the saved default action, duration
/// (or `duration_idx`) and target, with the saved advanced checkboxes.
///
/// Used when popups are disabled, on timeouts and when no dialog can be shown.
pub fn default_rule(
    con: &Connection,
    settings: &Settings,
    duration_idx: Option<usize>,
    created: i64,
) -> Option<Rule> {
    let what = model::what_targets(con);
    let ip = model::ip_targets(con);
    let mut idx = model::default_target_index(&what, con, settings.default_target);
    if !what.get(idx)?.enabled {
        idx = what.iter().position(|t| t.field == Field::DstPort)?;
    }
    let choice = Choice {
        action: Action::from_index(settings.default_action),
        duration_idx: duration_idx.unwrap_or(settings.default_duration),
        target: what.get(idx)?,
        ip_target: ip.first()?,
        check_ip: settings.advanced_dstip,
        check_port: settings.advanced_dstport,
        check_uid: settings.advanced_uid,
        check_sum: settings.advanced_checksum,
        checksum: crate::view::md5(con),
    };
    build_rule(con, &choice, created)
}

/// JSON in the format the daemon stores rules in.
pub fn to_json(rule: &Rule) -> serde_json::Value {
    fn op(o: &Operator) -> serde_json::Value {
        serde_json::json!({
            "type": o.r#type,
            "operand": o.operand,
            "sensitive": o.sensitive,
            "data": o.data,
            "list": o.list.iter().map(op).collect::<Vec<_>>(),
        })
    }
    serde_json::json!({
        "created": rule.created,
        "name": rule.name,
        "description": rule.description,
        "enabled": rule.enabled,
        "precedence": rule.precedence,
        "nolog": rule.nolog,
        "action": rule.action,
        "duration": rule.duration,
        "operator": rule.operator.as_ref().map(op),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn con() -> Connection {
        Connection {
            protocol: "tcp".into(),
            dst_ip: "93.184.216.34".into(),
            dst_host: "example.com".into(),
            dst_port: 443,
            user_id: 1000,
            process_id: 7,
            process_path: "/usr/bin/curl".into(),
            process_args: vec!["/usr/bin/curl".into(), "x".into()],
            ..Default::default()
        }
    }

    fn choice<'a>(targets: &'a [Target], idx: usize) -> Choice<'a> {
        Choice {
            action: Action::Allow,
            duration_idx: 8,
            target: &targets[idx],
            ip_target: &targets[3],
            check_ip: false,
            check_port: false,
            check_uid: false,
            check_sum: false,
            checksum: "",
        }
    }

    #[test]
    fn slugify_matches_python_slugify() {
        assert_eq!(
            slugify("allow always simple /usr/bin/curl"),
            "allow-always-simple-usr-bin-curl"
        );
        assert_eq!(slugify("  --Hi  there!! "), "hi-there");
    }

    #[test]
    fn simple_rule() {
        let c = con();
        let t = model::what_targets(&c);
        let rule = build_rule(&c, &choice(&t, 0), 1).unwrap();
        assert_eq!(rule.name, "allow-always-simple-usr-bin-curl");
        assert_eq!(
            (rule.action.as_str(), rule.duration.as_str()),
            ("allow", "always")
        );
        let op = rule.operator.unwrap();
        assert_eq!(
            (op.r#type.as_str(), op.operand.as_str(), op.data.as_str()),
            ("simple", "process.path", "/usr/bin/curl")
        );
        assert!(rule.enabled);
    }

    #[test]
    fn list_rule_from_checkboxes() {
        let c = con();
        let t = model::what_targets(&c);
        let mut ch = choice(&t, 0);
        ch.check_port = true;
        ch.check_uid = true;
        ch.check_sum = true;
        ch.checksum = "abc";
        let rule = build_rule(&c, &ch, 1).unwrap();
        assert_eq!(
            rule.name,
            "allow-always-list-usr-bin-curl-443-1000-process-hash-md5"
        );
        let op = rule.operator.unwrap();
        assert_eq!(op.r#type, "list");
        let operands: Vec<&str> = op.list.iter().map(|o| o.operand.as_str()).collect();
        assert_eq!(
            operands,
            ["dest.port", "user.id", "process.hash.md5", "process.path"]
        );
    }

    #[test]
    fn checkbox_skipped_when_it_is_the_main_target() {
        let c = con();
        let t = model::what_targets(&c);
        let mut ch = choice(&t, 2);
        ch.check_port = true;
        let op = build_rule(&c, &ch, 1).unwrap().operator.unwrap();
        assert_eq!(op.r#type, "list");
        assert_eq!(op.list.len(), 1);
    }

    #[test]
    fn relative_command_adds_path() {
        let mut c = con();
        c.process_args = vec!["curl".into(), "x".into()];
        let t = model::what_targets(&c);
        let op = build_rule(&c, &choice(&t, 1), 1).unwrap().operator.unwrap();
        assert_eq!(op.r#type, "list");
        let operands: Vec<&str> = op.list.iter().map(|o| o.operand.as_str()).collect();
        assert_eq!(operands, ["process.path", "process.command"]);
    }

    #[test]
    fn network_alias_adds_process_path() {
        let mut c = con();
        c.dst_ip = "192.168.0.5".into();
        let t = model::what_targets(&c);
        let idx = t.iter().position(|t| t.label == "to LAN").unwrap();
        let rule = build_rule(&c, &choice(&t, idx), 1).unwrap();
        assert!(rule.name.ends_with("-curl"));
        let op = rule.operator.unwrap();
        assert_eq!(op.list.len(), 2);
        assert_eq!(op.list[1].operand, "dest.network");
    }

    #[test]
    fn empty_operator_data_discards_rule() {
        let mut c = con();
        c.process_path.clear();
        let t = model::what_targets(&c);
        assert!(build_rule(&c, &choice(&t, 0), 1).is_none());
    }

    fn named(name: &str, action: &str) -> Rule {
        Rule {
            name: name.into(),
            action: action.into(),
            duration: "always".into(),
            operator: Some(Operator {
                r#type: "simple".into(),
                operand: "process.path".into(),
                data: "/usr/bin/curl".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn free_names_are_kept() {
        let mut rule = named("allow-always-simple-curl", "allow");
        make_name_unique(&mut rule, &[named("other", "allow")], 100);
        assert_eq!(rule.name, "allow-always-simple-curl");
    }

    #[test]
    fn identical_rule_keeps_its_name() {
        let mut rule = named("a", "allow");
        make_name_unique(&mut rule, &[named("a", "allow")], 100);
        assert_eq!(rule.name, "a");
    }

    #[test]
    fn taken_names_get_the_first_free_suffix() {
        let known = [
            named("a", "deny"),
            named("a-0", "deny"),
            named("a-1", "deny"),
        ];
        let mut rule = named("a", "allow");
        make_name_unique(&mut rule, &known, 100);
        assert_eq!(rule.name, "a-2");
    }

    #[test]
    fn expired_rules_release_their_name() {
        let mut old = named("a", "deny");
        old.duration = "5m".into();
        old.created = 0;
        let mut rule = named("a", "allow");
        make_name_unique(&mut rule, &[old], 1_000);
        assert_eq!(rule.name, "a");
    }

    #[test]
    fn gives_up_after_one_hundred_suffixes() {
        let mut known = vec![named("a", "deny")];
        known.extend((0..100).map(|i| named(&format!("a-{i}"), "deny")));
        let mut rule = named("a", "allow");
        make_name_unique(&mut rule, &known, 100);
        assert_eq!(rule.name, "a");
    }

    #[test]
    fn parses_durations() {
        assert_eq!(duration_secs("30s"), Some(30));
        assert_eq!(duration_secs("5m"), Some(300));
        assert_eq!(duration_secs("12h"), Some(43_200));
        assert_eq!(duration_secs("5\u{e9}"), None);
        assert_eq!(duration_secs("until restart"), None);
        assert_eq!(duration_secs("always"), None);
        assert_eq!(duration_secs(""), None);
    }

    #[test]
    fn drop_is_sent_as_deny() {
        assert_eq!(Action::from_index(0).as_rule_action(), "deny");
        assert_eq!(Action::from_index(2).as_rule_action(), "reject");
    }
}
