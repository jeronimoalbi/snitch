//! Detecting programs whose MD5 no longer matches the one pinned in a rule,
//! ported from the Qt UI (`dialogs/prompt/checksums.py`).
//!
//! Only list rules can pin a checksum: they hold the program path plus a
//! `process.hash.md5` condition.

use crate::model::{kind, operand};
use crate::proto::{Connection, Operator, Rule};

/// Rules whose pinned checksum differs from the running program's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mismatch {
    /// Names of the rules that can be updated.
    pub rule_names: Vec<String>,
    /// Checksums those rules expect (the running program has a different one).
    pub expected: Vec<String>,
}

impl Mismatch {
    /// True when at least one rule disagrees with the running program.
    pub fn is_empty(&self) -> bool {
        self.rule_names.is_empty()
    }
}

/// True for rules that can still apply: enabled, not one-shot, not expired.
fn is_active(rule: &Rule, now: i64) -> bool {
    if !rule.enabled || rule.duration == "once" {
        return false;
    }
    !crate::rule::is_expired(rule, now)
}

fn conditions(rule: &Rule) -> &[Operator] {
    rule.operator
        .as_ref()
        .filter(|op| op.r#type == kind::LIST)
        .map_or(&[], |op| op.list.as_slice())
}

/// The checksum a list rule pins, if any.
fn pinned_checksum(rule: &Rule) -> Option<&str> {
    conditions(rule)
        .iter()
        .find(|op| op.r#type == kind::SIMPLE && op.operand == operand::PROCESS_HASH_MD5)
        .map(|op| op.data.as_str())
}

/// True when the rule matches the program at `path`.
fn matches_path(rule: &Rule, path: &str) -> bool {
    conditions(rule)
        .iter()
        .any(|op| op.operand == operand::PROCESS_PATH && op.data == path)
}

/// Finds the active rules for the connection's program that pin another checksum.
///
/// A missing checksum on the connection (the daemon couldn't compute it, or
/// `Rules.EnableChecksums` is off) never counts as a mismatch.
pub fn find<'a>(rules: impl IntoIterator<Item = &'a Rule>, con: &Connection, now: i64) -> Mismatch {
    let current = crate::view::md5(con);
    let mut out = Mismatch::default();
    if current.is_empty() || con.process_path.is_empty() {
        return out;
    }
    let mut candidates: Vec<&Rule> = rules
        .into_iter()
        .filter(|r| is_active(r, now) && matches_path(r, &con.process_path))
        .collect();
    candidates.sort_by(|a, b| a.name.cmp(&b.name));
    for rule in candidates {
        if let Some(expected) = pinned_checksum(rule).filter(|e| *e != current) {
            out.rule_names.push(rule.name.clone());
            out.expected.push(expected.to_string());
        }
    }
    out
}

/// Text of the checksums page: what the program has and what the rules expect.
pub fn note(con: &Connection, mismatch: &Mismatch) -> String {
    format!(
        "Checksums differ for at least one rule.\n\nCurrent process ({}):\n{}\n\nExpected from the rules:\n{}",
        con.process_id,
        crate::view::md5(con),
        mismatch.expected.join("\n"),
    )
}

/// Copy of `rule` with its pinned checksum replaced by `md5`.
pub fn with_checksum(rule: &Rule, md5: &str) -> Rule {
    let mut updated = rule.clone();
    if let Some(op) = updated.operator.as_mut() {
        for cond in op
            .list
            .iter_mut()
            .filter(|c| c.operand == operand::PROCESS_HASH_MD5)
        {
            cond.data = md5.to_string();
        }
    }
    updated
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "/usr/bin/curl";

    fn op(operand: &str, data: &str) -> Operator {
        Operator {
            r#type: "simple".into(),
            operand: operand.into(),
            data: data.into(),
            ..Default::default()
        }
    }

    fn rule(name: &str, md5: &str) -> Rule {
        Rule {
            name: name.into(),
            enabled: true,
            action: "allow".into(),
            duration: "always".into(),
            created: 1_000,
            operator: Some(Operator {
                r#type: "list".into(),
                operand: "list".into(),
                list: vec![op("process.path", PATH), op("process.hash.md5", md5)],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn con(md5: &str) -> Connection {
        let mut con = Connection {
            process_path: PATH.into(),
            ..Default::default()
        };
        if !md5.is_empty() {
            con.process_checksums
                .insert("process.hash.md5".into(), md5.into());
        }
        con
    }

    #[test]
    fn matching_checksum_is_fine() {
        assert!(find([&rule("a", "aaa")], &con("aaa"), 2_000).is_empty());
    }

    #[test]
    fn different_checksum_is_reported() {
        let rules = [rule("b", "old"), rule("a", "other"), rule("c", "new")];
        let found = find(&rules, &con("new"), 2_000);
        assert_eq!(found.rule_names, ["a", "b"]);
        assert_eq!(found.expected, ["other", "old"]);
    }

    #[test]
    fn missing_checksum_is_ignored() {
        assert!(find([&rule("a", "aaa")], &con(""), 2_000).is_empty());
    }

    #[test]
    fn inactive_rules_are_skipped() {
        let mut disabled = rule("a", "old");
        disabled.enabled = false;
        let mut once = rule("b", "old");
        once.duration = "once".into();
        let mut expired = rule("c", "old");
        expired.duration = "5m".into();
        let mut live = rule("d", "old");
        live.duration = "5m".into();
        live.created = 1_900;
        let rules = [disabled, once, expired, live];
        assert_eq!(find(&rules, &con("new"), 2_000).rule_names, ["d"]);
    }

    #[test]
    fn rules_for_other_programs_and_simple_rules_are_skipped() {
        let mut other = rule("a", "old");
        other.operator.as_mut().unwrap().list[0].data = "/usr/bin/wget".into();
        let mut simple = rule("b", "old");
        simple.operator = Some(op("process.path", PATH));
        assert!(find([&other, &simple], &con("new"), 2_000).is_empty());
    }

    #[test]
    fn update_replaces_only_the_checksum() {
        let updated = with_checksum(&rule("a", "old"), "new");
        let list = &updated.operator.unwrap().list;
        assert_eq!(list[0].data, PATH);
        assert_eq!(list[1].data, "new");
    }

    #[test]
    fn note_lists_current_and_expected() {
        let rules = [rule("a", "old1"), rule("b", "old2")];
        let mut c = con("new");
        c.process_id = 42;
        let text = note(&c, &find(&rules, &c, 2_000));
        assert!(text.contains("Current process (42):\nnew"));
        assert!(text.ends_with("old1\nold2"));
    }
}
