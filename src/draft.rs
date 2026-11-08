//! What the rule editor holds, and how it becomes a daemon `Rule`. Kept free of
//! GTK so the checks can be unit tested.
//!
//! The daemon saves a rule as `<rules dir>/<name>.json` as root and replaces
//! any rule with the same name, so names are checked here before it sees them.

use crate::model::{kind, operand};
use crate::proto::{Operator, Rule};
use crate::rule::{self, MAX_NAME};

/// A `(label, value sent to the daemon)` pair of a dropdown.
pub type Choice = (&'static str, &'static str);

/// Rule actions the editor offers.
pub const ACTIONS: [Choice; 3] = [("Allow", "allow"), ("Drop", "deny"), ("Reject", "reject")];

/// What a condition can look at.
pub const OPERANDS: [Choice; 15] = [
    ("Executable path", operand::PROCESS_PATH),
    ("Command line", operand::PROCESS_COMMAND),
    ("Process ID", operand::PROCESS_ID),
    ("Program MD5", operand::PROCESS_HASH_MD5),
    ("User ID", operand::USER_ID),
    ("User name", operand::USER_NAME),
    ("Destination host", operand::DEST_HOST),
    ("Destination IP", operand::DEST_IP),
    ("Destination port", operand::DEST_PORT),
    ("Destination network", operand::DEST_NETWORK),
    ("Source IP", operand::SOURCE_IP),
    ("Source port", operand::SOURCE_PORT),
    ("Protocol", operand::PROTOCOL),
    ("Outgoing interface", operand::IFACE_OUT),
    ("Incoming interface", operand::IFACE_IN),
];

/// How a condition compares its value.
pub const MATCH_KINDS: [Choice; 3] = [
    ("is", kind::SIMPLE),
    ("matches regexp", kind::REGEXP),
    ("in network", kind::NETWORK),
];

/// Conditions whose value the daemon compares with a number.
const NUMERIC: [&str; 4] = [
    operand::DEST_PORT,
    operand::SOURCE_PORT,
    operand::PROCESS_ID,
    operand::USER_ID,
];

const ONCE: &str = "once";

/// Durations a saved rule can have. The daemon would keep a `once` rule sent
/// to it as a change, so that one is left out.
pub fn durations() -> Vec<Choice> {
    rule::DURATIONS
        .into_iter()
        .filter(|(_, value)| *value != ONCE)
        .collect()
}

/// The entries of a dropdown showing `current`. A value the table lacks, such
/// as one written by hand in a rule file, is added so saving doesn't lose it.
pub fn choices(table: &[Choice], current: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = table
        .iter()
        .map(|(label, value)| ((*label).to_string(), (*value).to_string()))
        .collect();
    if !current.is_empty() && !table.iter().any(|(_, value)| *value == current) {
        out.push((current.to_string(), current.to_string()));
    }
    out
}

/// The label of `value` in `table`, or `value` when the table lacks it.
pub fn label_of<'a>(table: &[Choice], value: &'a str) -> &'a str {
    table
        .iter()
        .find(|(_, candidate)| *candidate == value)
        .map_or(value, |(label, _)| *label)
}

/// The match type a condition must switch to once `operand` is selected, if
/// `current` can't be used with it.
pub fn forced_kind(operand: &str, current: &str) -> Option<&'static str> {
    match (operand == operand::DEST_NETWORK, current == kind::NETWORK) {
        (true, false) => Some(kind::NETWORK),
        (false, true) => Some(kind::SIMPLE),
        _ => None,
    }
}

/// The rules to show: those that haven't run out, by name.
pub fn listed(mut rules: Vec<Rule>, now: i64) -> Vec<Rule> {
    rules.retain(|r| !rule::is_expired(r, now));
    rules.sort_by(|a, b| a.name.cmp(&b.name));
    rules
}

/// One thing a rule checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    pub operand: String,
    pub kind: String,
    pub data: String,
    /// Case-sensitive comparison; the form keeps it but doesn't show it.
    pub sensitive: bool,
}

impl Default for Condition {
    fn default() -> Self {
        Self {
            operand: operand::PROCESS_PATH.to_string(),
            kind: kind::SIMPLE.to_string(),
            data: String::new(),
            sensitive: false,
        }
    }
}

impl Condition {
    fn from_operator(op: &Operator) -> Self {
        Self {
            operand: op.operand.clone(),
            kind: op.r#type.clone(),
            data: op.data.clone(),
            sensitive: op.sensitive,
        }
    }

    /// The operator for this condition, when its value makes sense.
    fn to_operator(&self) -> Result<Operator, String> {
        let shown = label_of(&OPERANDS, &self.operand);
        if self.data.trim().is_empty() {
            return Err(format!("{shown}: enter a value"));
        }
        if (self.operand == operand::DEST_NETWORK) != (self.kind == kind::NETWORK) {
            return Err(format!(
                "{shown}: \"in network\" only works with Destination network, and is the only match it allows"
            ));
        }
        let needs_number = self.kind == kind::SIMPLE && NUMERIC.contains(&self.operand.as_str());
        if needs_number && self.data.parse::<u32>().is_err() {
            return Err(format!("{shown}: enter a number"));
        }
        Ok(Operator {
            r#type: self.kind.clone(),
            operand: self.operand.clone(),
            data: self.data.clone(),
            sensitive: self.sensitive,
            list: Vec::new(),
        })
    }
}

/// The contents of the editor form.
#[derive(Debug, Clone)]
pub struct Draft {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub precedence: bool,
    pub nolog: bool,
    pub action: String,
    pub duration: String,
    pub conditions: Vec<Condition>,
    /// The rule being edited; `None` when adding one.
    pub original: Option<Rule>,
}

impl Default for Draft {
    /// A blank new rule, which drops until the user chooses otherwise.
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            enabled: true,
            precedence: false,
            nolog: false,
            action: "deny".to_string(),
            duration: "always".to_string(),
            conditions: vec![Condition::default()],
            original: None,
        }
    }
}

/// `Ok` when `name` is safe to use as a file name in the daemon's directory.
fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Give the rule a name".to_string());
    }
    if name.contains('/') || name.chars().any(char::is_control) {
        return Err("The name can't hold a / or control characters".to_string());
    }
    if name.starts_with('.') {
        return Err("The name can't start with a dot".to_string());
    }
    if name.len() > MAX_NAME {
        return Err(format!("The name is longer than {MAX_NAME} bytes"));
    }
    Ok(())
}

impl Draft {
    /// The form for editing `rule`.
    pub fn from_rule(rule: &Rule) -> Self {
        let conditions = match &rule.operator {
            Some(op) if op.r#type == kind::LIST => {
                op.list.iter().map(Condition::from_operator).collect()
            }
            Some(op) => vec![Condition::from_operator(op)],
            None => Vec::new(),
        };
        Self {
            name: rule.name.clone(),
            description: rule.description.clone(),
            enabled: rule.enabled,
            precedence: rule.precedence,
            nolog: rule.nolog,
            action: rule.action.clone(),
            duration: rule.duration.clone(),
            conditions,
            original: Some(rule.clone()),
        }
    }

    /// True when another live rule is called `name`. Saving under it would
    /// silently replace that rule.
    fn name_taken(&self, name: &str, known: &[Rule], now: i64) -> bool {
        self.original.as_ref().is_none_or(|r| r.name != name)
            && known
                .iter()
                .any(|r| r.name == name && !rule::is_expired(r, now))
    }

    /// The operator of the rule: the only condition, or a list of them.
    fn operator(&self) -> Result<Operator, String> {
        let mut operators = self
            .conditions
            .iter()
            .map(Condition::to_operator)
            .collect::<Result<Vec<_>, _>>()?;
        if operators.len() > 1 {
            return Ok(Operator {
                r#type: kind::LIST.to_string(),
                operand: kind::LIST.to_string(),
                list: operators,
                ..Default::default()
            });
        }
        operators
            .pop()
            .ok_or_else(|| "Add at least one condition".to_string())
    }

    /// When the rule's time limit started.
    ///
    /// The daemon's timer for a temporary rule keeps running across an edit
    /// and removes the rule if its name and duration are still the same, so
    /// only a new name or duration starts the clock again.
    fn created(&self, name: &str, now: i64) -> i64 {
        self.original
            .as_ref()
            .filter(|r| r.name == name && r.duration == self.duration)
            .map_or(now, |r| r.created)
    }

    /// The rule to send to the daemon, or what the user has to fix.
    pub fn to_rule(&self, known: &[Rule], now: i64) -> Result<Rule, String> {
        let name = self.name.trim();
        check_name(name)?;
        if self.name_taken(name, known, now) {
            return Err(format!("There is already a rule called {name}"));
        }
        if self.duration == ONCE {
            return Err("A saved rule can't last for one connection only".to_string());
        }
        Ok(Rule {
            created: self.created(name, now),
            name: name.to_string(),
            description: self.description.clone(),
            enabled: self.enabled,
            precedence: self.precedence,
            nolog: self.nolog,
            action: self.action.clone(),
            duration: self.duration.clone(),
            operator: Some(self.operator()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(kind: &str, operand: &str, data: &str) -> Operator {
        Operator {
            r#type: kind.into(),
            operand: operand.into(),
            data: data.into(),
            ..Default::default()
        }
    }

    fn saved(name: &str) -> Rule {
        Rule {
            name: name.into(),
            created: 10,
            enabled: true,
            action: "allow".into(),
            duration: "always".into(),
            operator: Some(op("simple", "process.path", "/usr/bin/curl")),
            ..Default::default()
        }
    }

    fn new_rule(name: &str) -> Draft {
        let mut draft = Draft {
            name: name.into(),
            ..Default::default()
        };
        draft.conditions[0].data = "/usr/bin/curl".into();
        draft
    }

    #[test]
    fn an_unchanged_simple_rule_comes_back_the_same() {
        let rule = saved("a");
        assert_eq!(
            Draft::from_rule(&rule).to_rule(std::slice::from_ref(&rule), 99),
            Ok(rule)
        );
    }

    #[test]
    fn an_unchanged_list_rule_comes_back_the_same() {
        let mut rule = saved("a");
        let mut sensitive = op("regexp", "dest.host", "^a$");
        sensitive.sensitive = true;
        rule.operator = Some(Operator {
            r#type: "list".into(),
            operand: "list".into(),
            list: vec![op("simple", "process.path", "/x"), sensitive],
            ..Default::default()
        });
        assert_eq!(
            Draft::from_rule(&rule).to_rule(std::slice::from_ref(&rule), 99),
            Ok(rule)
        );
    }

    #[test]
    fn what_the_form_does_not_know_survives() {
        let mut rule = saved("a");
        rule.description = "note".into();
        rule.precedence = true;
        rule.nolog = true;
        rule.duration = "2h".into();
        rule.operator = Some(op("lists", "lists.domains", "/etc/lists"));
        assert_eq!(
            Draft::from_rule(&rule).to_rule(std::slice::from_ref(&rule), 99),
            Ok(rule)
        );
    }

    #[test]
    fn dropdowns_gain_values_they_do_not_list() {
        let known = choices(&ACTIONS, "deny");
        assert_eq!(known.len(), 3);
        let extra = choices(&ACTIONS, "weird");
        assert_eq!(extra.last().unwrap(), &("weird".into(), "weird".into()));
        assert_eq!(choices(&ACTIONS, "").len(), 3);
    }

    #[test]
    fn once_is_not_offered_and_not_accepted() {
        assert!(durations().iter().all(|(_, value)| *value != "once"));
        let mut draft = new_rule("a");
        draft.duration = "once".into();
        assert!(draft.to_rule(&[], 1).is_err());
    }

    #[test]
    fn names_that_are_unsafe_as_files_are_refused() {
        for name in [
            "",
            "  ",
            "../x",
            "a/b",
            "/etc/passwd",
            ".hidden",
            "..",
            "a\nb",
            "a\0b",
        ] {
            assert!(new_rule(name).to_rule(&[], 1).is_err(), "{name:?}");
        }
        assert!(new_rule(&"x".repeat(MAX_NAME + 1)).to_rule(&[], 1).is_err());
        assert!(new_rule(&"x".repeat(MAX_NAME)).to_rule(&[], 1).is_ok());
    }

    #[test]
    fn names_are_trimmed() {
        assert_eq!(new_rule("  a b ").to_rule(&[], 1).unwrap().name, "a b");
    }

    #[test]
    fn adding_onto_a_live_name_is_refused() {
        let err = new_rule("a").to_rule(&[saved("a")], 1).unwrap_err();
        assert!(err.contains("already"), "{err}");
    }

    #[test]
    fn renaming_onto_a_live_name_is_refused() {
        let known = [saved("a"), saved("b")];
        let mut draft = Draft::from_rule(&known[0]);
        draft.name = "b".into();
        assert!(draft.to_rule(&known, 1).is_err());
        draft.name = "c".into();
        assert_eq!(draft.to_rule(&known, 1).unwrap().name, "c");
    }

    #[test]
    fn an_expired_rule_does_not_hold_its_name() {
        let mut old = saved("a");
        old.duration = "5m".into();
        old.created = 0;
        assert!(new_rule("a").to_rule(&[old], 1_000).is_ok());
    }

    #[test]
    fn the_clock_restarts_only_with_a_new_name_or_duration() {
        let mut rule = saved("a");
        rule.duration = "5m".into();
        let mut draft = Draft::from_rule(&rule);
        draft.action = "deny".into();
        assert_eq!(draft.to_rule(&[], 99).unwrap().created, 10);
        draft.duration = "1h".into();
        assert_eq!(draft.to_rule(&[], 99).unwrap().created, 99);
        draft.duration = "5m".into();
        draft.name = "b".into();
        assert_eq!(draft.to_rule(&[], 99).unwrap().created, 99);
        assert_eq!(new_rule("n").to_rule(&[], 99).unwrap().created, 99);
    }

    #[test]
    fn the_operator_shape_follows_the_number_of_conditions() {
        let mut draft = new_rule("a");
        let one = draft.to_rule(&[], 1).unwrap().operator.unwrap();
        assert_eq!(one.r#type, "simple");
        assert!(one.list.is_empty());

        draft.conditions.push(Condition {
            operand: "dest.port".into(),
            data: "443".into(),
            ..Default::default()
        });
        let two = draft.to_rule(&[], 1).unwrap().operator.unwrap();
        assert_eq!(
            (two.r#type.as_str(), two.operand.as_str()),
            ("list", "list")
        );
        assert_eq!(two.list.len(), 2);

        draft.conditions.clear();
        assert!(draft.to_rule(&[], 1).is_err());
    }

    fn with_condition(operand: &str, kind: &str, data: &str) -> Result<Rule, String> {
        let mut draft = new_rule("a");
        draft.conditions = vec![Condition {
            operand: operand.into(),
            kind: kind.into(),
            data: data.into(),
            sensitive: false,
        }];
        draft.to_rule(&[], 1)
    }

    #[test]
    fn condition_values_are_checked() {
        assert!(with_condition("process.path", "simple", " ").is_err());
        assert!(with_condition("dest.port", "simple", "https").is_err());
        assert!(with_condition("dest.port", "simple", "443").is_ok());
        assert!(with_condition("dest.port", "regexp", "44.*").is_ok());
        assert!(with_condition("user.id", "simple", "-1").is_err());
    }

    #[test]
    fn network_matching_goes_with_the_destination_network_only() {
        assert!(with_condition("dest.network", "network", "10.0.0.0/8").is_ok());
        assert!(with_condition("dest.network", "simple", "10.0.0.0/8").is_err());
        assert!(with_condition("dest.ip", "network", "10.0.0.0/8").is_err());
        assert!(with_condition("source.network", "network", "10.0.0.0/8").is_err());
    }

    #[test]
    fn selecting_an_operand_fixes_an_impossible_match_type() {
        assert_eq!(forced_kind("dest.network", "simple"), Some("network"));
        assert_eq!(forced_kind("dest.ip", "network"), Some("simple"));
        assert_eq!(forced_kind("dest.network", "network"), None);
        assert_eq!(forced_kind("dest.ip", "regexp"), None);
    }

    #[test]
    fn the_list_is_sorted_and_leaves_out_expired_rules() {
        let mut expired = saved("b");
        expired.duration = "5m".into();
        expired.created = 0;
        let names: Vec<String> = listed(vec![saved("c"), expired, saved("a")], 1_000)
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert_eq!(names, ["a", "c"]);
    }

    #[test]
    fn labels_fall_back_to_the_value() {
        assert_eq!(label_of(&ACTIONS, "deny"), "Drop");
        assert_eq!(label_of(&ACTIONS, "weird"), "weird");
    }
}
