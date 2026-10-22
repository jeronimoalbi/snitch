//! State shared with the daemon connection: the rules the daemon has loaded,
//! and the notification stream used to change them.
//!
//! The daemon sends every loaded rule in `Subscribe`. Its rule files are only
//! readable by root, so this copy is how the dialog learns about saved rules.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tonic::Status;

use crate::checksum;
use crate::proto::{Action, Notification, NotificationReply, NotificationReplyCode, Rule};

/// How long to wait for the daemon to confirm a rule change.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

type Outbox = mpsc::Sender<Result<Notification, Status>>;
type Verdict = Result<(), String>;

/// Rules known to the daemon and the channel to send it notifications.
#[derive(Default)]
pub struct Link {
    rules: Mutex<HashMap<String, Rule>>,
    stream: Mutex<Option<Outbox>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Verdict>>>,
    next_id: AtomicU64,
}

/// Locks `mutex`, ignoring poisoning: the data is plain maps that stay valid.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Link {
    /// Replaces the known rules with the daemon's list (sent on `Subscribe`).
    pub fn replace_rules(&self, rules: Vec<Rule>) {
        let mut known = lock(&self.rules);
        known.clear();
        known.extend(rules.into_iter().map(|r| (r.name.clone(), r)));
    }

    /// Records a rule the daemon is about to keep.
    pub fn remember(&self, rule: &Rule) {
        if rule.duration != "once" {
            lock(&self.rules).insert(rule.name.clone(), rule.clone());
        }
    }

    /// Copy of the known rules.
    pub fn rules(&self) -> Vec<Rule> {
        lock(&self.rules).values().cloned().collect()
    }

    /// Starts using `outbox` as the daemon's notification stream.
    pub fn attach(&self, outbox: Outbox) {
        *lock(&self.stream) = Some(outbox);
    }

    /// Stops using `outbox`, unless a newer stream has replaced it.
    pub fn detach(&self, outbox: &Outbox) {
        let mut stream = lock(&self.stream);
        if stream.as_ref().is_some_and(|s| s.same_channel(outbox)) {
            *stream = None;
        }
    }

    /// Delivers the daemon's answer to whoever waits for it.
    pub fn handle_reply(&self, reply: NotificationReply) {
        let Some(waiter) = lock(&self.pending).remove(&reply.id) else {
            return;
        };
        let verdict = if reply.code == NotificationReplyCode::Error as i32 {
            Err(reply.data)
        } else {
            Ok(())
        };
        // The waiter may have timed out already.
        let _ = waiter.send(verdict);
    }

    /// Asks the daemon to replace `rule` and waits for its answer.
    async fn change_rule(&self, rule: Rule) -> Verdict {
        let outbox = lock(&self.stream)
            .clone()
            .ok_or("the daemon is not connected")?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (waiter, answer) = oneshot::channel();
        lock(&self.pending).insert(id, waiter);

        let notification = Notification {
            id,
            r#type: Action::ChangeRule as i32,
            rules: vec![rule.clone()],
            ..Default::default()
        };
        if outbox.try_send(Ok(notification)).is_err() {
            lock(&self.pending).remove(&id);
            return Err("cannot reach the daemon".into());
        }
        let verdict = match tokio::time::timeout(REPLY_TIMEOUT, answer).await {
            Ok(Ok(verdict)) => verdict,
            Ok(Err(_)) => Err("the daemon disconnected".into()),
            Err(_) => Err("the daemon did not answer".into()),
        };
        lock(&self.pending).remove(&id);
        if verdict.is_ok() {
            self.remember(&rule);
        }
        verdict
    }

    /// Pins `md5` in the named rules. Stops at the first failure.
    async fn update_checksums(&self, names: &[String], md5: &str) -> Verdict {
        for name in names {
            let rule = lock(&self.rules)
                .get(name)
                .cloned()
                .ok_or_else(|| format!("rule not found by name ({name})"))?;
            self.change_rule(checksum::with_checksum(&rule, md5))
                .await
                .map_err(|e| format!("rule not updated ({name}): {e}"))?;
        }
        Ok(())
    }
}

/// Lets the GTK thread change daemon rules; the work runs on the tokio runtime.
#[derive(Clone)]
pub struct Updater {
    link: std::sync::Arc<Link>,
    runtime: tokio::runtime::Handle,
}

impl Updater {
    /// Must be created from inside the tokio runtime.
    pub fn new(link: std::sync::Arc<Link>) -> Self {
        Self {
            link,
            runtime: tokio::runtime::Handle::current(),
        }
    }

    /// Pins `md5` in the rules called `names`.
    pub async fn update_checksums(&self, names: Vec<String>, md5: String) -> Result<(), String> {
        let link = self.link.clone();
        self.runtime
            .spawn(async move { link.update_checksums(&names, &md5).await })
            .await
            .map_err(|e| e.to_string())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Operator;
    use std::sync::Arc;

    fn rule(name: &str, md5: &str) -> Rule {
        let op = |operand: &str, data: &str| Operator {
            r#type: "simple".into(),
            operand: operand.into(),
            data: data.into(),
            ..Default::default()
        };
        Rule {
            name: name.into(),
            enabled: true,
            duration: "always".into(),
            operator: Some(Operator {
                r#type: "list".into(),
                operand: "list".into(),
                list: vec![
                    op("process.path", "/usr/bin/curl"),
                    op("process.hash.md5", md5),
                ],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// A fake daemon that answers every notification with `code`.
    fn daemon(link: &Arc<Link>, code: NotificationReplyCode) -> mpsc::Receiver<Notification> {
        let (outbox, mut inbox) = mpsc::channel(8);
        link.attach(outbox);
        let (seen_tx, seen) = mpsc::channel(8);
        let link = link.clone();
        tokio::spawn(async move {
            while let Some(Ok(n)) = inbox.recv().await {
                link.handle_reply(NotificationReply {
                    id: n.id,
                    code: code as i32,
                    data: "boom".into(),
                });
                let _ = seen_tx.send(n).await;
            }
        });
        seen
    }

    #[tokio::test]
    async fn updates_checksums_through_the_daemon() {
        let link = Arc::new(Link::default());
        link.replace_rules(vec![rule("a", "old"), rule("b", "old")]);
        let mut seen = daemon(&link, NotificationReplyCode::Ok);

        let names = vec!["a".to_string(), "b".to_string()];
        link.update_checksums(&names, "new").await.unwrap();

        let first = seen.recv().await.unwrap();
        assert_eq!(first.r#type, Action::ChangeRule as i32);
        assert_eq!(
            first.rules[0].operator.as_ref().unwrap().list[1].data,
            "new"
        );
        let stored = link.rules();
        assert!(
            stored
                .iter()
                .all(|r| r.operator.as_ref().unwrap().list[1].data == "new")
        );
    }

    #[tokio::test]
    async fn daemon_errors_are_reported_and_not_remembered() {
        let link = Arc::new(Link::default());
        link.replace_rules(vec![rule("a", "old")]);
        let _seen = daemon(&link, NotificationReplyCode::Error);

        let err = link
            .update_checksums(&["a".to_string()], "new")
            .await
            .unwrap_err();
        assert!(err.contains("boom"), "{err}");
        assert_eq!(
            link.rules()[0].operator.as_ref().unwrap().list[1].data,
            "old"
        );
    }

    #[tokio::test]
    async fn fails_cleanly_without_daemon_or_rule() {
        let link = Arc::new(Link::default());
        link.replace_rules(vec![rule("a", "old")]);
        let err = link
            .update_checksums(&["a".to_string()], "new")
            .await
            .unwrap_err();
        assert!(err.contains("not connected"), "{err}");
        let err = link
            .update_checksums(&["zzz".to_string()], "new")
            .await
            .unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }

    #[test]
    fn once_rules_are_not_remembered_and_detach_keeps_newer_stream() {
        let link = Link::default();
        let mut once = rule("o", "x");
        once.duration = "once".into();
        link.remember(&once);
        assert!(link.rules().is_empty());

        let (old, _old_rx) = mpsc::channel(1);
        let (new, _new_rx) = mpsc::channel(1);
        link.attach(old.clone());
        link.attach(new.clone());
        link.detach(&old);
        assert!(lock(&link.stream).is_some());
        link.detach(&new);
        assert!(lock(&link.stream).is_none());
    }
}
