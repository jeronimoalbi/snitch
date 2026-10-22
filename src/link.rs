//! State shared with the daemon connection: the rules the daemon has loaded,
//! whether it is intercepting connections, and the notification stream used to
//! change them.
//!
//! The daemon sends every loaded rule in `Subscribe`. Its rule files are only
//! readable by root, so this copy is how the dialog learns about saved rules.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};
use tonic::Status;

use crate::checksum;
use crate::proto::{Action, Notification, NotificationReply, NotificationReplyCode, Rule};

/// How long to wait for the daemon to confirm a rule change.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

type Outbox = mpsc::Sender<Result<Notification, Status>>;
type Verdict = Result<(), String>;

/// Which rules an update changed, and why it stopped early (if it did).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Rules the daemon confirmed.
    pub updated: Vec<String>,
    /// The failure that ended the update; the remaining rules were not tried.
    pub error: Option<String>,
}

/// Whether the daemon intercepts connections.
///
/// The daemon never reports this, so it is what this UI last asked for and the
/// daemon confirmed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Interception {
    /// The daemon is not connected, so nothing is known.
    #[default]
    Unknown,
    On,
    Off,
}

impl Interception {
    /// The name used on the D-Bus interface.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

/// What this UI knows about the daemon.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DaemonState {
    /// The daemon holds its notification stream open.
    pub connected: bool,
    pub interception: Interception,
}

/// Rules known to the daemon and the channel to send it notifications.
pub struct Link {
    rules: Mutex<HashMap<String, Rule>>,
    stream: Mutex<Option<Outbox>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Verdict>>>,
    next_id: AtomicU64,
    status: watch::Sender<DaemonState>,
    /// A file that exists while interception is paused, so a restart of this
    /// program turns it back on instead of forgetting it.
    pause_marker: OnceLock<PathBuf>,
}

impl Default for Link {
    fn default() -> Self {
        Self {
            rules: Mutex::default(),
            stream: Mutex::default(),
            pending: Mutex::default(),
            next_id: AtomicU64::default(),
            status: watch::channel(DaemonState::default()).0,
            pause_marker: OnceLock::new(),
        }
    }
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

    /// Remembers a pause in `path`, which should live somewhere cleared at
    /// logout, such as the runtime directory. Only the first call counts.
    pub fn keep_pause_in(&self, path: PathBuf) {
        let _ = self.pause_marker.set(path);
    }

    /// What is known about the daemon right now.
    pub fn status(&self) -> DaemonState {
        *self.status.borrow()
    }

    /// Receives every change of [`DaemonState`].
    pub fn watch(&self) -> watch::Receiver<DaemonState> {
        self.status.subscribe()
    }

    /// True when a pause was recorded and not undone.
    fn paused_before(&self) -> bool {
        self.pause_marker.get().is_some_and(|path| path.exists())
    }

    fn record_pause(&self, paused: bool) {
        let Some(path) = self.pause_marker.get() else {
            return;
        };
        let done = if paused {
            std::fs::write(path, b"")
        } else {
            std::fs::remove_file(path).or_else(|err| match err.kind() {
                std::io::ErrorKind::NotFound => Ok(()),
                _ => Err(err),
            })
        };
        if let Err(err) = done {
            tracing::warn!("cannot update {}: {err}", path.display());
        }
    }

    /// Starts using `outbox` as the daemon's notification stream.
    ///
    /// A daemon that connects is taken to intercept, because only a UI can
    /// turn that off, unless this program paused it before (see
    /// [`Link::resume_if_paused`]).
    pub fn attach(&self, outbox: Outbox) {
        *lock(&self.stream) = Some(outbox);
        let paused = self.status().interception == Interception::Off || self.paused_before();
        self.status.send_modify(|status| {
            status.connected = true;
            status.interception = if paused {
                Interception::Off
            } else {
                Interception::On
            };
        });
    }

    /// Stops using `outbox`, unless a newer stream has replaced it.
    pub fn detach(&self, outbox: &Outbox) {
        let mut stream = lock(&self.stream);
        if stream.as_ref().is_some_and(|s| s.same_channel(outbox)) {
            *stream = None;
            self.status.send_replace(DaemonState::default());
        }
    }

    /// Turns interception back on when it was paused before the daemon
    /// (re)connected. A restart of this program or of the daemon must never
    /// leave the firewall silently off.
    pub async fn resume_if_paused(&self) {
        if self.status().interception != Interception::Off {
            return;
        }
        match self.set_interception(true).await {
            Ok(()) => tracing::info!("interception was paused; turned it back on"),
            Err(err) => tracing::warn!("cannot turn interception back on: {err}"),
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

    /// Sends the notification `build` makes for a fresh id and waits for the
    /// daemon's answer.
    async fn request(&self, build: impl FnOnce(u64) -> Notification) -> Verdict {
        let outbox = lock(&self.stream)
            .clone()
            .ok_or("the daemon is not connected")?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (waiter, answer) = oneshot::channel();
        lock(&self.pending).insert(id, waiter);

        if outbox.try_send(Ok(build(id))).is_err() {
            lock(&self.pending).remove(&id);
            return Err("cannot reach the daemon".into());
        }
        let verdict = match tokio::time::timeout(REPLY_TIMEOUT, answer).await {
            Ok(Ok(verdict)) => verdict,
            Ok(Err(_)) => Err("the daemon disconnected".into()),
            Err(_) => Err("the daemon did not answer".into()),
        };
        lock(&self.pending).remove(&id);
        verdict
    }

    /// Asks the daemon to replace `rule` and waits for its answer.
    async fn change_rule(&self, rule: Rule) -> Verdict {
        let verdict = self
            .request(|id| Notification {
                id,
                r#type: Action::ChangeRule as i32,
                rules: vec![rule.clone()],
                ..Default::default()
            })
            .await;
        if verdict.is_ok() {
            self.remember(&rule);
        }
        verdict
    }

    /// Asks the daemon to start or stop intercepting connections. The state
    /// changes only when the daemon confirms.
    pub async fn set_interception(&self, on: bool) -> Verdict {
        let action = if on {
            Action::EnableInterception
        } else {
            Action::DisableInterception
        };
        self.request(|id| Notification {
            id,
            r#type: action as i32,
            ..Default::default()
        })
        .await?;
        self.record_pause(!on);
        self.status.send_modify(|status| {
            status.interception = if on {
                Interception::On
            } else {
                Interception::Off
            };
        });
        Ok(())
    }

    /// Pins `md5` in the named rules. Stops at the first failure.
    async fn update_checksums(&self, names: &[String], md5: &str) -> Outcome {
        let mut outcome = Outcome::default();
        for name in names {
            let Some(rule) = lock(&self.rules).get(name).cloned() else {
                outcome.error = Some(format!("rule not found by name ({name})"));
                break;
            };
            match self.change_rule(checksum::with_checksum(&rule, md5)).await {
                Ok(()) => {
                    tracing::info!("pinned the new checksum in rule {name}");
                    outcome.updated.push(name.clone());
                }
                Err(err) => {
                    tracing::warn!("rule {name} not updated: {err}");
                    outcome.error = Some(format!("rule not updated ({name}): {err}"));
                    break;
                }
            }
        }
        outcome
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
        Self::on(link, tokio::runtime::Handle::current())
    }

    /// Runs the work on `runtime`.
    pub fn on(link: std::sync::Arc<Link>, runtime: tokio::runtime::Handle) -> Self {
        Self { link, runtime }
    }

    /// What is known about the daemon right now.
    pub fn status(&self) -> DaemonState {
        self.link.status()
    }

    /// Receives every change of [`DaemonState`].
    pub fn watch(&self) -> watch::Receiver<DaemonState> {
        self.link.watch()
    }

    /// Starts or stops interception.
    pub async fn set_interception(&self, on: bool) -> Result<(), String> {
        let link = self.link.clone();
        let task = self
            .runtime
            .spawn(async move { link.set_interception(on).await });
        task.await.unwrap_or_else(|err| Err(err.to_string()))
    }

    /// Pins `md5` in the rules called `names`.
    pub async fn update_checksums(&self, names: Vec<String>, md5: String) -> Outcome {
        let link = self.link.clone();
        let task = self
            .runtime
            .spawn(async move { link.update_checksums(&names, &md5).await });
        task.await.unwrap_or_else(|err| Outcome {
            updated: Vec::new(),
            error: Some(err.to_string()),
        })
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
        let outcome = link.update_checksums(&names, "new").await;
        assert_eq!(outcome.error, None);
        assert_eq!(outcome.updated, ["a", "b"]);

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

        let outcome = link.update_checksums(&["a".to_string()], "new").await;
        let err = outcome.error.unwrap();
        assert!(err.contains("boom"), "{err}");
        assert!(outcome.updated.is_empty());
        assert_eq!(
            link.rules()[0].operator.as_ref().unwrap().list[1].data,
            "old"
        );
    }

    #[tokio::test]
    async fn a_failure_keeps_the_rules_updated_before_it() {
        let link = Arc::new(Link::default());
        link.replace_rules(vec![rule("a", "old"), rule("c", "old")]);
        let _seen = daemon(&link, NotificationReplyCode::Ok);
        let names = vec!["a".to_string(), "missing".to_string(), "c".to_string()];
        let outcome = link.update_checksums(&names, "new").await;
        assert_eq!(outcome.updated, ["a"]);
        assert!(outcome.error.unwrap().contains("missing"));
    }

    #[tokio::test]
    async fn fails_cleanly_without_daemon_or_rule() {
        let link = Arc::new(Link::default());
        link.replace_rules(vec![rule("a", "old")]);
        let err = link
            .update_checksums(&["a".to_string()], "new")
            .await
            .error
            .unwrap();
        assert!(err.contains("not connected"), "{err}");
        let err = link
            .update_checksums(&["zzz".to_string()], "new")
            .await
            .error
            .unwrap();
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

    /// A fresh path in the temporary directory for one test.
    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("snitch-test-{}-{name}", std::process::id()))
    }

    #[tokio::test]
    async fn interception_changes_only_when_the_daemon_confirms() {
        let link = Arc::new(Link::default());
        let (outbox, _inbox) = mpsc::channel(8);
        link.attach(outbox);
        assert_eq!(link.status().interception, Interception::On);

        let mut seen = daemon(&link, NotificationReplyCode::Error);
        let err = link.set_interception(false).await.unwrap_err();
        assert!(err.contains("boom"), "{err}");
        assert_eq!(link.status().interception, Interception::On);
        let sent = seen.recv().await.unwrap();
        assert_eq!(sent.r#type, Action::DisableInterception as i32);

        let mut seen = daemon(&link, NotificationReplyCode::Ok);
        link.set_interception(false).await.unwrap();
        assert_eq!(link.status().interception, Interception::Off);
        link.set_interception(true).await.unwrap();
        assert_eq!(link.status().interception, Interception::On);
        assert_eq!(
            seen.recv().await.unwrap().r#type,
            Action::DisableInterception as i32
        );
        assert_eq!(
            seen.recv().await.unwrap().r#type,
            Action::EnableInterception as i32
        );
    }

    #[tokio::test]
    async fn status_follows_the_connection() {
        let link = Arc::new(Link::default());
        let mut changes = link.watch();
        assert_eq!(link.status(), DaemonState::default());

        let (outbox, _inbox) = mpsc::channel(1);
        link.attach(outbox.clone());
        changes.changed().await.unwrap();
        assert_eq!(
            *changes.borrow_and_update(),
            DaemonState {
                connected: true,
                interception: Interception::On
            }
        );
        link.detach(&outbox);
        assert_eq!(link.status(), DaemonState::default());
    }

    #[tokio::test]
    async fn a_pause_survives_a_restart_and_is_undone_on_connect() {
        let marker = scratch("pause");
        let _ = std::fs::remove_file(&marker);

        let link = Arc::new(Link::default());
        link.keep_pause_in(marker.clone());
        let (outbox, _inbox) = mpsc::channel(8);
        link.attach(outbox);
        let _seen = daemon(&link, NotificationReplyCode::Ok);
        link.set_interception(false).await.unwrap();
        assert!(marker.exists());

        // A new process: nothing in memory, but the marker is still there.
        let restarted = Arc::new(Link::default());
        restarted.keep_pause_in(marker.clone());
        let (outbox, _inbox) = mpsc::channel(8);
        restarted.attach(outbox);
        assert_eq!(restarted.status().interception, Interception::Off);
        let mut seen = daemon(&restarted, NotificationReplyCode::Ok);
        restarted.resume_if_paused().await;
        assert_eq!(restarted.status().interception, Interception::On);
        assert_eq!(
            seen.recv().await.unwrap().r#type,
            Action::EnableInterception as i32
        );
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn nothing_is_sent_when_interception_was_never_paused() {
        let link = Arc::new(Link::default());
        let (outbox, mut inbox) = mpsc::channel(8);
        link.attach(outbox);
        link.resume_if_paused().await;
        assert!(inbox.try_recv().is_err());
        assert_eq!(link.status().interception, Interception::On);
    }
}
