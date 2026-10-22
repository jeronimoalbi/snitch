//! gRPC `UI` service the daemon connects to.
//!
//! The daemon calls `AskRule` for every unknown connection; the handler hands
//! the connection to the GTK thread and waits for the user's rule. Failures
//! never reach the daemon as gRPC errors: they become a one-shot rule with the
//! saved default action instead.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::Stream;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream, UnixListenerStream};
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use crate::checksum::{self, Mismatch};
use crate::link::{Link, Updater};
use crate::proto::ui_server::{Ui, UiServer};
use crate::proto::{
    Alert, ClientConfig, Connection, MsgResponse, Notification, NotificationReply, PingReply,
    PingRequest, Rule,
};
use crate::rule;
use crate::settings::Settings;

/// Error type used for startup failures.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The daemon gives up on `AskRule` after 120 s; answer a bit earlier.
const ASK_DEADLINE: Duration = Duration::from_secs(115);
/// Identical connections asked within this window reuse the previous answer.
const DEDUP_WINDOW: Duration = Duration::from_secs(2);

/// A connection waiting for the user's decision on the GTK thread.
pub struct PromptRequest {
    pub con: Connection,
    pub settings: Settings,
    /// Saved rules that pin a different checksum than the running program.
    pub mismatch: Mismatch,
    /// Changes daemon rules; `None` in demo mode, where there is no daemon.
    pub updater: Option<Updater>,
    /// Receives the rule; dropped by the server when the daemon stops waiting.
    pub reply: oneshot::Sender<Option<Rule>>,
}

type DedupKey = (u32, String, String, String, u32, String);

/// Implementation of the `UI` gRPC service.
pub struct Service {
    prompts: async_channel::Sender<PromptRequest>,
    settings_path: PathBuf,
    link: Arc<Link>,
    /// Only one dialog at a time.
    turn: tokio::sync::Mutex<()>,
    recent: Mutex<HashMap<DedupKey, (Instant, Rule)>>,
}

impl Service {
    /// Creates the service; prompts are sent through `prompts`.
    pub fn new(prompts: async_channel::Sender<PromptRequest>, settings_path: PathBuf) -> Self {
        Self {
            prompts,
            settings_path,
            link: Arc::new(Link::default()),
            turn: tokio::sync::Mutex::new(()),
            recent: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, key: &DedupKey) -> Option<Rule> {
        let recent = self.recent.lock().ok()?;
        recent
            .get(key)
            .filter(|(at, _)| at.elapsed() < DEDUP_WINDOW)
            .map(|(_, r)| r.clone())
    }

    fn remember(&self, key: DedupKey, rule: &Rule) {
        if let Ok(mut recent) = self.recent.lock() {
            recent.retain(|_, (at, _)| at.elapsed() < DEDUP_WINDOW);
            recent.insert(key, (Instant::now(), rule.clone()));
        }
    }

    /// Asks the GTK thread; `None` when no rule came back in time.
    async fn prompt(&self, con: &Connection, settings: &Settings) -> Option<Rule> {
        let (reply, answer) = oneshot::channel();
        let request = PromptRequest {
            con: con.clone(),
            settings: settings.clone(),
            mismatch: checksum::find(&self.link.rules(), con, now_secs()),
            updater: Some(Updater::new(self.link.clone())),
            reply,
        };
        self.prompts.send(request).await.ok()?;
        tokio::time::timeout(ASK_DEADLINE, answer)
            .await
            .ok()?
            .ok()?
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

fn dedup_key(con: &Connection) -> DedupKey {
    (
        con.user_id,
        con.process_path.clone(),
        con.dst_host.clone(),
        con.dst_ip.clone(),
        con.dst_port,
        con.protocol.clone(),
    )
}

type NotificationStream = Pin<Box<dyn Stream<Item = Result<Notification, Status>> + Send>>;

#[tonic::async_trait]
impl Ui for Service {
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        Ok(Response::new(PingReply {
            id: request.into_inner().id,
        }))
    }

    async fn ask_rule(&self, request: Request<Connection>) -> Result<Response<Rule>, Status> {
        let con = request.into_inner();
        let settings = Settings::load(&self.settings_path);
        let key = dedup_key(&con);
        if let Some(rule) = self.cached(&key) {
            return Ok(Response::new(rule));
        }

        let _turn = self.turn.lock().await;
        if let Some(rule) = self.cached(&key) {
            return Ok(Response::new(rule));
        }
        let answer = self.prompt(&con, &settings).await;
        let rule = match answer {
            Some(rule) => rule,
            None => {
                tracing::warn!(
                    "no answer for {}, applying the default action once",
                    con.process_path
                );
                rule::default_rule(&con, &settings, Some(0), now_secs())
                    .ok_or_else(|| Status::internal("cannot build a default rule"))?
            }
        };
        self.link.remember(&rule);
        self.remember(key, &rule);
        Ok(Response::new(rule))
    }

    async fn subscribe(
        &self,
        request: Request<ClientConfig>,
    ) -> Result<Response<ClientConfig>, Status> {
        let mut config = request.into_inner();
        tracing::info!(
            "daemon {} {} connected, {} rules",
            config.name,
            config.version,
            config.rules.len()
        );
        self.link.replace_rules(config.rules.clone());
        let settings = Settings::load(&self.settings_path);
        if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&config.config) {
            // The daemon applies this default while a UI is connected.
            json["DefaultAction"] = if settings.default_action == 1 {
                "allow"
            } else {
                "deny"
            }
            .into();
            config.config = json.to_string();
        }
        Ok(Response::new(config))
    }

    type NotificationsStream = NotificationStream;

    async fn notifications(
        &self,
        request: Request<Streaming<NotificationReply>>,
    ) -> Result<Response<Self::NotificationsStream>, Status> {
        // The daemon treats a closed stream as "UI gone", so keep it open for as
        // long as the daemon keeps its side open. Rule changes are pushed on it
        // and the daemon's replies are routed back to whoever asked.
        let mut replies = request.into_inner();
        let (outbox, stream) = mpsc::channel::<Result<Notification, Status>>(8);
        self.link.attach(outbox.clone());
        let link = self.link.clone();
        tokio::spawn(async move {
            while let Ok(Some(reply)) = replies.message().await {
                link.handle_reply(reply);
            }
            link.detach(&outbox);
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(stream))))
    }

    async fn post_alert(&self, request: Request<Alert>) -> Result<Response<MsgResponse>, Status> {
        let alert = request.into_inner();
        tracing::info!("alert {}: {:?}", alert.id, alert.data);
        Ok(Response::new(MsgResponse { id: alert.id }))
    }
}

/// Where to listen.
#[derive(Debug, PartialEq, Eq)]
enum Listen {
    Unix(PathBuf),
    Abstract(String),
    Tcp(String),
}

fn parse_address(address: &str) -> Listen {
    if let Some(name) = address.strip_prefix("unix-abstract:") {
        Listen::Abstract(name.to_string())
    } else if let Some(name) = address.strip_prefix("unix:@") {
        Listen::Abstract(name.to_string())
    } else if let Some(path) = address
        .strip_prefix("unix://")
        .or_else(|| address.strip_prefix("unix:"))
    {
        Listen::Unix(PathBuf::from(path))
    } else {
        Listen::Tcp(address.to_string())
    }
}

/// Path of the unix socket `address` refers to, if it is a filesystem socket.
pub fn socket_path(address: &str) -> Option<PathBuf> {
    match parse_address(address) {
        Listen::Unix(path) => Some(path),
        _ => None,
    }
}

/// Binds a filesystem socket, refusing to take over one that is in use.
async fn bind_unix(path: &Path) -> Result<UnixListener, BoxError> {
    if UnixStream::connect(path).await.is_ok() {
        return Err(format!("another UI is already listening on {}", path.display()).into());
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn bind_abstract(name: &str) -> Result<UnixListener, BoxError> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    let listener = std::os::unix::net::UnixListener::bind_addr(&addr)?;
    listener.set_nonblocking(true)?;
    Ok(UnixListener::from_std(listener)?)
}

/// Resolves on SIGINT or SIGTERM.
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let Ok(mut term) = signal(SignalKind::terminate()) else {
        return std::future::pending().await;
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

/// Serves `service` on `address` until the process ends or an error occurs.
pub async fn serve(address: &str, service: Service) -> Result<(), BoxError> {
    let server = Server::builder().add_service(UiServer::new(service));
    tracing::info!("listening on {address}");
    match parse_address(address) {
        Listen::Unix(path) => {
            let listener = bind_unix(&path).await?;
            server
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await?;
        }
        Listen::Abstract(name) => {
            let listener = bind_abstract(&name)?;
            server
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await?;
        }
        Listen::Tcp(addr) => {
            let addr: SocketAddr = addr.parse()?;
            let listener = TcpListener::bind(addr).await?;
            server
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_addresses() {
        assert_eq!(
            parse_address("unix:///tmp/osui.sock"),
            Listen::Unix("/tmp/osui.sock".into())
        );
        assert_eq!(
            parse_address("unix:/tmp/a.sock"),
            Listen::Unix("/tmp/a.sock".into())
        );
        assert_eq!(parse_address("unix:@osui"), Listen::Abstract("osui".into()));
        assert_eq!(
            parse_address("unix-abstract:osui"),
            Listen::Abstract("osui".into())
        );
        assert_eq!(
            parse_address("127.0.0.1:50051"),
            Listen::Tcp("127.0.0.1:50051".into())
        );
    }

    fn con() -> Connection {
        Connection {
            protocol: "tcp".into(),
            dst_ip: "1.2.3.4".into(),
            dst_port: 443,
            process_id: 7,
            process_path: "/usr/bin/curl".into(),
            process_args: vec!["curl".into()],
            ..Default::default()
        }
    }

    /// A service whose "GTK side" answers with `answer` (or drops the request).
    fn service(answer: Option<Rule>) -> Service {
        let (tx, rx) = async_channel::unbounded::<PromptRequest>();
        tokio::spawn(async move {
            while let Ok(request) = rx.recv().await {
                if let Some(rule) = answer.clone() {
                    let _ = request.reply.send(Some(rule));
                }
            }
        });
        Service::new(tx, PathBuf::from("/nonexistent/settings.conf"))
    }

    fn rule(name: &str) -> Rule {
        Rule {
            name: name.into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn ask_rule_returns_the_users_rule() {
        let svc = service(Some(rule("user-choice")));
        let reply = svc.ask_rule(Request::new(con())).await.unwrap();
        assert_eq!(reply.into_inner().name, "user-choice");
    }

    #[tokio::test]
    async fn identical_connections_reuse_the_answer() {
        let (tx, rx) = async_channel::unbounded::<PromptRequest>();
        let svc = Service::new(tx, PathBuf::from("/nonexistent/settings.conf"));
        let asked = tokio::spawn(async move {
            let mut n = 0;
            while let Ok(request) = rx.recv().await {
                n += 1;
                let _ = request.reply.send(Some(rule(&format!("answer-{n}"))));
                if n == 2 {
                    break;
                }
            }
            n
        });
        let first = svc.ask_rule(Request::new(con())).await.unwrap();
        let second = svc.ask_rule(Request::new(con())).await.unwrap();
        assert_eq!(first.into_inner().name, "answer-1");
        assert_eq!(second.into_inner().name, "answer-1");
        let mut other = con();
        other.dst_port = 80;
        let third = svc.ask_rule(Request::new(other)).await.unwrap();
        assert_eq!(third.into_inner().name, "answer-2");
        assert_eq!(asked.await.unwrap(), 2);
    }

    #[tokio::test]
    async fn unanswered_prompt_falls_back_to_default_action_once() {
        let svc = service(None);
        let reply = svc
            .ask_rule(Request::new(con()))
            .await
            .unwrap()
            .into_inner();
        // Default settings: drop, sent to the daemon as "deny".
        assert_eq!(
            (reply.action.as_str(), reply.duration.as_str()),
            ("deny", "once")
        );
        assert!(reply.enabled);
        assert!(reply.operator.is_some());
    }

    #[tokio::test]
    async fn subscribe_sets_the_default_action_and_ping_echoes() {
        let svc = service(None);
        let config = ClientConfig {
            config: r#"{"DefaultAction":"allow","LogLevel":2}"#.into(),
            ..Default::default()
        };
        let reply = svc
            .subscribe(Request::new(config))
            .await
            .unwrap()
            .into_inner();
        let json: serde_json::Value = serde_json::from_str(&reply.config).unwrap();
        assert_eq!(json["DefaultAction"], "deny");
        assert_eq!(json["LogLevel"], 2);

        let ping = svc
            .ping(Request::new(PingRequest {
                id: 9,
                ..Default::default()
            }))
            .await
            .unwrap();
        assert_eq!(ping.into_inner().id, 9);
    }

    /// Real gRPC round trip: the daemon subscribes with a rule, opens the
    /// notification stream, and confirms the `CHANGE_RULE` that the dialog's
    /// "Update rule" button triggers.
    #[tokio::test]
    async fn checksum_update_reaches_the_daemon_over_grpc() {
        use crate::proto::ui_client::UiClient;
        use crate::proto::{Action, NotificationReplyCode, Operator};

        let (tx, _rx) = async_channel::unbounded::<PromptRequest>();
        let service = Service::new(tx, PathBuf::from("/nonexistent/settings.conf"));
        let link = service.link.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(UiServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await;
        });

        let op = |operand: &str, data: &str| Operator {
            r#type: "simple".into(),
            operand: operand.into(),
            data: data.into(),
            ..Default::default()
        };
        let saved = Rule {
            name: "allow-always-list-curl".into(),
            enabled: true,
            duration: "always".into(),
            operator: Some(Operator {
                r#type: "list".into(),
                operand: "list".into(),
                list: vec![
                    op("process.path", "/usr/bin/curl"),
                    op("process.hash.md5", "old"),
                ],
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut daemon = UiClient::connect(format!("http://{addr}")).await.unwrap();
        daemon
            .subscribe(ClientConfig {
                config: "{}".into(),
                rules: vec![saved],
                ..Default::default()
            })
            .await
            .unwrap();
        let (replies, replies_rx) = mpsc::channel(4);
        let mut inbox = daemon
            .notifications(tokio_stream::wrappers::ReceiverStream::new(replies_rx))
            .await
            .unwrap()
            .into_inner();

        // The mismatch is found from the rules the daemon announced.
        let mut con = con();
        con.process_checksums
            .insert("process.hash.md5".into(), "new".into());
        let found = crate::checksum::find(&link.rules(), &con, now_secs());
        assert_eq!(found.rule_names, ["allow-always-list-curl"]);

        let updater = Updater::new(link.clone());
        let update = tokio::spawn(async move {
            updater
                .update_checksums(vec!["allow-always-list-curl".into()], "new".into())
                .await
        });
        let notification = inbox.message().await.unwrap().unwrap();
        assert_eq!(notification.r#type, Action::ChangeRule as i32);
        let list = &notification.rules[0].operator.as_ref().unwrap().list;
        assert_eq!(list[1].data, "new");
        replies
            .send(NotificationReply {
                id: notification.id,
                code: NotificationReplyCode::Ok as i32,
                data: String::new(),
            })
            .await
            .unwrap();
        update.await.unwrap().unwrap();
        assert!(crate::checksum::find(&link.rules(), &con, now_secs()).is_empty());
    }
}
