//! gRPC `UI` service the daemon connects to.
//!
//! The daemon calls `AskRule` for every unknown connection; the handler hands
//! the connection to the GTK thread and waits for the user's rule. Failures
//! never reach the daemon as gRPC errors: they become a one-shot rule with the
//! saved default action instead.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::unix::UCred;
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::Stream;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream, UnixListenerStream};
use tonic::transport::Server;
use tonic::transport::server::UdsConnectInfo;
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
use crate::view;

/// Which connecting processes may act as the daemon.
///
/// Only root by default. The daemon runs as root, and anything else that can
/// reach the socket could spam prompts, feed fake rules or take over the
/// notification stream. Unix sockets tell who is connecting; TCP cannot.
pub struct PeerPolicy {
    allowed: Vec<u32>,
    /// Peers already reported, so a flood of calls logs one line.
    reported: Mutex<HashSet<(u32, Option<i32>)>>,
}

/// The most distinct rejected peers that are logged.
const MAX_REPORTED: usize = 64;

impl PeerPolicy {
    /// Root plus the `extra` user ids.
    pub fn new(extra: &[u32]) -> Self {
        let mut allowed = vec![0];
        allowed.extend_from_slice(extra);
        Self {
            allowed,
            reported: Mutex::new(HashSet::new()),
        }
    }

    /// True when processes of user `uid` may act as the daemon.
    pub fn allows(&self, uid: u32) -> bool {
        self.allowed.contains(&uid)
    }

    /// `Ok` when `request` may be served.
    pub fn check<T>(&self, request: &Request<T>) -> Result<(), Status> {
        // No Unix credentials means a TCP connection, which can't be checked.
        let Some(info) = request.extensions().get::<UdsConnectInfo>() else {
            return Ok(());
        };
        match info.peer_cred {
            Some(cred) if self.allows(cred.uid()) => Ok(()),
            cred => {
                self.report(cred);
                Err(Status::permission_denied(
                    "only the OpenSnitch daemon may use this UI",
                ))
            }
        }
    }

    fn report(&self, cred: Option<UCred>) {
        let key = cred.map_or((u32::MAX, None), |c| (c.uid(), c.pid()));
        let first = self
            .reported
            .lock()
            .is_ok_and(|mut seen| seen.len() < MAX_REPORTED && seen.insert(key));
        if first {
            match cred {
                Some(c) => tracing::warn!(
                    "refused a connection from uid {} (pid {:?}): only uid(s) {:?} may act as the daemon",
                    c.uid(),
                    c.pid(),
                    self.allowed
                ),
                None => tracing::warn!("refused a connection whose owner could not be determined"),
            }
        }
    }
}

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

    /// What the daemon connection shares with the rest of the program.
    pub fn link(&self) -> Arc<Link> {
        self.link.clone()
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
        let summary = view::connection_summary(&con);
        tracing::info!("asked about {summary}");
        let settings = Settings::load(&self.settings_path);
        let key = dedup_key(&con);
        if let Some(rule) = self.cached(&key) {
            tracing::debug!("reusing the answer just given for {summary}");
            return Ok(Response::new(rule));
        }

        let _turn = self.turn.lock().await;
        if let Some(rule) = self.cached(&key) {
            return Ok(Response::new(rule));
        }
        let answer = self.prompt(&con, &settings).await;
        let mut rule = match answer {
            Some(rule) => rule,
            None => {
                tracing::warn!("no answer for {summary}, applying the default action once");
                rule::default_rule(&con, &settings, Some(0), now_secs())
                    .ok_or_else(|| Status::internal("cannot build a default rule"))?
            }
        };
        rule::make_name_unique(&mut rule, &self.link.rules(), now_secs());
        tracing::info!(
            "answered {} {} as {}",
            rule.action,
            rule.duration,
            rule.name
        );
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
        let resume = self.link.clone();
        tokio::spawn(async move { resume.resume_if_paused().await });
        tokio::spawn(async move {
            while let Ok(Some(reply)) = replies.message().await {
                link.handle_reply(reply);
            }
            link.detach(&outbox);
            tracing::info!("the daemon closed its notification stream");
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
///
/// Only root and the `allowed_uids` may call it (see [`PeerPolicy`]).
pub async fn serve(address: &str, service: Service, allowed_uids: &[u32]) -> Result<(), BoxError> {
    let policy = Arc::new(PeerPolicy::new(allowed_uids));
    let guarded = UiServer::with_interceptor(service, move |request: Request<()>| {
        policy.check(&request)?;
        Ok(request)
    });
    let server = Server::builder().add_service(guarded);
    if allowed_uids.is_empty() {
        tracing::info!("listening on {address}; only root may act as the daemon");
    } else {
        tracing::info!(
            "listening on {address}; only root and uid(s) {allowed_uids:?} may act as the daemon"
        );
    }
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
            tracing::warn!(
                "listening on TCP: connecting processes can't be identified, so any local process can act as the daemon"
            );
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
        let outcome = update.await.unwrap();
        assert_eq!(outcome.error, None);
        assert_eq!(outcome.updated, ["allow-always-list-curl"]);
        assert!(crate::checksum::find(&link.rules(), &con, now_secs()).is_empty());
    }

    /// Builds one HTTP/2 frame.
    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len()).unwrap();
        let mut out = len.to_be_bytes()[1..].to_vec();
        out.extend([kind, flags]);
        out.extend(stream.to_be_bytes());
        out.extend(payload);
        out
    }

    /// An HPACK "literal without indexing" header with a new name.
    fn literal(name: &str, value: &str) -> Vec<u8> {
        let mut out = vec![0x00, u8::try_from(name.len()).unwrap()];
        out.extend(name.as_bytes());
        out.push(u8::try_from(value.len()).unwrap());
        out.extend(value.as_bytes());
        out
    }

    /// opensnitchd uses grpc-go 1.32, which sends the unix socket path as the
    /// HTTP/2 `:authority`. That is not a valid authority and the HTTP/2 library
    /// used to answer with PROTOCOL_ERROR, so no call from the daemon worked.
    /// This sends the same request as raw bytes and expects a normal reply.
    #[tokio::test]
    async fn accepts_the_invalid_authority_sent_by_grpc_go() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (tx, _rx) = async_channel::unbounded::<PromptRequest>();
        let service = Service::new(tx, PathBuf::from("/nonexistent/settings.conf"));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(UiServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await;
        });

        // HEADERS: POST, http, /protocol.UI/Ping, the bad authority, gRPC type.
        let mut headers = vec![0x83, 0x86];
        headers.extend([0x04, 17]);
        headers.extend(b"/protocol.UI/Ping");
        headers.extend([0x01, 14]);
        headers.extend(b"/tmp/osui.sock");
        headers.extend(literal("content-type", "application/grpc"));
        headers.extend(literal("te", "trailers"));
        // DATA: a gRPC message holding PingRequest { id: 7 }.
        let message = [0, 0, 0, 0, 2, 0x08, 0x07];

        let mut request = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        request.extend(frame(0x4, 0, 0, &[])); // SETTINGS
        request.extend(frame(0x1, 0x4, 1, &headers)); // HEADERS, END_HEADERS
        request.extend(frame(0x0, 0x1, 1, &message)); // DATA, END_STREAM

        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        conn.write_all(&request).await.unwrap();

        // Read frames until the reply arrives or the stream is reset.
        let mut reply = Vec::new();
        let outcome = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let mut head = [0u8; 9];
                conn.read_exact(&mut head).await.unwrap();
                let len =
                    usize::try_from(u32::from_be_bytes([0, head[0], head[1], head[2]])).unwrap();
                let mut payload = vec![0u8; len];
                conn.read_exact(&mut payload).await.unwrap();
                match (
                    head[3],
                    u32::from_be_bytes([head[5], head[6], head[7], head[8]]),
                ) {
                    (0x3, 1) => return Err(format!("stream reset, code {payload:?}")),
                    (0x7, _) => return Err(format!("connection closed (GOAWAY), {payload:?}")),
                    (0x0, 1) => {
                        reply.extend(payload);
                        return Ok(());
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("no reply within 5 seconds");

        assert_eq!(outcome, Ok(()));
        assert_eq!(reply, [0, 0, 0, 0, 2, 0x08, 0x07], "PingReply with id 7");
    }

    /// Raw HTTP/2 bytes for a `Ping` call with id 7.
    fn ping_request() -> Vec<u8> {
        let mut headers = vec![0x83, 0x86];
        headers.extend([0x04, 17]);
        headers.extend(b"/protocol.UI/Ping");
        headers.extend([0x01, 9]);
        headers.extend(b"localhost");
        headers.extend(literal("content-type", "application/grpc"));
        headers.extend(literal("te", "trailers"));
        let message = [0, 0, 0, 0, 2, 0x08, 0x07];

        let mut request = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        request.extend(frame(0x4, 0, 0, &[]));
        request.extend(frame(0x1, 0x4, 1, &headers));
        request.extend(frame(0x0, 0x1, 1, &message));
        request
    }

    /// How the server treated a call.
    #[derive(Debug, PartialEq, Eq)]
    enum Served {
        /// A reply with a body.
        Reply,
        /// An error answered with headers only, as gRPC does.
        Refused,
    }

    /// Sends `Ping` over `conn` and tells whether it was served or refused.
    async fn ping_outcome<S>(conn: &mut S) -> Result<Served, String>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        conn.write_all(&ping_request()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let mut head = [0u8; 9];
                conn.read_exact(&mut head)
                    .await
                    .map_err(|e| e.to_string())?;
                let len =
                    usize::try_from(u32::from_be_bytes([0, head[0], head[1], head[2]])).unwrap();
                let mut payload = vec![0u8; len];
                conn.read_exact(&mut payload)
                    .await
                    .map_err(|e| e.to_string())?;
                let (kind, flags) = (head[3], head[4]);
                let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]);
                match (kind, stream) {
                    (0x0, 1) => return Ok(Served::Reply),
                    (0x1, 1) if flags & 0x1 != 0 => return Ok(Served::Refused),
                    (0x3, 1) => return Err(format!("stream reset {payload:?}")),
                    (0x7, _) => return Err(format!("GOAWAY {payload:?}")),
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| "no answer within 5 seconds".to_string())?
    }

    /// Serves on `address` in the background and connects to the unix `path`.
    async fn serve_and_connect(
        address: String,
        path: &std::path::Path,
        allowed: Vec<u32>,
    ) -> (tokio::task::JoinHandle<()>, tokio::net::UnixStream) {
        let (tx, _rx) = async_channel::unbounded::<PromptRequest>();
        let service = Service::new(tx, PathBuf::from("/nonexistent/settings.conf"));
        let server = tokio::spawn(async move {
            let _ = serve(&address, service, &allowed).await;
        });
        for _ in 0..100 {
            if let Ok(conn) = UnixStream::connect(path).await {
                return (server, conn);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the server never started listening on {}", path.display());
    }

    #[test]
    fn the_policy_allows_root_and_the_listed_users_only() {
        let policy = PeerPolicy::new(&[1000]);
        assert!(policy.allows(0));
        assert!(policy.allows(1000));
        assert!(!policy.allows(1001));
        assert!(!PeerPolicy::new(&[]).allows(1000));
    }

    /// The daemon is root. A process of the user who runs snitch can open the
    /// socket (it is 0600) but must not be taken for the daemon.
    #[tokio::test]
    async fn a_non_root_process_is_refused_on_a_unix_socket() {
        use std::os::unix::fs::MetadataExt;

        let own_uid = std::fs::metadata("/proc/self").unwrap().uid();
        for allowed in [vec![], vec![own_uid]] {
            let path = std::env::temp_dir().join(format!(
                "snitch-peer-{}-{}.sock",
                std::process::id(),
                allowed.len()
            ));
            let (server, mut conn) =
                serve_and_connect(format!("unix:{}", path.display()), &path, allowed.clone()).await;
            let outcome = ping_outcome(&mut conn).await;
            server.abort();
            let _ = std::fs::remove_file(&path);

            // Running the tests as root makes the first case legitimate.
            let expect = if allowed.is_empty() && own_uid != 0 {
                Served::Refused
            } else {
                Served::Reply
            };
            assert_eq!(
                outcome,
                Ok(expect),
                "allowed uids {allowed:?}, running as {own_uid}"
            );
        }
    }

    /// TCP carries no process identity, so it is still served (with a warning).
    #[tokio::test]
    async fn tcp_connections_are_still_served() {
        let port = {
            let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
            probe.local_addr().unwrap().port()
        };
        let (tx, _rx) = async_channel::unbounded::<PromptRequest>();
        let service = Service::new(tx, PathBuf::from("/nonexistent/settings.conf"));
        let address = format!("127.0.0.1:{port}");
        let server = tokio::spawn(async move {
            let _ = serve(&address, service, &[]).await;
        });
        let mut conn = None;
        for _ in 0..100 {
            if let Ok(c) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                conn = Some(c);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut conn = conn.expect("the server never started listening");
        let outcome = ping_outcome(&mut conn).await;
        server.abort();
        assert_eq!(outcome, Ok(Served::Reply));
    }
}
