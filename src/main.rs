//! snitch: a GTK4 prompt UI for the OpenSnitch daemon.
//!
//! Run without arguments to listen for the daemon (replacing `opensnitch-ui`),
//! or with `--demo` to preview the dialog with a fake connection.

mod checksum;
mod demo;
mod dialog;
mod link;
mod model;
mod rule;
mod server;
mod settings;
mod view;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use gtk4::gio::ApplicationFlags;
use gtk4::glib;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::server::{PromptRequest, Service};
use crate::settings::{DEFAULT_ADDRESS, Settings};

/// Types generated from `proto/ui.proto`.
pub mod proto {
    tonic::include_proto!("protocol");
}

const APP_ID: &str = "io.github.jeronimoalbi.Snitch";

const USAGE: &str = "\
snitch - GTK prompt for the OpenSnitch daemon

USAGE: snitch [OPTIONS]

OPTIONS:
    --demo                   Show the dialog with a fake connection and print the rule
    --demo-scenario <NAME>   Demo scenario (implies --demo); default: curl
    --socket <ADDRESS>       Address to listen on (default: the Qt UI setting, else unix:///tmp/osui.sock)
    --settings <PATH>        Qt UI settings file (default: ~/.config/opensnitch/settings.conf)
    -h, --help               Show this help";

/// Parsed command line.
#[derive(Debug, Default)]
struct Args {
    demo: Option<String>,
    socket: Option<String>,
    settings: Option<PathBuf>,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut out = Args::default();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--demo" => {
                out.demo.get_or_insert_with(|| "curl".to_string());
            }
            "--demo-scenario" => {
                let name = value("--demo-scenario")?;
                if demo::scenario(&name).is_none() {
                    return Err(format!(
                        "unknown scenario '{name}', try: {}",
                        demo::SCENARIOS.join(", ")
                    ));
                }
                out.demo = Some(name);
            }
            "--socket" => out.socket = Some(value("--socket")?),
            "--settings" => out.settings = Some(PathBuf::from(value("--settings")?)),
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    Ok(Some(out))
}

fn main() -> glib::ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(Some(args)) => args,
        Ok(None) => {
            println!("{USAGE}");
            return glib::ExitCode::SUCCESS;
        }
        Err(err) => {
            eprintln!("snitch: {err}\n\n{USAGE}");
            return glib::ExitCode::FAILURE;
        }
    };

    let app = adw::Application::builder()
        .application_id(APP_ID)
        .flags(ApplicationFlags::NON_UNIQUE)
        .build();
    let args = Rc::new(args);
    app.connect_activate(move |app| {
        // No window exists between prompts, so keep the application alive.
        std::mem::forget(app.hold());
        let settings_path = args.settings.clone().unwrap_or_else(Settings::default_path);
        match &args.demo {
            Some(name) => run_demo(app, name, &settings_path),
            None => run_daemon(app, args.socket.clone(), settings_path),
        }
    });
    app.run_with_args::<String>(&[])
}

/// Shows one fake prompt, prints the resulting rule and exits.
fn run_demo(app: &adw::Application, scenario: &str, settings_path: &std::path::Path) {
    let Some(con) = demo::scenario(scenario) else {
        return;
    };
    let settings = Settings::load(settings_path);
    let app = app.clone();
    let scenario = scenario.to_string();
    glib::spawn_future_local(async move {
        let checks = dialog::Checks {
            mismatch: demo::mismatch(&scenario),
            updater: None,
        };
        match dialog::prompt(&app, con, settings, checks, || false)
            .await
            .rule
        {
            Some(rule) => println!(
                "{}",
                serde_json::to_string_pretty(&rule::to_json(&rule)).unwrap_or_default()
            ),
            None => println!("no rule (empty selection)"),
        }
        app.quit();
    });
}

/// Starts the gRPC server and shows a dialog for every `AskRule` it receives.
fn run_daemon(app: &adw::Application, socket: Option<String>, settings_path: PathBuf) {
    let address = socket
        .or_else(|| Settings::load(&settings_path).server_address)
        .unwrap_or_else(|| DEFAULT_ADDRESS.to_string());
    if let Some(dir) = server::socket_path(&address)
        .as_deref()
        .and_then(|p| p.parent())
        && !dir.is_dir()
    {
        tracing::error!("socket directory {} does not exist", dir.display());
        app.quit();
        return;
    }

    let (prompts, requests) = async_channel::unbounded::<PromptRequest>();
    let service = Service::new(prompts, settings_path);
    let serve_address = address.clone();
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                tracing::error!("cannot start the async runtime: {err}");
                std::process::exit(1);
            }
        };
        let outcome = runtime.block_on(async {
            tokio::select! {
                result = server::serve(&serve_address, service) => result,
                () = server::shutdown_signal() => Ok(()),
            }
        });
        // Don't leave a stale socket behind.
        if let Some(path) = server::socket_path(&serve_address) {
            let _ = std::fs::remove_file(path);
        }
        if let Err(err) = outcome {
            tracing::error!("server stopped: {err}");
            std::process::exit(1);
        }
        std::process::exit(0);
    });

    // Prompts are handled one after another on the GTK thread.
    let prompt_app = app.clone();
    glib::spawn_future_local(async move {
        while let Ok(PromptRequest {
            con,
            settings,
            mismatch,
            updater,
            reply,
        }) = requests.recv().await
        {
            let reply = Rc::new(RefCell::new(Some(reply)));
            let gone = reply.clone();
            let cancelled = move || gone.borrow().as_ref().is_none_or(|r| r.is_closed());
            let checks = dialog::Checks { mismatch, updater };
            let asked = con.clone();
            let answer = dialog::prompt(&prompt_app, con, settings, checks, cancelled).await;
            if answer.timed_out
                && let Some(rule) = &answer.rule
            {
                let (title, body) = view::missed_popup(&asked, rule);
                glib::spawn_future_local(notify_desktop(title, body));
            }
            if let Some(reply) = reply.borrow_mut().take() {
                // The daemon may have given up meanwhile; nothing to do then.
                let _ = reply.send(answer.rule);
            }
        }
    });
}

/// Shows a desktop notification through `org.freedesktop.Notifications`, the
/// interface GNOME, KDE, dunst and mako all implement. It needs no desktop
/// file, unlike notifications sent through the application ID.
///
/// The server decides how long it stays up, and applies its own Do Not Disturb
/// and notification settings, such as GNOME's.
async fn notify_desktop(title: String, body: String) {
    use std::collections::HashMap;

    use glib::prelude::ToVariant;

    let urgency_normal: u8 = 1;
    let hints = HashMap::from([("urgency".to_string(), urgency_normal.to_variant())]);
    // -1 means "the server's default expiry".
    let expire_ms: i32 = -1;
    let params = (
        "OpenSnitch",
        0u32,
        "dialog-information",
        title,
        body,
        Vec::<String>::new(),
        hints,
        expire_ms,
    )
        .to_variant();

    let sent = async {
        let bus = gtk4::gio::bus_get_future(gtk4::gio::BusType::Session).await?;
        bus.call_future(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
            "Notify",
            Some(&params),
            None,
            gtk4::gio::DBusCallFlags::NONE,
            5_000,
        )
        .await
    };
    if let Err(err) = sent.await {
        tracing::warn!("cannot show the notification: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Option<Args>, String> {
        parse_args(args.iter().map(|a| a.to_string()))
    }

    #[test]
    fn parses_flags() {
        let a = parse(&["--demo-scenario", "dns", "--socket", "unix:/x"])
            .unwrap()
            .unwrap();
        assert_eq!(a.demo.as_deref(), Some("dns"));
        assert_eq!(a.socket.as_deref(), Some("unix:/x"));
        assert_eq!(
            parse(&["--demo"]).unwrap().unwrap().demo.as_deref(),
            Some("curl")
        );
        assert!(parse(&["--help"]).unwrap().is_none());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse(&["--demo-scenario", "nope"]).is_err());
        assert!(parse(&["--socket"]).is_err());
        assert!(parse(&["--wat"]).is_err());
    }
}
