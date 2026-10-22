//! The session D-Bus service other programs, such as the GNOME Shell
//! extension, use to see and change whether the daemon intercepts connections.
//!
//! Turning interception on is open to every program in the session: it can
//! only make the firewall stricter. Turning it off has to be authorised
//! through polkit, because any program of the user could call this service.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use gtk4::gio::{self, BusNameOwnerFlags, BusType, DBusConnection, DBusMethodInvocation};
use gtk4::glib::prelude::ToVariant;
use gtk4::glib::{self, Variant};

use crate::link::{DaemonState, Interception, Updater};

/// Well-known name of the service.
pub const NAME: &str = "io.github.jeronimoalbi.Snitch";
const PATH: &str = "/io/github/jeronimoalbi/Snitch";
const INTERFACE: &str = "io.github.jeronimoalbi.Snitch";
/// Version of this interface. Bumped when something is removed or changed;
/// adding methods and properties keeps it.
const VERSION: u32 = 1;
/// The polkit action that guards `Disable`; see `contrib/polkit`.
const POLKIT_ACTION: &str = "io.github.jeronimoalbi.Snitch.disable-interception";
/// Longest wait for a person to type their password.
const POLKIT_TIMEOUT_MS: i32 = 120_000;

const XML: &str = r#"
<node>
  <interface name="io.github.jeronimoalbi.Snitch">
    <property name="Version" type="u" access="read"/>
    <property name="Interception" type="s" access="read"/>
    <property name="Connected" type="b" access="read"/>
    <property name="SettingsPath" type="s" access="read"/>
    <method name="Enable"/>
    <method name="Disable"/>
  </interface>
</node>"#;

/// Starts offering the service on the session bus.
/// `settings` is the OpenSnitch settings file snitch reads, offered as the
/// `SettingsPath` property so other programs edit the same file.
pub fn serve(updater: Updater, settings: PathBuf) {
    gio::bus_own_name(
        BusType::Session,
        NAME,
        BusNameOwnerFlags::DO_NOT_QUEUE,
        move |connection, _| match register(&connection, &updater, &settings) {
            Ok(()) => tracing::info!("D-Bus service {NAME} ready"),
            Err(err) => tracing::warn!("cannot offer {NAME} on D-Bus: {err}"),
        },
        |_, _| {},
        |_, _| tracing::warn!("cannot own {NAME} on the session bus; is snitch already running?"),
    );
}

fn register(
    connection: &DBusConnection,
    updater: &Updater,
    settings: &Path,
) -> Result<(), glib::Error> {
    let node = gio::DBusNodeInfo::for_xml(XML)?;
    let interface = node
        .lookup_interface(INTERFACE)
        .ok_or_else(|| glib::Error::new(gio::DBusError::Failed, "interface missing"))?;

    let calls = updater.clone();
    let reads = updater.clone();
    let settings = settings.to_path_buf();
    connection
        .register_object(PATH, &interface)
        .method_call(move |connection, sender, _, _, method, _, invocation| {
            call(&calls, &connection, sender, method, invocation);
        })
        .property(move |_, _, _, _, name| property(reads.status(), &settings, name))
        .build()?;

    let connection = connection.clone();
    let mut changes = updater.watch();
    glib::spawn_future_local(async move {
        let mut before = *changes.borrow();
        while changes.changed().await.is_ok() {
            let now = *changes.borrow_and_update();
            announce(&connection, before, now);
            before = now;
        }
    });
    Ok(())
}

/// Value of the property `name`.
fn property(state: DaemonState, settings: &Path, name: &str) -> Variant {
    match name {
        "Version" => VERSION.to_variant(),
        "Interception" => state.interception.as_str().to_variant(),
        "Connected" => state.connected.to_variant(),
        "SettingsPath" => settings.to_string_lossy().to_variant(),
        _ => ().to_variant(),
    }
}

/// Emits `PropertiesChanged` and, when the firewall was paused or resumed,
/// shows a notification so that change can't go unnoticed.
fn announce(connection: &DBusConnection, before: DaemonState, now: DaemonState) {
    let mut changed = HashMap::new();
    if before.interception != now.interception {
        changed.insert("Interception", now.interception.as_str().to_variant());
    }
    if before.connected != now.connected {
        changed.insert("Connected", now.connected.to_variant());
    }
    if changed.is_empty() {
        return;
    }
    let params = (INTERFACE, changed, Vec::<String>::new()).to_variant();
    if let Err(err) = connection.emit_signal(
        None,
        PATH,
        "org.freedesktop.DBus.Properties",
        "PropertiesChanged",
        Some(&params),
    ) {
        tracing::warn!("cannot announce the change on D-Bus: {err}");
    }

    match (before.interception, now.interception) {
        (_, Interception::Off) if before.interception != Interception::Off => {
            glib::spawn_future_local(crate::notify_desktop(
                "Firewall paused".into(),
                "OpenSnitch no longer asks about connections.".into(),
            ));
        }
        (Interception::Off, Interception::On) => {
            glib::spawn_future_local(crate::notify_desktop(
                "Firewall on".into(),
                "OpenSnitch asks about connections again.".into(),
            ));
        }
        _ => {}
    }
}

fn failed(message: impl AsRef<str>) -> glib::Error {
    glib::Error::new(gio::DBusError::Failed, message.as_ref())
}

fn call(
    updater: &Updater,
    connection: &DBusConnection,
    sender: Option<&str>,
    method: &str,
    invocation: DBusMethodInvocation,
) {
    let updater = updater.clone();
    match (method, sender) {
        ("Enable", _) => {
            invocation.return_future_local(async move {
                updater
                    .set_interception(true)
                    .await
                    .map(|()| None)
                    .map_err(failed)
            });
        }
        ("Disable", Some(sender)) => {
            let connection = connection.clone();
            let sender = sender.to_string();
            invocation.return_future_local(async move {
                authorize(&connection, &sender).await?;
                tracing::info!("interception paused by an authorised request");
                updater
                    .set_interception(false)
                    .await
                    .map(|()| None)
                    .map_err(failed)
            });
        }
        _ => invocation.return_error(gio::DBusError::UnknownMethod, "no such method"),
    }
}

/// Asks polkit whether the process behind `sender` (a name on the session
/// bus) may turn interception off, letting polkit prompt for a password.
async fn authorize(session: &DBusConnection, sender: &str) -> Result<(), glib::Error> {
    let denied = |why: &str| glib::Error::new(gio::DBusError::AccessDenied, why);

    // Polkit identifies a caller by process, not by the session bus name.
    let pid = session
        .call_future(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "GetConnectionUnixProcessID",
            Some(&(sender,).to_variant()),
            None,
            gio::DBusCallFlags::NONE,
            5_000,
        )
        .await?
        .get::<(u32,)>()
        .ok_or_else(|| failed("unexpected reply about the caller"))?
        .0;
    let start_time = process_start_time(pid)
        .ok_or_else(|| denied("cannot identify the calling process for authorisation"))?;

    let subject = (
        "unix-process",
        HashMap::from([
            ("pid", pid.to_variant()),
            ("start-time", start_time.to_variant()),
        ]),
    );
    let allow_user_interaction = 1u32;
    let params = (
        subject,
        POLKIT_ACTION,
        HashMap::<String, String>::new(),
        allow_user_interaction,
        "",
    )
        .to_variant();

    // Only a checked "yes" counts; every failure below means no.
    let system = gio::bus_get_future(BusType::System).await.map_err(|err| {
        denied(&format!(
            "cannot reach the system bus to ask polkit: {}",
            err.message()
        ))
    })?;
    let reply = system
        .call_future(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            "org.freedesktop.PolicyKit1.Authority",
            "CheckAuthorization",
            Some(&params),
            None,
            gio::DBusCallFlags::NONE,
            POLKIT_TIMEOUT_MS,
        )
        .await
        .map_err(|err| denied(&format!("polkit refused to answer: {}", err.message())))?;
    let ((authorized, _challenge, _details),) = reply
        .get::<((bool, bool, HashMap<String, String>),)>()
        .ok_or_else(|| denied("unexpected answer from polkit"))?;
    if authorized {
        Ok(())
    } else {
        Err(denied("not authorised to turn the firewall off"))
    }
}

/// When process `pid` started, in clock ticks since boot, as polkit wants it
/// to tell a process from a later one that reuses its id.
fn process_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    start_time_from_stat(&stat)
}

/// Field 22 of `/proc/<pid>/stat`. The second field is the program name in
/// parentheses and may contain spaces and parentheses, so count from the last
/// closing one.
fn start_time_from_stat(stat: &str) -> Option<u64> {
    let after_name = &stat[stat.rfind(')')? + 1..];
    // The first field after the name is field 3, the state.
    after_name.split_whitespace().nth(22 - 3)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_interface_description_is_valid() {
        let node = gio::DBusNodeInfo::for_xml(XML).unwrap();
        let interface = node.lookup_interface(INTERFACE).unwrap();
        assert!(interface.lookup_method("Enable").is_some());
        assert!(interface.lookup_method("Disable").is_some());
        assert!(interface.lookup_property("Interception").is_some());
    }

    #[test]
    fn reads_the_start_time_even_when_the_name_is_odd() {
        let stat = "4242 (my (odd) name) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 \
                    987654 1000 2 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
        assert_eq!(start_time_from_stat(stat), Some(987_654));
        assert_eq!(start_time_from_stat("garbage"), None);
        assert_eq!(start_time_from_stat("1 (x) S 1"), None);
    }

    #[test]
    fn this_process_has_a_start_time() {
        assert!(process_start_time(std::process::id()).is_some());
    }

    #[test]
    fn properties_report_the_state() {
        let state = DaemonState {
            connected: true,
            interception: Interception::Off,
        };
        assert_eq!(
            property(state, Path::new("/x"), "Interception").str(),
            Some("off")
        );
        assert_eq!(
            property(state, Path::new("/x"), "Connected").get::<bool>(),
            Some(true)
        );
        assert_eq!(
            property(state, Path::new("/x"), "Version").get::<u32>(),
            Some(VERSION)
        );
        assert_eq!(
            property(state, Path::new("/a/settings.conf"), "SettingsPath").str(),
            Some("/a/settings.conf")
        );
    }
}
