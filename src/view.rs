//! Texts shown by the prompt, ported from the Qt UI
//! (`dialogs/prompt/utils.py` and `details.py`). Kept free of GTK so it can
//! be unit tested. Connection data is attacker-controlled, so everything that
//! ends up in Pango markup goes through [`escape_markup`].

use std::path::{Component, Path};

use crate::model::command_line;
use crate::proto::{Connection, Rule};

/// Escapes `text` for use inside Pango markup.
pub fn escape_markup(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Cuts `text` to `max` characters, appending `...` when shortened.
pub fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() > max {
        let head: String = text.chars().take(max).collect();
        format!("{head}...")
    } else {
        text.to_string()
    }
}

/// Drops control characters, which could spoof or break the labels.
pub fn printable(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

/// Like [`printable`] but keeps line breaks.
pub fn printable_lines(text: &str) -> String {
    text.chars()
        .filter(|c| *c == '\n' || !c.is_control())
        .collect()
}

/// Escapes the characters desktop notification bodies treat as markup.
fn escape_body(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Title and body of the notification shown when a prompt timed out and the
/// default rule was applied. The values come from the connection, so they are
/// escaped for the notification body.
pub fn missed_popup(con: &Connection, rule: &Rule) -> (String, String) {
    let verb = match rule.action.as_str() {
        "allow" => "allowed",
        "reject" => "rejected",
        _ => "dropped",
    };
    let program = match con.process_path.rsplit('/').next() {
        Some(name) if !name.is_empty() => printable(name),
        _ => "A program".to_string(),
    };
    let host = if con.dst_host.is_empty() {
        &con.dst_ip
    } else {
        &con.dst_host
    };
    let destination = match con.dst_port {
        0 => printable(host),
        port => format!("{}:{port}", printable(host)),
    };
    let protocol = match con.protocol.as_str() {
        "" => String::new(),
        p => format!(" ({})", printable(&p.to_uppercase())),
    };
    let body = format!(
        "{} to {}{}\nNobody answered in time, so the default action was applied.",
        escape_body(&program),
        escape_body(&destination),
        escape_body(&protocol),
    );
    (format!("Connection {verb}"), body)
}

/// One-line description of a connection for the logs: program, destination and
/// protocol. Command-line arguments are left out on purpose, since they can
/// hold secrets such as tokens in URLs.
pub fn connection_summary(con: &Connection) -> String {
    let program = if con.process_path.is_empty() {
        "unknown program"
    } else {
        &con.process_path
    };
    let host = if con.dst_host.is_empty() {
        &con.dst_ip
    } else {
        &con.dst_host
    };
    let destination = match con.dst_port {
        0 => printable(host),
        port => format!("{}:{port}", printable(host)),
    };
    format!(
        "{} -> {destination} {}",
        printable(program),
        printable(&con.protocol)
    )
}

/// Directories only root can write to. A program installed there is what its
/// name says, which a program in a world-writable place like `/tmp` is not.
const SYSTEM_DIRS: [&str; 7] = ["/usr", "/opt", "/bin", "/sbin", "/lib", "/lib64", "/snap"];

/// True when `path` is absolute, has no `..`, and is inside a system directory.
pub fn in_system_dir(path: &Path) -> bool {
    path.is_absolute()
        && !path.components().any(|c| matches!(c, Component::ParentDir))
        && SYSTEM_DIRS.iter().any(|dir| path.starts_with(dir))
}

/// Whether a desktop entry that launches `exec` is the program at `process`.
///
/// `Exec=` usually holds only a name (`firefox`), so a program is matched by
/// name only when it sits in a system directory. A binary called `firefox` in
/// `/tmp` or the home directory must not borrow Firefox's name, icon and
/// description, which is what the user trusts when answering.
pub fn same_program(exec: &Path, process: &Path) -> bool {
    exec == process
        || (in_system_dir(process)
            && exec.file_name().is_some()
            && exec.file_name() == process.file_name())
}

/// Application name: desktop entry name, else the binary name.
pub fn app_name(desktop_name: Option<&str>, con: &Connection) -> String {
    if let Some(name) = desktop_name.filter(|n| !n.is_empty()) {
        return name.to_string();
    }
    match con.process_path.rsplit('/').next() {
        Some(base) if !base.is_empty() => base.to_string(),
        _ => "Outgoing connection".to_string(),
    }
}

/// Sentence under the app name, as Pango markup.
pub fn popup_message(app_name: &str, con: &Connection) -> String {
    let name = format!("<b>{}</b>", escape_markup(&truncate(app_name, 64)));
    let target = escape_markup(if con.dst_host.is_empty() {
        &con.dst_ip
    } else {
        &con.dst_host
    });
    let proto = escape_markup(&con.protocol.to_uppercase());
    let action = if con.dst_port == 53 && con.dst_ip != con.dst_host && !con.dst_host.is_empty() {
        format!(
            "is attempting to resolve <b>{target}</b> via {}, {proto} port {}",
            escape_markup(&con.dst_ip),
            con.dst_port
        )
    } else if con.dst_port == 0 {
        // ICMP and friends have no port.
        format!("is connecting to <b>{target}</b>, {proto}")
    } else {
        format!(
            "is connecting to <b>{target}</b> on {proto} port {}",
            con.dst_port
        )
    };
    format!("{name} {action}")
}

/// Binary path line, shown only when it isn't already part of the command line.
pub fn path_label(app_name: &str, con: &Connection) -> Option<String> {
    let path = &con.process_path;
    if path.is_empty() {
        return None;
    }
    let text = if con.process_args.is_empty() {
        truncate(path, 64)
    } else if !con.process_args.contains(path) {
        if app_name.to_lowercase() == command_line(con) {
            truncate(path, 64)
        } else {
            truncate(&format!("({path})"), 64)
        }
    } else {
        return None;
    };
    Some(printable(&text))
}

/// Command line, hidden when it is just the app name.
pub fn args_label(app_name: &str, con: &Connection) -> Option<String> {
    let args = command_line(con);
    if app_name.to_lowercase() == args || args.is_empty() {
        None
    } else {
        Some(printable(&truncate(&args, 256)))
    }
}

/// `1000 (name)` or just the id when the user is unknown.
pub fn user_label(uid: u32, name: Option<&str>) -> String {
    match name {
        Some(name) => format!("{uid} ({name})"),
        None => uid.to_string(),
    }
}

/// Looks up the login name of `uid` in `/etc/passwd`.
pub fn user_name(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut f = line.split(':');
        let (name, _, id) = (f.next()?, f.next()?, f.next()?);
        (id.parse::<u32>().ok()? == uid).then(|| name.to_string())
    })
}

/// MD5 of the process as reported by the daemon (needs `Rules.EnableChecksums`).
pub fn md5(con: &Connection) -> &str {
    con.process_checksums
        .get("process.hash.md5")
        .map_or("", String::as_str)
}

/// Plain-text body of the details page.
pub fn details_text(con: &Connection, user: &str) -> String {
    let mut out = format!(
        "{} {}:{} -> {}:{}\n\n",
        con.protocol.to_uppercase(),
        con.src_ip,
        con.src_port,
        con.dst_ip,
        con.dst_port
    );
    let mut line =
        |key: &str, value: &str| out.push_str(&format!("{key:<9}{}\n", printable(value)));
    line("Path:", &con.process_path);
    line("Cmdline:", &command_line(con));
    line("CWD:", &con.process_cwd);
    line("MD5:", md5(con));
    line("UID:", user);
    line("PID:", &con.process_id.to_string());

    if !con.process_tree.is_empty() {
        out.push_str("\nProcess tree:\n");
        for (depth, entry) in con.process_tree.iter().rev().enumerate() {
            let indent = "  ".repeat(depth);
            let branch = if depth == 0 { "" } else { "\\_ " };
            out.push_str(&format!(
                "{indent}{branch}{} ({})\n",
                printable(&entry.key),
                entry.value
            ));
        }
    }
    if !con.process_env.is_empty() {
        out.push_str("\nEnvironment:\n");
        let mut env: Vec<_> = con.process_env.iter().collect();
        env.sort();
        for (key, value) in env {
            out.push_str(&format!("{}={}\n", printable(key), printable(value)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::StringInt;

    fn con() -> Connection {
        Connection {
            protocol: "tcp".into(),
            src_ip: "10.0.0.2".into(),
            src_port: 5555,
            dst_ip: "1.2.3.4".into(),
            dst_host: "example.com".into(),
            dst_port: 443,
            process_path: "/usr/bin/curl".into(),
            process_args: vec!["curl".into(), "x".into()],
            ..Default::default()
        }
    }

    #[test]
    fn message_variants() {
        let mut c = con();
        assert_eq!(
            popup_message("curl", &c),
            "<b>curl</b> is connecting to <b>example.com</b> on TCP port 443"
        );
        c.dst_port = 0;
        assert_eq!(
            popup_message("curl", &c),
            "<b>curl</b> is connecting to <b>example.com</b>, TCP"
        );
        c.dst_port = 53;
        c.protocol = "udp".into();
        assert_eq!(
            popup_message("curl", &c),
            "<b>curl</b> is attempting to resolve <b>example.com</b> via 1.2.3.4, UDP port 53"
        );
    }

    #[test]
    fn message_escapes_markup() {
        let mut c = con();
        c.dst_host = "<i>evil</i>&".into();
        assert!(popup_message("<b>x", &c).contains("&lt;i&gt;evil&lt;/i&gt;&amp;"));
        assert!(popup_message("<b>x", &c).starts_with("<b>&lt;b&gt;x</b>"));
    }

    #[test]
    fn path_and_args_labels() {
        let mut c = con();
        assert_eq!(path_label("curl", &c).as_deref(), Some("(/usr/bin/curl)"));
        assert_eq!(args_label("curl", &c).as_deref(), Some("curl x"));
        c.process_args = vec!["/usr/bin/curl".into()];
        assert_eq!(path_label("curl", &c), None);
        c.process_args.clear();
        assert_eq!(path_label("curl", &c).as_deref(), Some("/usr/bin/curl"));
        assert_eq!(args_label("curl", &c), None);
    }

    #[test]
    fn summary_names_program_destination_and_protocol() {
        let mut c = con();
        assert_eq!(
            connection_summary(&c),
            "/usr/bin/curl -> example.com:443 tcp"
        );
        c.process_args = vec!["--token=secret".into()];
        assert!(!connection_summary(&c).contains("secret"));
        c.process_path.clear();
        c.dst_host.clear();
        c.dst_port = 0;
        assert_eq!(connection_summary(&c), "unknown program -> 1.2.3.4 tcp");
    }

    #[test]
    fn summary_cannot_forge_log_lines() {
        let mut c = con();
        c.process_path = "/tmp/x\nINFO answered allow always".into();
        assert!(!connection_summary(&c).contains('\n'));
    }

    #[test]
    fn system_directories_are_recognised() {
        let system = |p: &str| in_system_dir(Path::new(p));
        assert!(system("/usr/bin/firefox"));
        assert!(system("/usr/lib/firefox/firefox"));
        assert!(system("/opt/google/chrome/chrome"));
        assert!(system("/snap/firefox/4793/usr/lib/firefox/firefox"));
        assert!(!system("/tmp/evil/firefox"));
        assert!(!system("/home/user/bin/firefox"));
        assert!(!system("/dev/shm/firefox"));
        assert!(!system("/usrx/bin/firefox"), "only whole directory names");
        assert!(!system("/usr/../tmp/evil/firefox"), "no parent components");
        assert!(!system("usr/bin/firefox"), "relative");
    }

    #[test]
    fn a_program_borrows_a_desktop_entry_only_from_a_system_directory() {
        let same = |exec: &str, process: &str| same_program(Path::new(exec), Path::new(process));
        // `Exec=firefox` is just a name.
        assert!(same("firefox", "/usr/lib/firefox/firefox"));
        assert!(same("firefox", "/usr/bin/firefox"));
        assert!(!same("firefox", "/tmp/evil/firefox"));
        assert!(!same("firefox", "/home/user/.cache/firefox"));
        assert!(!same("chrome", "/usr/bin/firefox"));
        // An entry that names the exact binary matches it wherever it is.
        assert!(same("/opt/app/bin/app", "/opt/app/bin/app"));
        assert!(same("/home/user/app/app", "/home/user/app/app"));
        assert!(!same("", "/usr/bin/firefox"));
    }

    #[test]
    fn names() {
        let mut c = con();
        assert_eq!(app_name(None, &c), "curl");
        assert_eq!(app_name(Some("Curl App"), &c), "Curl App");
        c.process_path.clear();
        assert_eq!(app_name(None, &c), "Outgoing connection");
    }

    fn applied(action: &str) -> Rule {
        Rule {
            action: action.into(),
            ..Default::default()
        }
    }

    #[test]
    fn missed_popup_says_what_happened() {
        let (title, body) = missed_popup(&con(), &applied("deny"));
        assert_eq!(title, "Connection dropped");
        assert_eq!(
            body,
            "curl to example.com:443 (TCP)\nNobody answered in time, so the default action was applied."
        );
    }

    #[test]
    fn missed_popup_title_follows_the_action() {
        assert_eq!(
            missed_popup(&con(), &applied("allow")).0,
            "Connection allowed"
        );
        assert_eq!(
            missed_popup(&con(), &applied("reject")).0,
            "Connection rejected"
        );
    }

    #[test]
    fn missed_popup_copes_with_missing_data() {
        let mut c = con();
        c.process_path.clear();
        c.dst_host.clear();
        c.dst_port = 0;
        c.protocol.clear();
        let (_, body) = missed_popup(&c, &applied("deny"));
        assert!(body.starts_with("A program to 1.2.3.4\n"), "{body}");
    }

    #[test]
    fn missed_popup_escapes_connection_data() {
        let mut c = con();
        c.process_path = "/tmp/<i>evil&".into();
        c.dst_host = "<a href=\"x\">".into();
        let (_, body) = missed_popup(&c, &applied("deny"));
        assert!(
            body.starts_with("&lt;i&gt;evil&amp; to &lt;a href=\"x\"&gt;:443 (TCP)\n"),
            "{body}"
        );
    }

    #[test]
    fn truncation() {
        assert_eq!(truncate("abcdef", 3), "abc...");
        assert_eq!(truncate("abc", 3), "abc");
    }

    #[test]
    fn details_include_tree_and_env() {
        let mut c = con();
        c.process_tree = vec![
            StringInt {
                key: "/usr/bin/systemd".into(),
                value: 1,
            },
            StringInt {
                key: "/usr/bin/curl".into(),
                value: 77,
            },
        ];
        c.process_env.insert("HOME".into(), "/root".into());
        let text = details_text(&c, "0 (root)");
        assert!(text.starts_with("TCP 10.0.0.2:5555 -> 1.2.3.4:443"));
        assert!(text.contains("/usr/bin/curl (77)\n  \\_ /usr/bin/systemd (1)"));
        assert!(text.contains("HOME=/root"));
    }
}
