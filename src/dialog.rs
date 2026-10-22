//! The connection prompt window, mirroring the Qt UI's `PromptDialog`.

use std::cell::{Cell, RefCell};
use std::path::Path;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use adw::prelude::*;
use gtk4 as gtk;
use gtk4_layer_shell::{Edge, KeyboardMode, Layer, LayerShell};
use libadwaita as adw;

use crate::checksum::{self, Mismatch};
use crate::link::{Outcome, Updater};
use crate::model::{self, Target};
use crate::proto::{Connection, Rule};
use crate::rule::{self, Action, Choice, DURATIONS};
use crate::settings::Settings;
use crate::view;

const WIDTH: i32 = 540;
const MARGIN: i32 = 16;

/// Checksum information shown with the prompt.
pub struct Checks {
    /// Saved rules that pin a different checksum than the running program.
    pub mismatch: Mismatch,
    /// Changes daemon rules; `None` in demo mode, where updates are only pretended.
    pub updater: Option<Updater>,
}

/// What the prompt resolved to.
#[derive(Debug, Default)]
pub struct Answer {
    /// The user's rule; `None` when it was cancelled or the selection is empty.
    pub rule: Option<Rule>,
    /// The countdown ran out (or popups are disabled), so the default applied.
    pub timed_out: bool,
}

/// Shows the prompt for `con` and resolves to the user's rule.
///
/// Resolves to `None` when `cancelled` turns true (the daemon stopped waiting)
/// or when no rule can be built from the selection. With popups disabled
/// (timeout 0) no window is shown and the saved default is returned.
pub async fn prompt(
    app: &adw::Application,
    con: Connection,
    settings: Settings,
    checks: Checks,
    cancelled: impl Fn() -> bool + 'static,
) -> Answer {
    if settings.popups_disabled() {
        return Answer {
            rule: rule::default_rule(&con, &settings, None, now_secs()),
            timed_out: true,
        };
    }
    let (result, answer) = async_channel::bounded(1);
    let dialog = Dialog::new(app, con, settings, checks, result);
    dialog.start(cancelled);
    answer.recv().await.unwrap_or_default()
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

/// Entry of the desktop database for the binary at `path`, if any.
fn desktop_info(path: &str) -> Option<gtk::gio::AppInfo> {
    if path.is_empty() {
        return None;
    }
    let wanted = Path::new(path);
    let apps = gtk::gio::AppInfo::all();
    apps.iter()
        .find(|a| a.executable() == wanted)
        .or_else(|| {
            apps.iter()
                .find(|a| a.executable().file_name() == wanted.file_name())
        })
        .cloned()
}

fn label(text: &str) -> gtk::Label {
    let l = gtk::Label::new(Some(text));
    l.set_xalign(0.0);
    l.set_wrap(true);
    l
}

/// A vertical box with the window's content margins.
fn padded_box(spacing: i32) -> gtk::Box {
    let b = gtk::Box::new(gtk::Orientation::Vertical, spacing);
    b.set_margin_top(MARGIN);
    b.set_margin_bottom(MARGIN);
    b.set_margin_start(MARGIN);
    b.set_margin_end(MARGIN);
    b
}

/// Widgets of the checksums page that the update handlers touch.
#[derive(Clone)]
struct ChecksumsUi {
    names: gtk::DropDown,
    status: gtk::Label,
    buttons: gtk::Box,
    update: gtk::Button,
    update_all: gtk::Button,
}

/// Every name in a [`name_dropdown`].
fn list_names(dd: &gtk::DropDown) -> Vec<String> {
    let Some(model) = dd.model() else {
        return Vec::new();
    };
    (0..model.n_items())
        .filter_map(|i| model.item(i).and_downcast::<gtk::StringObject>())
        .map(|s| s.string().to_string())
        .collect()
}

/// The selected name of a [`name_dropdown`].
fn selected_name(dd: &gtk::DropDown) -> Option<String> {
    dd.selected_item()
        .and_downcast::<gtk::StringObject>()
        .map(|s| s.string().to_string())
}

/// Removes `names` from a [`name_dropdown`].
fn remove_names(dd: &gtk::DropDown, names: &[String]) {
    let Some(list) = dd.model().and_downcast::<gtk::StringList>() else {
        return;
    };
    for name in names {
        let position = (0..list.n_items()).find(|&i| list.string(i).as_deref() == Some(name));
        if let Some(position) = position {
            list.remove(position);
        }
    }
}

/// A dropdown of `names` whose entries are cut short instead of widening the window.
fn name_dropdown(names: &[String]) -> gtk::DropDown {
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let dd = gtk::DropDown::from_strings(&names);
    let factory = gtk::SignalListItemFactory::new();
    factory.connect_setup(|_, item| {
        let Some(item) = item.downcast_ref::<gtk::ListItem>() else {
            return;
        };
        let l = label("");
        l.set_wrap(false);
        l.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
        l.set_max_width_chars(44);
        item.set_child(Some(&l));
    });
    factory.connect_bind(|_, item| {
        let Some(item) = item.downcast_ref::<gtk::ListItem>() else {
            return;
        };
        let text = item
            .item()
            .and_downcast::<gtk::StringObject>()
            .map(|s| s.string());
        if let (Some(text), Some(l)) = (text, item.child().and_downcast::<gtk::Label>()) {
            l.set_text(&text);
        }
    });
    dd.set_factory(Some(&factory));
    dd.set_hexpand(true);
    dd
}

fn dropdown(targets: &[Target]) -> gtk::DropDown {
    let labels: Vec<&str> = targets.iter().map(|t| t.label.as_str()).collect();
    let dd = gtk::DropDown::from_strings(&labels);
    dd.set_hexpand(true);
    dd
}

struct Dialog {
    window: adw::Window,
    stack: gtk::Stack,
    con: Connection,
    what: Vec<Target>,
    ip: Vec<Target>,
    checksum: String,
    what_dd: gtk::DropDown,
    ip_dd: gtk::DropDown,
    duration_dd: gtk::DropDown,
    check_ip: gtk::CheckButton,
    check_port: gtk::CheckButton,
    check_uid: gtk::CheckButton,
    check_sum: gtk::CheckButton,
    advanced: gtk::ToggleButton,
    checks: Checks,
    allow_btn: gtk::Button,
    deny_btn: adw::SplitButton,
    default_action: Action,
    remaining: Cell<u32>,
    timeout: u32,
    counting: Cell<bool>,
    done: Cell<bool>,
    result: async_channel::Sender<Answer>,
    timed_out: Cell<bool>,
    /// The red warning on the main page, hidden once every rule is updated.
    warning: RefCell<Option<gtk::Label>>,
}

impl Dialog {
    fn new(
        app: &adw::Application,
        con: Connection,
        settings: Settings,
        checks: Checks,
        result: async_channel::Sender<Answer>,
    ) -> Rc<Self> {
        let info = desktop_info(&con.process_path);
        let app_name = view::app_name(info.as_ref().map(|i| i.display_name()).as_deref(), &con);
        let user = view::user_label(con.user_id, view::user_name(con.user_id).as_deref());

        // Disabled entries are left out of the combos; the default index is
        // computed on the full list and mapped back by label.
        let all = model::what_targets(&con);
        let mut default_idx = model::default_target_index(&all, &con, settings.default_target);
        if all.get(default_idx).is_some_and(|t| !t.enabled) {
            default_idx = 2;
        }
        let default_label = all.get(default_idx).map(|t| t.label.clone());
        let what: Vec<Target> = all.into_iter().filter(|t| t.enabled).collect();
        let ip = model::ip_targets(&con);

        let what_dd = dropdown(&what);
        if let Some(pos) = what
            .iter()
            .position(|t| Some(&t.label) == default_label.as_ref())
        {
            what_dd.set_selected(u32::try_from(pos).unwrap_or(0));
        }
        let ip_dd = dropdown(&ip);
        let duration_labels: Vec<&str> = DURATIONS.iter().map(|d| d.0).collect();
        let duration_dd = gtk::DropDown::from_strings(&duration_labels);
        duration_dd.set_selected(u32::try_from(settings.default_duration).unwrap_or(0));

        let checksum = view::md5(&con).to_string();
        let check_ip = gtk::CheckButton::with_label("Destination IP");
        let check_port = gtk::CheckButton::with_label("Destination port");
        let check_uid = gtk::CheckButton::with_label("User ID");
        let check_sum = gtk::CheckButton::with_label("Checksum");
        check_ip.set_active(settings.advanced_dstip);
        check_port.set_active(settings.advanced_dstport);
        check_uid.set_active(settings.advanced_uid);
        check_sum.set_active(settings.advanced_checksum);

        let default_action = Action::from_index(settings.default_action);
        let allow_btn = gtk::Button::with_label("Allow");
        allow_btn.add_css_class("suggested-action");
        let deny_btn = adw::SplitButton::new();
        deny_btn.add_css_class("destructive-action");
        let advanced = gtk::ToggleButton::new();
        advanced.set_icon_name("view-more-symbolic");
        advanced.set_tooltip_text(Some("Advanced options"));

        let window = adw::Window::new();
        window.set_title(Some("OpenSnitch"));
        window.set_resizable(false);
        place(&window, settings.popup_position);
        window.set_application(Some(app));

        let stack = gtk::Stack::new();
        stack.set_vhomogeneous(false);
        // A non-resizable window fits its content, so pin the width there; a
        // default size would be dropped when the advanced rows are revealed.
        stack.set_width_request(WIDTH);

        let dialog = Rc::new(Self {
            window,
            stack,
            con,
            what,
            ip,
            checksum,
            what_dd,
            ip_dd,
            duration_dd,
            check_ip,
            check_port,
            check_uid,
            check_sum,
            advanced,
            checks,
            allow_btn,
            deny_btn,
            default_action,
            remaining: Cell::new(settings.timeout),
            timeout: settings.timeout,
            counting: Cell::new(!settings.advanced),
            done: Cell::new(false),
            result,
            timed_out: Cell::new(false),
            warning: RefCell::new(None),
        });
        dialog.build_ui(info.as_ref(), &app_name, &user);
        dialog.advanced.set_active(settings.advanced);
        dialog.update_buttons();
        dialog.lock_button_widths();
        dialog.connect_signals();
        dialog
    }

    fn build_ui(self: &Rc<Self>, info: Option<&gtk::gio::AppInfo>, app_name: &str, user: &str) {
        let con = &self.con;

        // Header: icon, names and the details button.
        let icon = gtk::Image::new();
        icon.set_pixel_size(48);
        match info.and_then(|i| i.icon()) {
            Some(gicon) => icon.set_from_gicon(&gicon),
            None => icon.set_icon_name(Some("application-x-executable")),
        }
        icon.set_valign(gtk::Align::Start);

        let titles = gtk::Box::new(gtk::Orientation::Vertical, 2);
        titles.set_hexpand(true);
        let name = label(&view::printable(&view::truncate(app_name, 42)));
        name.add_css_class("title-2");
        titles.append(&name);
        if let Some(description) = info.and_then(|i| i.description()).filter(|d| !d.is_empty()) {
            let l = label(&view::printable(&view::truncate(&description, 64)));
            l.add_css_class("dim-label");
            titles.append(&l);
        }
        for text in [
            view::path_label(app_name, con),
            view::args_label(app_name, con),
        ]
        .into_iter()
        .flatten()
        {
            let l = label(&text);
            l.add_css_class("dim-label");
            l.add_css_class("caption");
            l.set_selectable(true);
            l.set_tooltip_text(Some(&view::printable(&con.process_path)));
            titles.append(&l);
        }

        let details_btn = gtk::Button::from_icon_name("view-reveal-symbolic");
        details_btn.add_css_class("flat");
        details_btn.set_valign(gtk::Align::Start);
        details_btn.set_tooltip_text(Some("Process details"));

        let header = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        header.append(&icon);
        header.append(&titles);
        header.append(&details_btn);

        let message = label(&view::popup_message(app_name, con));
        message.set_use_markup(true);
        let warning = self.checksum_warning();

        // Advanced rows.
        let grid = gtk::Grid::new();
        grid.set_row_spacing(6);
        grid.set_column_spacing(12);
        let cwd = label(&view::printable(&view::truncate(&con.process_cwd, 32)));
        cwd.set_tooltip_text(Some(&view::printable(&con.process_cwd)));
        let mut row = 0;
        let mut add = |key: gtk::Widget, value: gtk::Widget| {
            grid.attach(&key, 0, row, 1, 1);
            grid.attach(&value, 1, row, 1, 1);
            row += 1;
        };
        add(label("Executed from").upcast(), cwd.upcast());
        add(label("Source IP").upcast(), label(&con.src_ip).upcast());
        add(self.check_ip.clone().upcast(), self.ip_dd.clone().upcast());
        if con.dst_port != 0 {
            add(
                self.check_port.clone().upcast(),
                label(&con.dst_port.to_string()).upcast(),
            );
        }
        add(self.check_uid.clone().upcast(), label(user).upcast());
        if !self.checksum.is_empty() {
            add(
                self.check_sum.clone().upcast(),
                label(&self.checksum).upcast(),
            );
        }
        let revealer = gtk::Revealer::new();
        revealer.set_child(Some(&grid));
        self.advanced
            .bind_property("active", &revealer, "reveal-child")
            .sync_create()
            .build();

        // Bottom row.
        let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let apply = gtk::Box::new(gtk::Orientation::Vertical, 6);
        apply.set_hexpand(true);
        let selectors = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        selectors.append(&self.what_dd);
        selectors.append(&self.duration_dd);
        apply.append(&selectors);
        actions.append(&apply);
        actions.append(&self.deny_btn);
        actions.append(&self.allow_btn);
        actions.append(&self.advanced);
        actions.set_valign(gtk::Align::End);

        let main = padded_box(14);
        main.append(&header);
        main.append(&message);
        if let Some(warning) = &warning {
            main.append(warning);
        }
        main.append(&revealer);
        main.append(&actions);

        // Details page.
        let text = gtk::Label::new(Some(&view::details_text(con, user)));
        text.set_xalign(0.0);
        text.set_yalign(0.0);
        text.set_selectable(true);
        text.set_wrap(true);
        text.set_wrap_mode(gtk::pango::WrapMode::Char);
        text.add_css_class("monospace");
        let scroll = gtk::ScrolledWindow::new();
        scroll.set_child(Some(&text));
        scroll.set_min_content_height(300);
        scroll.set_vexpand(true);
        let back = gtk::Button::with_label("Back");
        back.set_halign(gtk::Align::End);
        let details = padded_box(12);
        details.append(&scroll);
        details.append(&back);

        self.stack.add_named(&main, Some("main"));
        self.stack.add_named(&details, Some("details"));
        if !self.checks.mismatch.is_empty() {
            self.stack
                .add_named(&self.checksums_page(), Some("checksums"));
        }

        let bar = adw::HeaderBar::new();
        bar.set_show_end_title_buttons(false);
        bar.set_show_start_title_buttons(false);
        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&bar);
        toolbar.set_content(Some(&self.stack));
        self.window.set_content(Some(&toolbar));

        let d = self.clone();
        details_btn.connect_clicked(move |_| {
            d.stop_countdown();
            d.stack.set_visible_child_name("details");
        });
        let d = self.clone();
        back.connect_clicked(move |_| d.stack.set_visible_child_name("main"));

        // The Drop / Reject menu next to the deny button.
        let menu = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let popover = gtk::Popover::new();
        for action in [Action::Drop, Action::Reject] {
            let item = gtk::Button::with_label(action.label());
            item.add_css_class("flat");
            let (d, p) = (self.clone(), popover.clone());
            item.connect_clicked(move |_| {
                p.popdown();
                d.send_rule(action);
            });
            menu.append(&item);
        }
        popover.set_child(Some(&menu));
        self.deny_btn.set_popover(Some(&popover));
    }

    /// The red warning under the message, with a link to the checksums page.
    fn checksum_warning(self: &Rc<Self>) -> Option<gtk::Label> {
        if self.checks.mismatch.is_empty() {
            return None;
        }
        let warning = label("WARNING, bad checksum (<a href=\"#warning-checksum\">More info</a>)");
        warning.set_use_markup(true);
        warning.add_css_class("error");
        let d = self.clone();
        warning.connect_activate_link(move |_, _| {
            d.stop_countdown();
            d.stack.set_visible_child_name("checksums");
            gtk::glib::Propagation::Stop
        });
        *self.warning.borrow_mut() = Some(warning.clone());
        Some(warning)
    }

    /// Page to pin the program's current checksum in the rules that disagree.
    fn checksums_page(self: &Rc<Self>) -> gtk::Box {
        let note = label(&view::printable_lines(&checksum::note(
            &self.con,
            &self.checks.mismatch,
        )));
        note.set_selectable(true);
        note.set_wrap_mode(gtk::pango::WrapMode::Char);

        let back = gtk::Button::with_label("Back");
        let ui = ChecksumsUi {
            names: name_dropdown(&self.checks.mismatch.rule_names),
            status: label(""),
            buttons: gtk::Box::new(gtk::Orientation::Horizontal, 8),
            update: gtk::Button::with_label("Update rule"),
            update_all: gtk::Button::with_label("Update all"),
        };
        ui.buttons.set_halign(gtk::Align::End);
        for b in [&ui.update, &ui.update_all, &back] {
            ui.buttons.append(b);
        }

        // `update_all` asks for every rule still listed, `update` for the selected one.
        for (button, all) in [(&ui.update, false), (&ui.update_all, true)] {
            let (d, ui) = (self.clone(), ui.clone());
            button.connect_clicked(move |_| {
                let targets = if all {
                    list_names(&ui.names)
                } else {
                    selected_name(&ui.names).into_iter().collect()
                };
                if !targets.is_empty() {
                    d.update_rules(&ui, targets);
                }
            });
        }
        let d = self.clone();
        back.connect_clicked(move |_| d.stack.set_visible_child_name("main"));

        let page = padded_box(12);
        page.append(&note);
        page.append(&ui.names);
        page.append(&ui.status);
        page.append(&ui.buttons);
        page
    }

    /// Pins the program's checksum in `names` and reports the outcome on the page.
    ///
    /// Updated rules leave the list, so they aren't sent again; when none are
    /// left the warning goes away too.
    fn update_rules(self: &Rc<Self>, ui: &ChecksumsUi, names: Vec<String>) {
        let md5 = view::md5(&self.con).to_string();
        let updater = self.checks.updater.clone();
        let (d, ui) = (self.clone(), ui.clone());
        ui.status.remove_css_class("error");
        ui.status.remove_css_class("success");
        ui.status.set_text("Updating...");
        ui.buttons.set_sensitive(false);
        gtk::glib::spawn_future_local(async move {
            let outcome = match updater {
                Some(updater) => updater.update_checksums(names, md5).await,
                // Demo mode has no daemon: pretend it worked.
                None => Outcome {
                    updated: names,
                    error: None,
                },
            };
            remove_names(&ui.names, &outcome.updated);
            match &outcome.error {
                None => {
                    ui.status.add_css_class("success");
                    ui.status.set_text(&match outcome.updated.len() {
                        1 => "\u{2714} Rule updated.".to_string(),
                        n => format!("\u{2714} {n} rules updated."),
                    });
                }
                Some(err) => {
                    ui.status.add_css_class("error");
                    ui.status
                        .set_text(&format!("\u{2718} {}", view::printable(err)));
                }
            }
            ui.buttons.set_sensitive(true);
            if list_names(&ui.names).is_empty() {
                for b in [&ui.update, &ui.update_all] {
                    b.set_sensitive(false);
                }
                ui.names.set_sensitive(false);
                if let Some(warning) = d.warning.borrow().as_ref() {
                    warning.set_visible(false);
                }
            }
        });
    }

    /// Action of the deny button: the saved default unless that is "allow".
    fn deny_action(&self) -> Action {
        if self.default_action == Action::Allow {
            Action::Drop
        } else {
            self.default_action
        }
    }

    /// Refreshes the button texts, with the countdown on the default one.
    fn update_buttons(&self) {
        let text = |action: Action, is_default: bool| {
            if is_default && self.counting.get() {
                format!("{} ({})", action.label(), self.remaining.get())
            } else {
                action.label().to_string()
            }
        };
        let allow_is_default = self.default_action == Action::Allow;
        self.allow_btn
            .set_label(&text(Action::Allow, allow_is_default));
        self.deny_btn
            .set_label(&text(self.deny_action(), !allow_is_default));
    }

    /// Keeps the buttons as wide as they are with the countdown shown, so the
    /// window doesn't shrink when the countdown stops and the text gets shorter.
    fn lock_button_widths(&self) {
        let widgets = [
            self.allow_btn.clone().upcast::<gtk::Widget>(),
            self.deny_btn.clone().upcast::<gtk::Widget>(),
        ];
        for widget in widgets {
            let (_, natural, _, _) = widget.measure(gtk::Orientation::Horizontal, -1);
            widget.set_width_request(natural);
        }
    }

    fn stop_countdown(&self) {
        if self.counting.replace(false) {
            self.update_buttons();
        }
    }

    fn connect_signals(self: &Rc<Self>) {
        let d = self.clone();
        self.allow_btn
            .connect_clicked(move |_| d.send_rule(Action::Allow));
        let d = self.clone();
        self.deny_btn
            .connect_clicked(move |_| d.send_rule(d.deny_action()));

        // Any interaction stops the countdown.
        let d = self.clone();
        self.advanced.connect_toggled(move |b| {
            if b.is_active() {
                d.stop_countdown();
            }
        });
        for dd in [&self.what_dd, &self.ip_dd, &self.duration_dd] {
            let d = self.clone();
            dd.connect_selected_notify(move |_| d.stop_countdown());
        }
        for check in [
            &self.check_ip,
            &self.check_port,
            &self.check_uid,
            &self.check_sum,
        ] {
            let d = self.clone();
            check.connect_toggled(move |_| d.stop_countdown());
        }
        let click = gtk::GestureClick::new();
        click.set_propagation_phase(gtk::PropagationPhase::Capture);
        let d = self.clone();
        click.connect_pressed(move |_, _, _, _| d.stop_countdown());
        self.window.add_controller(click);

        // Escape is ignored, and closing the window answers with the current selection.
        let keys = gtk::EventControllerKey::new();
        keys.connect_key_pressed(|_, key, _, _| {
            if key == gtk::gdk::Key::Escape {
                gtk::glib::Propagation::Stop
            } else {
                gtk::glib::Propagation::Proceed
            }
        });
        self.window.add_controller(keys);
        let d = self.clone();
        self.window.connect_close_request(move |_| {
            d.send_rule(d.default_action);
            gtk::glib::Propagation::Stop
        });
    }

    /// Shows the window and starts the countdown / cancellation timer.
    fn start(self: &Rc<Self>, cancelled: impl Fn() -> bool + 'static) {
        self.advanced.grab_focus();
        self.window.present();
        let d = self.clone();
        gtk::glib::timeout_add_seconds_local(1, move || {
            if d.done.get() {
                return gtk::glib::ControlFlow::Break;
            }
            if cancelled() {
                d.finish(None);
                return gtk::glib::ControlFlow::Break;
            }
            if d.counting.get() && d.timeout > 0 {
                let left = d.remaining.get().saturating_sub(1);
                d.remaining.set(left);
                if left == 0 {
                    d.timed_out.set(true);
                    d.send_rule(d.default_action);
                    return gtk::glib::ControlFlow::Break;
                }
                d.update_buttons();
            }
            gtk::glib::ControlFlow::Continue
        });
    }

    /// Builds the rule from the current selection and answers the daemon.
    fn send_rule(&self, action: Action) {
        let index = |dd: &gtk::DropDown| usize::try_from(dd.selected()).unwrap_or(0);
        let rule = match (
            self.what.get(index(&self.what_dd)),
            self.ip.get(index(&self.ip_dd)),
        ) {
            (Some(target), Some(ip_target)) => {
                let choice = Choice {
                    action,
                    duration_idx: index(&self.duration_dd),
                    target,
                    ip_target,
                    check_ip: self.check_ip.is_active(),
                    check_port: self.check_port.is_active(),
                    check_uid: self.check_uid.is_active(),
                    check_sum: self.check_sum.is_active(),
                    checksum: &self.checksum,
                };
                rule::build_rule(&self.con, &choice, now_secs())
            }
            _ => None,
        };
        self.finish(rule);
    }

    fn finish(&self, rule: Option<Rule>) {
        if self.done.replace(true) {
            return;
        }
        // The channel has room for exactly this one answer.
        let _ = self.result.try_send(Answer {
            rule,
            timed_out: self.timed_out.get(),
        });
        self.window.destroy();
    }
}

/// Pins the window to a screen corner when the compositor supports layer-shell
/// (wlroots, KDE). Elsewhere the compositor decides where it goes.
fn place(window: &adw::Window, position: u32) {
    // layer-shell asserts on non-Wayland displays, so check before asking.
    let on_wayland =
        gtk::gdk::Display::default().is_some_and(|d| d.type_().name() == "GdkWaylandDisplay");
    // GNOME never implements layer-shell, and probing for it makes the library
    // print a notice about the session-lock protocol on every start.
    let on_gnome =
        std::env::var("XDG_CURRENT_DESKTOP").is_ok_and(|d| d.split(':').any(|p| p == "GNOME"));
    if !on_wayland || on_gnome || !gtk4_layer_shell::is_supported() {
        return;
    }
    window.init_layer_shell();
    window.set_layer(Layer::Overlay);
    window.set_keyboard_mode(KeyboardMode::OnDemand);
    window.set_namespace(Some("snitch"));
    let (vertical, horizontal) = match position {
        1 => (Some(Edge::Top), Some(Edge::Right)),
        2 => (Some(Edge::Bottom), Some(Edge::Right)),
        3 => (Some(Edge::Top), Some(Edge::Left)),
        4 => (Some(Edge::Bottom), Some(Edge::Left)),
        _ => (None, None),
    };
    for edge in [vertical, horizontal].into_iter().flatten() {
        window.set_anchor(edge, true);
        window.set_margin(edge, 24);
    }
}
