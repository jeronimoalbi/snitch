//! The window that lists the rules the daemon has loaded and lets the user add,
//! change, turn off and delete them.
//!
//! Signal handlers hold weak references to the window's state: a strong one
//! would be a cycle (state -> widget -> handler -> state) that never frees.

use std::cell::RefCell;
use std::rc::{Rc, Weak};

use adw::prelude::*;
use gtk::glib;
use gtk4 as gtk;
use libadwaita as adw;
use tokio::sync::watch;

use crate::dialog::{label, now_secs, padded_box};
use crate::draft::{self, ACTIONS, Condition, Draft, MATCH_KINDS, OPERANDS};
use crate::link::Updater;
use crate::model::operand;
use crate::proto::Rule;
use crate::view;

/// Window title. It also tells this window from the prompt.
const TITLE: &str = "Snitch rules";
const WIDTH: i32 = 720;
const HEIGHT: i32 = 560;
const LIST_PAGE: &str = "list";
const EDIT_PAGE: &str = "edit";
/// How often to look for temporary rules that ran out; the daemon doesn't say.
const EXPIRY_CHECK_SECS: u32 = 5;
const DELETE_RESPONSE: &str = "delete";
const CANCEL_RESPONSE: &str = "cancel";

/// Shows the rules window, reusing the one already open.
pub fn show(app: &adw::Application, updater: Updater) -> gtk::Window {
    let open = app
        .windows()
        .into_iter()
        .find(|w| w.title().as_deref() == Some(TITLE));
    if let Some(window) = open {
        window.present();
        return window;
    }
    let rules = Rules::new(app, updater);
    rules.window.present();
    rules.window.clone().upcast()
}

/// A dropdown showing labels and giving back the matching values.
struct Pick {
    dropdown: gtk::DropDown,
    values: Vec<String>,
}

impl Pick {
    /// Starts on `current`, which should be among `choices`.
    fn new(choices: Vec<(String, String)>, current: &str) -> Self {
        let (labels, values): (Vec<String>, Vec<String>) = choices
            .into_iter()
            .map(|(label, value)| (view::printable(&label), value))
            .unzip();
        let shown: Vec<&str> = labels.iter().map(String::as_str).collect();
        let pick = Self {
            dropdown: gtk::DropDown::from_strings(&shown),
            values,
        };
        pick.select(current);
        pick
    }

    fn select(&self, value: &str) {
        let position = self.values.iter().position(|v| v == value).unwrap_or(0);
        self.dropdown
            .set_selected(u32::try_from(position).unwrap_or(0));
    }

    fn value(&self) -> String {
        usize::try_from(self.dropdown.selected())
            .ok()
            .and_then(|i| self.values.get(i))
            .cloned()
            .unwrap_or_default()
    }
}

/// One line of the conditions in the form.
struct ConditionRow {
    widget: gtk::Box,
    operand: Pick,
    kind: Pick,
    data: gtk::Entry,
    remove: gtk::Button,
    /// Not in the form; carried over so saving keeps it.
    sensitive: bool,
}

impl ConditionRow {
    fn new(condition: &Condition) -> Rc<Self> {
        let operand = Pick::new(
            draft::choices(&OPERANDS, &condition.operand),
            &condition.operand,
        );
        let kind = Pick::new(
            draft::choices(&MATCH_KINDS, &condition.kind),
            &condition.kind,
        );
        let data = gtk::Entry::new();
        data.set_text(&condition.data);
        data.set_placeholder_text(Some("Value"));
        data.set_hexpand(true);
        let remove = gtk::Button::from_icon_name("list-remove-symbolic");
        remove.set_tooltip_text(Some("Remove this condition"));
        remove.add_css_class("flat");

        let widget = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        widget.append(&operand.dropdown);
        widget.append(&kind.dropdown);
        widget.append(&data);
        widget.append(&remove);

        let row = Rc::new(Self {
            widget,
            operand,
            kind,
            data,
            remove,
            sensitive: condition.sensitive,
        });
        row.sync_kind();
        row
    }

    /// Network matching and the destination network only go together.
    fn sync_kind(&self) {
        let operand = self.operand.value();
        if let Some(kind) = draft::forced_kind(&operand, &self.kind.value()) {
            self.kind.select(kind);
        }
        self.kind
            .dropdown
            .set_sensitive(operand != operand::DEST_NETWORK);
    }

    fn condition(&self) -> Condition {
        Condition {
            operand: self.operand.value(),
            kind: self.kind.value(),
            data: self.data.text().to_string(),
            sensitive: self.sensitive,
        }
    }
}

/// The form for adding or changing one rule.
struct Editor {
    /// The rule as it was when the form opened; `None` when adding.
    original: Option<Rule>,
    page: gtk::Box,
    name: gtk::Entry,
    description: gtk::Entry,
    enabled: gtk::CheckButton,
    precedence: gtk::CheckButton,
    nolog: gtk::CheckButton,
    action: Pick,
    duration: Pick,
    conditions: gtk::Box,
    rows: RefCell<Vec<Rc<ConditionRow>>>,
    error: gtk::Label,
    add_condition: gtk::Button,
    buttons: gtk::Box,
    save: gtk::Button,
    delete: gtk::Button,
    cancel: gtk::Button,
}

/// A check button already set to `active`.
fn check(text: &str, active: bool) -> gtk::CheckButton {
    let button = gtk::CheckButton::with_label(text);
    button.set_active(active);
    button
}

/// An entry already holding `text`.
fn entry(text: &str) -> gtk::Entry {
    let entry = gtk::Entry::new();
    entry.set_text(text);
    entry.set_hexpand(true);
    entry
}

impl Editor {
    fn new(draft: Draft) -> Rc<Self> {
        let editor = Rc::new(Self {
            page: gtk::Box::new(gtk::Orientation::Vertical, 0),
            name: entry(&draft.name),
            description: entry(&draft.description),
            enabled: check("Enabled", draft.enabled),
            precedence: check("Takes priority over other rules", draft.precedence),
            nolog: check("Don't log connections", draft.nolog),
            action: Pick::new(draft::choices(&ACTIONS, &draft.action), &draft.action),
            duration: Pick::new(
                draft::choices(&draft::durations(), &draft.duration),
                &draft.duration,
            ),
            conditions: gtk::Box::new(gtk::Orientation::Vertical, 6),
            rows: RefCell::default(),
            error: label(""),
            add_condition: gtk::Button::with_label("Add condition"),
            buttons: gtk::Box::new(gtk::Orientation::Horizontal, 8),
            save: gtk::Button::with_label("Save"),
            delete: gtk::Button::with_label("Delete"),
            cancel: gtk::Button::with_label("Cancel"),
            original: draft.original,
        });
        editor.build();
        for condition in &draft.conditions {
            editor.add_row(condition);
        }
        editor
    }

    fn form_grid(&self) -> gtk::Grid {
        let grid = gtk::Grid::new();
        grid.set_row_spacing(8);
        grid.set_column_spacing(12);
        let fields: [(&str, &gtk::Widget); 4] = [
            ("Name", self.name.upcast_ref()),
            ("Description", self.description.upcast_ref()),
            ("Action", self.action.dropdown.upcast_ref()),
            ("Duration", self.duration.dropdown.upcast_ref()),
        ];
        for (row, (title, widget)) in (0..).zip(fields) {
            grid.attach(&label(title), 0, row, 1, 1);
            grid.attach(widget, 1, row, 1, 1);
        }
        grid
    }

    fn build(self: &Rc<Self>) {
        self.save.add_css_class("suggested-action");
        self.delete.add_css_class("destructive-action");
        self.delete.set_visible(self.original.is_some());
        self.delete.set_hexpand(true);
        self.delete.set_halign(gtk::Align::Start);
        self.error.add_css_class("error");
        self.error.set_visible(false);
        self.add_condition.set_halign(gtk::Align::Start);
        for button in [&self.delete, &self.cancel, &self.save] {
            self.buttons.append(button);
        }

        let heading = label("Conditions (all must match)");
        heading.add_css_class("heading");
        let body = padded_box(12);
        body.append(&self.form_grid());
        for button in [&self.enabled, &self.precedence, &self.nolog] {
            body.append(button);
        }
        body.append(&heading);
        body.append(&self.conditions);
        body.append(&self.add_condition);
        let scroller = gtk::ScrolledWindow::new();
        scroller.set_vexpand(true);
        scroller.set_child(Some(&body));

        // Outside the scrolled part, so they can't end up out of sight.
        let footer = padded_box(8);
        footer.append(&self.error);
        footer.append(&self.buttons);
        self.page.append(&scroller);
        self.page.append(&footer);

        let weak = Rc::downgrade(self);
        self.add_condition.connect_clicked(move |_| {
            if let Some(editor) = weak.upgrade() {
                editor.add_row(&Condition::default());
            }
        });
    }

    fn add_row(self: &Rc<Self>, condition: &Condition) {
        let row = ConditionRow::new(condition);
        let weak_row = Rc::downgrade(&row);
        row.operand.dropdown.connect_selected_notify(move |_| {
            if let Some(row) = weak_row.upgrade() {
                row.sync_kind();
            }
        });
        let (weak_editor, weak_row) = (Rc::downgrade(self), Rc::downgrade(&row));
        row.remove.connect_clicked(move |_| {
            if let (Some(editor), Some(row)) = (weak_editor.upgrade(), weak_row.upgrade()) {
                editor.remove_row(&row);
            }
        });
        self.conditions.append(&row.widget);
        self.rows.borrow_mut().push(row);
    }

    fn remove_row(&self, row: &Rc<ConditionRow>) {
        self.conditions.remove(&row.widget);
        self.rows.borrow_mut().retain(|r| !Rc::ptr_eq(r, row));
    }

    /// What the form says right now.
    fn draft(&self) -> Draft {
        Draft {
            name: self.name.text().to_string(),
            description: self.description.text().to_string(),
            enabled: self.enabled.is_active(),
            precedence: self.precedence.is_active(),
            nolog: self.nolog.is_active(),
            action: self.action.value(),
            duration: self.duration.value(),
            conditions: self.rows.borrow().iter().map(|r| r.condition()).collect(),
            original: self.original.clone(),
        }
    }

    /// Shows why the rule wasn't saved, leaving the form open to fix it.
    fn fail(&self, message: &str) {
        self.error.set_text(&view::printable(message));
        self.error.set_visible(true);
        self.buttons.set_sensitive(true);
    }

    /// Blocks the buttons while the daemon answers.
    fn wait(&self) {
        self.error.set_visible(false);
        self.buttons.set_sensitive(false);
    }
}

/// The state of the window.
struct Rules {
    window: adw::Window,
    updater: Updater,
    stack: gtk::Stack,
    list: gtk::ListBox,
    search: gtk::SearchEntry,
    add: gtk::Button,
    notice: gtk::Label,
    /// Why the last switch of a rule didn't work.
    status: gtk::Label,
    /// The rules on screen, so an unchanged list isn't rebuilt.
    shown: RefCell<Vec<Rule>>,
    editor: RefCell<Option<Rc<Editor>>>,
}

/// Refreshes the window every time `changes` reports something, until it closes.
fn refresh_on_change<T: Send + Sync + 'static>(
    rules: Weak<Rules>,
    mut changes: watch::Receiver<T>,
) {
    glib::spawn_future_local(async move {
        while changes.changed().await.is_ok() {
            let Some(rules) = rules.upgrade() else {
                break;
            };
            rules.refresh();
        }
    });
}

impl Rules {
    fn new(app: &adw::Application, updater: Updater) -> Rc<Self> {
        let window = adw::Window::new();
        window.set_title(Some(TITLE));
        window.set_default_size(WIDTH, HEIGHT);
        window.set_application(Some(app));
        let rules = Rc::new(Self {
            window,
            updater,
            stack: gtk::Stack::new(),
            list: gtk::ListBox::new(),
            search: gtk::SearchEntry::new(),
            add: gtk::Button::with_label("Add rule"),
            notice: label("The daemon is not connected, so rules can't be changed."),
            status: label(""),
            shown: RefCell::default(),
            editor: RefCell::default(),
        });
        rules.build();
        rules.follow_changes();
        rules.refresh();
        rules
    }

    fn build(self: &Rc<Self>) {
        self.stack.add_named(&self.list_page(), Some(LIST_PAGE));
        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&adw::HeaderBar::new());
        toolbar.set_content(Some(&self.stack));
        self.window.set_content(Some(&toolbar));

        // The only strong reference outside short-lived work. It lives in a
        // cell so closing the window can let go of it.
        let keep_alive = RefCell::new(Some(self.clone()));
        self.window.connect_close_request(move |_| {
            keep_alive.take();
            glib::Propagation::Proceed
        });
    }

    fn list_page(self: &Rc<Self>) -> gtk::Box {
        self.search.set_hexpand(true);
        self.search.set_placeholder_text(Some("Search rules"));
        self.add.add_css_class("suggested-action");
        let top = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        top.append(&self.search);
        top.append(&self.add);

        self.list.add_css_class("boxed-list");
        self.list.set_selection_mode(gtk::SelectionMode::None);
        self.list.set_valign(gtk::Align::Start);
        self.list.set_placeholder(Some(&label("No rules")));
        let scroller = gtk::ScrolledWindow::new();
        scroller.set_vexpand(true);
        scroller.set_child(Some(&self.list));
        self.connect_list();

        self.notice.add_css_class("warning");
        self.status.add_css_class("error");
        let page = padded_box(12);
        page.append(&self.notice);
        page.append(&top);
        page.append(&scroller);
        page.append(&self.status);
        page
    }

    fn connect_list(self: &Rc<Self>) {
        let list = self.list.downgrade();
        self.search.connect_search_changed(move |_| {
            if let Some(list) = list.upgrade() {
                list.invalidate_filter();
            }
        });
        let search = self.search.downgrade();
        self.list.set_filter_func(move |row| {
            let query = search.upgrade().map(|s| s.text()).unwrap_or_default();
            row.downcast_ref::<adw::ActionRow>().is_none_or(|row| {
                let subtitle = row.subtitle().unwrap_or_default();
                view::matches_search(&query, &[row.title().as_str(), subtitle.as_str()])
            })
        });
        let weak = Rc::downgrade(self);
        self.add.connect_clicked(move |_| {
            if let Some(rules) = weak.upgrade() {
                rules.open_editor(Draft::default());
            }
        });
    }

    fn follow_changes(self: &Rc<Self>) {
        refresh_on_change(Rc::downgrade(self), self.updater.watch_rules());
        refresh_on_change(Rc::downgrade(self), self.updater.watch());
        let weak = Rc::downgrade(self);
        glib::timeout_add_seconds_local(EXPIRY_CHECK_SECS, move || match weak.upgrade() {
            Some(rules) => {
                rules.refresh();
                glib::ControlFlow::Continue
            }
            None => glib::ControlFlow::Break,
        });
    }

    /// Brings the window up to date with the daemon.
    fn refresh(self: &Rc<Self>) {
        let connected = self.updater.status().connected;
        self.notice.set_visible(!connected);
        self.add.set_sensitive(connected);
        self.list.set_sensitive(connected);

        let rules = draft::listed(self.updater.rules(), now_secs());
        if *self.shown.borrow() == rules {
            return;
        }
        while let Some(child) = self.list.first_child() {
            self.list.remove(&child);
        }
        for rule in &rules {
            self.list.append(&self.rule_row(rule));
        }
        *self.shown.borrow_mut() = rules;
    }

    fn rule_row(self: &Rc<Self>, rule: &Rule) -> adw::ActionRow {
        let row = adw::ActionRow::new();
        // Rule names and values come from programs and DNS answers.
        row.set_use_markup(false);
        row.set_title(&view::printable(&rule.name));
        row.set_subtitle(&view::rule_summary(rule));
        row.set_title_lines(1);
        row.set_subtitle_lines(1);
        row.set_activatable(true);

        let toggle = gtk::Switch::new();
        toggle.set_active(rule.enabled);
        toggle.set_valign(gtk::Align::Center);
        toggle.set_tooltip_text(Some("Rule enabled"));
        row.add_suffix(&toggle);

        let (weak, saved) = (Rc::downgrade(self), rule.clone());
        toggle.connect_active_notify(move |toggle| {
            if let Some(rules) = weak.upgrade() {
                rules.set_enabled(saved.clone(), toggle.is_active());
            }
        });
        let (weak, saved) = (Rc::downgrade(self), rule.clone());
        row.connect_activated(move |_| {
            if let Some(rules) = weak.upgrade() {
                rules.open_editor(Draft::from_rule(&saved));
            }
        });
        row
    }

    /// Turns a rule on or off; on failure the list goes back to the truth.
    fn set_enabled(self: &Rc<Self>, mut rule: Rule, enabled: bool) {
        rule.enabled = enabled;
        self.status.set_text("");
        let rules = self.clone();
        glib::spawn_future_local(async move {
            if let Err(err) = rules.updater.save_rule(None, rule).await {
                rules.status.set_text(&view::printable(&err));
                rules.shown.borrow_mut().clear();
                rules.refresh();
            }
        });
    }

    fn open_editor(self: &Rc<Self>, draft: Draft) {
        let editor = Editor::new(draft);
        self.on_click(&editor.save, Self::save);
        self.on_click(&editor.cancel, Self::close_editor);
        self.on_click(&editor.delete, Self::confirm_delete);
        self.stack.add_named(&editor.page, Some(EDIT_PAGE));
        self.stack.set_visible_child_name(EDIT_PAGE);
        *self.editor.borrow_mut() = Some(editor);
    }

    fn on_click(self: &Rc<Self>, button: &gtk::Button, action: impl Fn(&Rc<Self>) + 'static) {
        let weak = Rc::downgrade(self);
        button.connect_clicked(move |_| {
            if let Some(rules) = weak.upgrade() {
                action(&rules);
            }
        });
    }

    fn close_editor(self: &Rc<Self>) {
        self.stack.set_visible_child_name(LIST_PAGE);
        if let Some(editor) = self.editor.borrow_mut().take() {
            self.stack.remove(&editor.page);
        }
        self.refresh();
    }

    /// The open form. A shared handle, because it is used across an `await`
    /// and the `RefCell` must not stay borrowed that long.
    fn editor(&self) -> Option<Rc<Editor>> {
        self.editor.borrow().clone()
    }

    fn save(self: &Rc<Self>) {
        let Some(editor) = self.editor() else {
            return;
        };
        let rule = match editor.draft().to_rule(&self.updater.rules(), now_secs()) {
            Ok(rule) => rule,
            Err(err) => return editor.fail(&err),
        };
        let original = editor.original.as_ref().map(|r| r.name.clone());
        editor.wait();
        let rules = self.clone();
        glib::spawn_future_local(async move {
            match rules.updater.save_rule(original, rule).await {
                Ok(()) => rules.close_editor(),
                Err(err) => editor.fail(&err),
            }
        });
    }

    /// Asks before removing the rule being edited.
    fn confirm_delete(self: &Rc<Self>) {
        let Some(name) = self
            .editor()
            .and_then(|e| e.original.as_ref().map(|r| r.name.clone()))
        else {
            return;
        };
        let dialog = adw::MessageDialog::new(
            Some(&self.window),
            Some("Delete this rule?"),
            Some(&view::printable(&name)),
        );
        dialog.add_responses(&[(CANCEL_RESPONSE, "Cancel"), (DELETE_RESPONSE, "Delete")]);
        dialog.set_response_appearance(DELETE_RESPONSE, adw::ResponseAppearance::Destructive);
        dialog.set_default_response(Some(CANCEL_RESPONSE));
        dialog.set_close_response(CANCEL_RESPONSE);
        let weak = Rc::downgrade(self);
        dialog.connect_response(Some(DELETE_RESPONSE), move |_, _| {
            if let Some(rules) = weak.upgrade() {
                rules.delete(name.clone());
            }
        });
        dialog.present();
    }

    fn delete(self: &Rc<Self>, name: String) {
        let Some(editor) = self.editor() else {
            return;
        };
        editor.wait();
        let rules = self.clone();
        glib::spawn_future_local(async move {
            match rules.updater.delete_rule(name).await {
                Ok(()) => rules.close_editor(),
                Err(err) => editor.fail(&err),
            }
        });
    }
}
