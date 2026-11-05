//! Die Oberfläche: Sperrbildschirm, Seitenleiste, Tabs und alle Formulare.

use crate::config::{self, Config, Source};
use crate::keys;
use crate::ssh::{self, Cmd, Hop, HopAuth, Plan};
use crate::store::{AuthKind, ConnectionRec, KeyRec, KnownHost, PasswordChange, Store};
use crate::term::{self, Prompt, Shared, Status, ViewState};
use crate::theme::{self, Colors, TermPalette, ThemeChoice};
use crate::tray::{self, TrayHandle, TrayState};
use crate::vault::Dek;
use anyhow::{Context, Result, anyhow, bail};
use eframe::egui::{
    self, Align, Color32, CornerRadius, FontId, Frame, Key, Layout, Margin, Modifiers, RichText,
    Sense, Stroke, TextEdit, Ui, Vec2,
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

const MIN_PASSWORD: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Home,
    Editor,
    Keys,
    KnownHosts,
    Settings,
}

struct Session {
    id: u64,
    conn_id: i64,
    name: String,
    shared: Arc<Shared>,
    cmds: mpsc::UnboundedSender<Cmd>,
    abort: tokio::task::AbortHandle,
    view: ViewState,
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.cmds.send(Cmd::Close);
        self.abort.abort();
    }
}

struct Editor {
    rec: ConnectionRec,
    port: String,
    keepalive: String,
    password: Zeroizing<String>,
    clear_password: bool,
    error: Option<String>,
}

impl Editor {
    fn new(rec: ConnectionRec) -> Self {
        Self {
            port: rec.port.to_string(),
            keepalive: rec.keepalive_secs.to_string(),
            rec,
            password: Zeroizing::new(String::new()),
            clear_password: false,
            error: None,
        }
    }
}

#[derive(Default)]
struct KeyForm {
    generate: bool,
    name: String,
    pem: Zeroizing<String>,
    passphrase: Zeroizing<String>,
    save_passphrase: bool,
    path: String,
    error: Option<String>,
    /// Neuen Schlüssel direkt im offenen Verbindungseditor auswählen.
    for_editor: bool,
}

/// Ergebnis des Öffnens beim Programmstart.
pub struct StartDb {
    store: Store,
    problem: Option<DbProblem>,
}

/// Die Datenbank ist nicht verfügbar, etwa weil ein Laufwerk nicht eingehängt ist. Es wird bewusst
/// nicht still eine neue, leere Datenbank angelegt.
struct DbProblem {
    path: PathBuf,
    message: String,
    missing: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum DbMode {
    UseExisting,
    CopyCurrent,
    Empty,
}

struct DbDialog {
    path: PathBuf,
    exists: bool,
    error: Option<String>,
}

enum Confirm {
    DeleteConnection(i64, String),
    DeleteKey(i64, String, usize),
    CloseSession(u64, String),
    ForgetHost(String, u16),
}

#[derive(Default)]
struct PasswordForm {
    current: Zeroizing<String>,
    new: Zeroizing<String>,
    repeat: Zeroizing<String>,
    error: Option<String>,
}

pub struct App {
    store: Arc<Mutex<Store>>,
    rt: tokio::runtime::Runtime,
    ctx: egui::Context,
    dek: Option<Dek>,
    vault_exists: bool,
    lock_pw: Zeroizing<String>,
    lock_pw2: Zeroizing<String>,
    lock_error: Option<String>,
    lock_focus: bool,

    connections: Vec<ConnectionRec>,
    keys: Vec<KeyRec>,
    known_hosts: Vec<KnownHost>,

    search: String,
    page: Page,
    sessions: Vec<Session>,
    active: Option<u64>,
    next_session: u64,

    editor: Option<Editor>,
    key_form: Option<KeyForm>,
    file_rx: Option<std::sync::mpsc::Receiver<Option<std::path::PathBuf>>>,
    rename_key: Option<(i64, String)>,
    confirm: Option<Confirm>,
    password_form: PasswordForm,

    theme: ThemeChoice,
    font_size: f32,
    toast: Option<(String, bool, Instant)>,

    config: Config,
    config_path: PathBuf,
    db_source: Source,
    db_problem: Option<DbProblem>,
    db_form: String,
    db_dialog: Option<DbDialog>,
    db_file_rx: Option<std::sync::mpsc::Receiver<Option<PathBuf>>>,

    tray_state: Arc<TrayState>,
    tray: Option<TrayHandle>,
    tray_error: Option<String>,
    hide_on_close: bool,
    window_size: Vec2,
}

fn avatar_color(name: &str) -> Color32 {
    // Abgedunkelte Nord-Töne, auf denen der weiße Anfangsbuchstabe gut lesbar bleibt.
    const COLORS: [Color32; 8] = [
        Color32::from_rgb(0x5e, 0x81, 0xac),
        Color32::from_rgb(0xa8, 0x53, 0x5c),
        Color32::from_rgb(0xb3, 0x6d, 0x56),
        Color32::from_rgb(0x96, 0x7f, 0x4a),
        Color32::from_rgb(0x6f, 0x8b, 0x5c),
        Color32::from_rgb(0x4f, 0x87, 0x86),
        Color32::from_rgb(0x4c, 0x6f, 0x96),
        Color32::from_rgb(0x8c, 0x68, 0x87),
    ];
    let h = name.bytes().fold(7u32, |a, b| a.wrapping_mul(31).wrapping_add(b as u32));
    COLORS[h as usize % COLORS.len()]
}

/// Ermittelt die Jump-Kette (äußerste Station zuerst, Ziel zuletzt) und erkennt Schleifen.
pub fn resolve_chain(all: &[ConnectionRec], target: &ConnectionRec) -> Result<Vec<ConnectionRec>> {
    let by_id: HashMap<i64, &ConnectionRec> =
        all.iter().filter_map(|c| c.id.map(|id| (id, c))).collect();
    let mut chain = vec![target.clone()];
    let mut seen: Vec<i64> = target.id.into_iter().collect();
    let mut next = target.jump_id;
    while let Some(id) = next {
        if seen.contains(&id) {
            bail!("Die Jump-Hosts bilden eine Schleife.");
        }
        seen.push(id);
        let c = by_id.get(&id).ok_or_else(|| anyhow!("Der Jump-Host existiert nicht mehr."))?;
        chain.push((*c).clone());
        next = c.jump_id;
    }
    chain.reverse();
    Ok(chain)
}

/// Eingaben des Editors prüfen und in den Datensatz übernehmen.
fn validate(e: &mut Editor, all: &[ConnectionRec]) -> Result<()> {
    let r = &mut e.rec;
    r.name = r.name.trim().to_owned();
    r.host = r.host.trim().to_owned();
    r.username = r.username.trim().to_owned();
    r.group = r.group.trim().to_owned();
    if r.name.is_empty() {
        bail!("Bitte einen Verbindungsnamen eingeben.");
    }
    if r.host.is_empty() || r.host.contains(char::is_whitespace) {
        bail!("Bitte einen gültigen Host eingeben.");
    }
    r.port = match e.port.trim().parse::<u16>() {
        Ok(p) if p > 0 => p,
        _ => bail!("Der Port muss zwischen 1 und 65535 liegen."),
    };
    if r.username.is_empty() {
        bail!("Bitte einen Benutzernamen eingeben.");
    }
    r.keepalive_secs = e
        .keepalive
        .trim()
        .parse()
        .map_err(|_| anyhow!("Keepalive muss eine Zahl sein (Sekunden, 0 = aus)."))?;
    if r.auth == AuthKind::Key && r.key_id.is_none() {
        bail!("Bitte einen Schlüssel auswählen oder importieren.");
    }
    resolve_chain(all, r)?;
    Ok(())
}

fn soft_card(c: &Colors) -> Frame {
    Frame::new()
        .fill(c.panel)
        .stroke(Stroke::new(1.0, c.border))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(16))
}

fn primary_button(c: &Colors, text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_owned()).color(c.on_accent).strong())
        .fill(c.accent)
        .stroke(Stroke::NONE)
}

fn danger_button(c: &Colors, text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_owned()).color(c.danger))
}

fn modal(id: &str, c: &Colors) -> egui::Modal {
    egui::Modal::new(egui::Id::unique(id)).frame(
        Frame::new()
            .fill(c.panel)
            .stroke(Stroke::new(1.0, c.border))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::same(22)),
    )
}

/// Beschriftung über einem Formularfeld.
fn field_label(ui: &mut Ui, c: &Colors, text: &str) {
    ui.label(RichText::new(text).size(12.5).color(c.muted));
}

fn text_field(ui: &mut Ui, value: &mut String, hint: &str) -> egui::Response {
    ui.add(
        TextEdit::singleline(value)
            .hint_text(hint)
            .margin(Margin::symmetric(8, 6))
            .desired_width(f32::INFINITY),
    )
}

fn secret_field(ui: &mut Ui, value: &mut String, hint: &str) -> egui::Response {
    ui.add(
        TextEdit::singleline(value)
            .password(true)
            .hint_text(hint)
            .margin(Margin::symmetric(8, 6))
            .desired_width(f32::INFINITY),
    )
}

fn stored_font_size(store: &Store) -> f32 {
    store.get_setting("font_size").and_then(|s| s.parse().ok()).unwrap_or(14.0f32).clamp(9.0, 28.0)
}

/// Zwei Spalten nebeneinander; `frac` ist der Anteil der linken Spalte.
fn split(ui: &mut Ui, frac: f32, left: impl FnOnce(&mut Ui), right: impl FnOnce(&mut Ui)) {
    let gap = 12.0;
    let total = ui.available_width();
    let left_w = (total - gap) * frac;
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = gap;
        ui.vertical(|ui| {
            ui.set_width(left_w);
            left(ui);
        });
        ui.vertical(|ui| {
            ui.set_width(total - gap - left_w);
            right(ui);
        });
    });
}

impl App {
    /// Öffnet die Datenbank für den Programmstart. Ein Fehler führt zur Fehlerseite statt zum Abbruch,
    /// denn ein aus dem Menü gestartetes Programm hat keine sichtbare Konsole.
    pub fn open_start_db(path: PathBuf, source: Source) -> StartDb {
        let missing = source == Source::Config && !path.exists();
        let opened = if missing {
            Err(anyhow!("Die Datei wurde nicht gefunden."))
        } else {
            Store::open(&path)
        };
        match opened {
            Ok(store) => StartDb { store, problem: None },
            Err(e) => StartDb {
                store: Store::open_memory().expect("SQLite im Speicher"),
                problem: Some(DbProblem { path, message: format!("{e:#}"), missing }),
            },
        }
    }

    pub fn new(start: StartDb, config_path: PathBuf, config: Config, db_source: Source) -> Result<App> {
        let store = start.store;
        let theme_choice = store.get_setting("theme").map_or(ThemeChoice::Dark, |s| ThemeChoice::parse(&s));
        let font_size = stored_font_size(&store);
        let vault_exists = store.load_vault()?.is_some();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .context("Hintergrundthreads starten")?;
        let db_form = store.path().display().to_string();
        let mut app = App {
            store: Arc::new(Mutex::new(store)),
            rt,
            ctx: egui::Context::default(),
            dek: None,
            vault_exists,
            lock_pw: Zeroizing::new(String::new()),
            lock_pw2: Zeroizing::new(String::new()),
            lock_error: None,
            lock_focus: true,
            connections: Vec::new(),
            keys: Vec::new(),
            known_hosts: Vec::new(),
            search: String::new(),
            page: Page::Home,
            sessions: Vec::new(),
            active: None,
            next_session: 1,
            editor: None,
            key_form: None,
            file_rx: None,
            rename_key: None,
            confirm: None,
            password_form: PasswordForm::default(),
            theme: theme_choice,
            font_size,
            toast: None,
            config,
            config_path,
            db_source,
            db_problem: start.problem,
            db_form,
            db_dialog: None,
            db_file_rx: None,
            tray_state: TrayState::new(),
            tray: None,
            tray_error: None,
            hide_on_close: false,
            window_size: Vec2::new(1180.0, 760.0),
        };
        if app.config.close_to_tray {
            app.start_tray();
        }
        Ok(app)
    }

    /// Verbindet die App mit einem (neuen) Fenster.
    pub fn attach(&mut self, ctx: &egui::Context) {
        self.ctx = ctx.clone();
        theme::apply_style(ctx);
        theme::load_symbol_font(ctx);
        ctx.options_mut(|o| o.zoom_with_keyboard = false);
        self.apply_theme();
        self.hide_on_close = false;
        self.tray_state.set_ctx(Some(ctx.clone()));
        for s in &self.sessions {
            s.shared.set_repaint(Some(ctx.clone()));
        }
    }

    /// Das Fenster ist zu; bis zum nächsten gibt es nichts neu zu zeichnen.
    pub fn detach(&mut self) {
        self.tray_state.set_ctx(None);
        for s in &self.sessions {
            s.shared.set_repaint(None);
        }
    }

    pub fn tray_state(&self) -> &TrayState {
        &self.tray_state
    }

    /// Soll der Prozess nach dem Schließen des Fensters weiterlaufen?
    pub fn stay_in_tray(&self) -> bool {
        self.hide_on_close && self.tray_state.is_alive() && !self.tray_state.quit_requested()
    }

    pub fn window_size(&self) -> Vec2 {
        self.window_size
    }

    fn start_tray(&mut self) {
        // Die Tests sollen kein echtes Symbol in der Statusleiste erzeugen.
        if cfg!(test) {
            self.tray_state.set_alive(true);
            return;
        }
        if self.tray.is_some() {
            return;
        }
        match tray::start(&self.rt, &self.tray_state) {
            Ok(handle) => {
                self.tray = Some(handle);
                self.tray_error = None;
            }
            Err(e) => self.tray_error = Some(e),
        }
    }

    fn stop_tray(&mut self) {
        if let Some(handle) = self.tray.take() {
            handle.stop(&self.rt, &self.tray_state);
        }
        self.tray_state.set_alive(false);
        self.tray_error = None;
    }

    fn set_close_to_tray(&mut self, enabled: bool) {
        self.config.close_to_tray = enabled;
        if enabled {
            self.start_tray();
        } else {
            self.stop_tray();
        }
        let saved = self.config.save(&self.config_path);
        self.report(saved);
    }

    /// Fenster schließen, Statusleiste und Fenstergröße: läuft in jedem Frame, auch im gesperrten Zustand.
    fn handle_window_events(&mut self, ui: &Ui) {
        let ctx = ui.ctx();
        if let Some(rect) = ctx.input(|i| i.viewport().inner_rect) {
            self.window_size = rect.size();
        }
        if self.tray_state.quit_requested() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        } else if self.tray_state.take_show_request() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        if ctx.input(|i| i.viewport().close_requested()) {
            self.hide_on_close = self.config.close_to_tray;
        }
    }

    /// Macht `new` zur aktiven Datenbank; danach muss neu entsperrt werden.
    fn use_store(&mut self, new: Store) -> Result<()> {
        self.vault_exists = new.load_vault()?.is_some();
        self.theme = new.get_setting("theme").map_or(ThemeChoice::Dark, |s| ThemeChoice::parse(&s));
        self.font_size = stored_font_size(&new);
        self.db_form = new.path().display().to_string();
        *self.store.lock() = new;
        self.db_source = Source::Config;
        self.db_problem = None;
        self.db_dialog = None;
        self.page = Page::Home;
        self.apply_theme();
        self.lock();
        Ok(())
    }

    fn switch_db(&mut self, path: PathBuf, mode: DbMode) -> Result<()> {
        if !self.sessions.is_empty() {
            bail!("Bitte zuerst alle Tabs schließen.");
        }
        if mode == DbMode::CopyCurrent {
            self.store.lock().copy_to(&path)?;
        }
        let new = Store::open(&path)?;
        let mut config = self.config.clone();
        config.db_path = Some(path);
        config.save(&self.config_path)?;
        self.config = config;
        self.use_store(new)?;
        self.notify(
            match mode {
                DbMode::UseExisting => "Datenbank gewechselt. Bitte mit ihrem Master-Passwort entsperren.",
                DbMode::CopyCurrent => "Daten kopiert. Das Master-Passwort bleibt gleich; die alte Datei wurde nicht gelöscht.",
                DbMode::Empty => "Neue Datenbank angelegt. Bitte ein Master-Passwort festlegen.",
            },
            false,
        );
        Ok(())
    }

    /// Prüft die Eingabe aus den Einstellungen und fragt nach dem gewünschten Vorgehen.
    fn request_db_change(&mut self) {
        let result = config::normalize_db_path(&self.db_form);
        let Some(path) = self.report(result) else { return };
        if path == self.store.lock().path() {
            self.notify("Diese Datenbank wird bereits verwendet.", false);
            return;
        }
        let exists = path.exists();
        self.db_dialog = Some(DbDialog { path, exists, error: None });
    }

    fn ui_db_dialog(&mut self, ui: &mut Ui, c: &Colors) {
        let Some(dialog) = &self.db_dialog else { return };
        let (path, exists) = (dialog.path.clone(), dialog.exists);
        let error = dialog.error.clone();
        let mut chosen = None;
        let mut cancel = false;
        let ctx = ui.ctx().clone();
        modal("db_dialog", c).show(&ctx, |ui| {
            ui.set_width(480.0);
            ui.label(RichText::new("Datenbank wechseln").size(17.0).strong());
            ui.label(RichText::new(path.display().to_string()).monospace().size(12.5));
            if exists {
                ui.label("Diese Datei gibt es bereits. Sie wird geöffnet und nicht verändert. Zum Entsperren gilt ihr eigenes Master-Passwort.");
            } else {
                ui.label("Diese Datei gibt es noch nicht. Sollen die aktuellen Verbindungen und Schlüssel mitkommen?");
            }
            if let Some(e) = &error {
                ui.label(RichText::new(e).color(c.danger));
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if exists {
                    if ui.add(primary_button(c, "Diese Datenbank verwenden")).clicked() {
                        chosen = Some(DbMode::UseExisting);
                    }
                } else {
                    if ui.add(primary_button(c, "Daten dorthin kopieren")).clicked() {
                        chosen = Some(DbMode::CopyCurrent);
                    }
                    if ui.button("Leer beginnen").clicked() {
                        chosen = Some(DbMode::Empty);
                    }
                }
                cancel = ui.button("Abbrechen").clicked();
            });
        });
        if cancel {
            self.db_dialog = None;
        } else if let Some(mode) = chosen
            && let Err(e) = self.switch_db(path, mode)
            && let Some(d) = &mut self.db_dialog
        {
            d.error = Some(format!("{e:#}"));
        }
    }

    fn ui_db_problem(&mut self, ui: &mut Ui, c: &Colors) {
        let Some(problem) = &self.db_problem else { return };
        let path = problem.path.clone();
        let (message, missing) = (problem.message.clone(), problem.missing);
        let (mut retry, mut create, mut standard) = (false, false, false);
        let mut error = None;
        let config_file = self.config_path.display().to_string();
        ui.vertical_centered(|ui| {
            ui.add_space((ui.available_height() * 0.5 - 150.0).max(20.0));
            ui.set_max_width(560.0);
            soft_card(c).inner_margin(Margin::same(26)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.with_layout(Layout::top_down(Align::Min), |ui| {
                    ui.label(RichText::new("Datenbank nicht verfügbar").size(19.0).strong());
                    ui.label(RichText::new(path.display().to_string()).monospace().size(12.5));
                    ui.label(RichText::new(&message).color(c.danger));
                    if missing {
                        ui.label(RichText::new("Liegt sie auf einem Laufwerk, das noch nicht eingehängt ist? Sonst lässt sie sich hier neu anlegen.").color(c.muted));
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        retry = ui.add(primary_button(c, "Erneut versuchen")).clicked();
                        if missing {
                            create = ui.button("Hier neu anlegen").clicked();
                        }
                        standard = ui.button("Standardort verwenden").clicked();
                    });
                    ui.label(RichText::new(format!("Konfiguration: {config_file}")).size(12.0).color(c.muted));
                });
            });
        });
        if retry || create {
            match (if retry && !path.exists() { Err(anyhow!("Die Datei wurde nicht gefunden.")) } else { Store::open(&path) })
                .and_then(|new| self.use_store(new))
            {
                Ok(()) => {}
                Err(e) => error = Some(format!("{e:#}")),
            }
        }
        if standard {
            let result = (|| -> Result<()> {
                let mut config = self.config.clone();
                config.db_path = None;
                let (path, source) = config::resolve(None, &config)?;
                let new = Store::open(&path)?;
                config.save(&self.config_path)?;
                self.config = config;
                self.use_store(new)?;
                self.db_source = source;
                Ok(())
            })();
            if let Err(e) = result {
                error = Some(format!("{e:#}"));
            }
        }
        if let (Some(e), Some(p)) = (error, self.db_problem.as_mut()) {
            p.message = e;
        }
    }

    fn apply_theme(&self) {
        self.ctx.set_theme(match self.theme {
            ThemeChoice::System => egui::ThemePreference::System,
            ThemeChoice::Dark => egui::ThemePreference::Dark,
            ThemeChoice::Light => egui::ThemePreference::Light,
        });
    }

    fn notify(&mut self, text: impl Into<String>, error: bool) {
        self.toast = Some((text.into(), error, Instant::now()));
    }

    fn report<T>(&mut self, r: Result<T>) -> Option<T> {
        match r {
            Ok(v) => Some(v),
            Err(e) => {
                self.notify(format!("{e:#}"), true);
                None
            }
        }
    }

    fn reload(&mut self) {
        let loaded = {
            let s = self.store.lock();
            (|| Ok::<_, anyhow::Error>((s.connections()?, s.keys()?, s.known_hosts()?)))()
        };
        if let Some((c, k, h)) = self.report(loaded) {
            self.connections = c;
            self.keys = k;
            self.known_hosts = h;
        }
    }

    // --- Tresor ----------------------------------------------------------------------------

    fn submit_lock(&mut self) {
        self.lock_error = None;
        let result = (|| -> Result<Dek> {
            let mut store = self.store.lock();
            if let Some(wrapped) = store.load_vault()? {
                Dek::unlock(&self.lock_pw, &wrapped)?.ok_or_else(|| anyhow!("Das Passwort ist falsch."))
            } else {
                if self.lock_pw.chars().count() < MIN_PASSWORD {
                    bail!("Das Passwort muss mindestens {MIN_PASSWORD} Zeichen haben.");
                }
                if *self.lock_pw != *self.lock_pw2 {
                    bail!("Die Passwörter stimmen nicht überein.");
                }
                let (dek, wrapped) = Dek::create(&self.lock_pw)?;
                store.save_vault(&wrapped)?;
                Ok(dek)
            }
        })();
        match result {
            Ok(dek) => {
                self.dek = Some(dek);
                self.vault_exists = true;
                *self.lock_pw = String::new();
                *self.lock_pw2 = String::new();
                self.reload();
            }
            Err(e) => {
                self.lock_error = Some(format!("{e:#}"));
                self.lock_focus = true;
            }
        }
    }

    /// Sperrt die App. Laufende Sitzungen bleiben im Hintergrund verbunden.
    fn lock(&mut self) {
        self.dek = None;
        self.editor = None;
        self.key_form = None;
        self.rename_key = None;
        self.confirm = None;
        self.db_dialog = None;
        self.password_form = PasswordForm::default();
        self.lock_focus = true;
        self.connections.clear();
        self.keys.clear();
        self.known_hosts.clear();
    }

    fn ui_lock(&mut self, ui: &mut Ui, c: &Colors) {
        let creating = !self.vault_exists;
        let mut submit = false;
        ui.vertical_centered(|ui| {
            ui.add_space((ui.available_height() * 0.5 - 190.0).max(20.0));
            ui.set_max_width(400.0);
            soft_card(c).inner_margin(Margin::same(26)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("🔑").size(30.0).color(c.accent));
                ui.heading(if creating { "Willkommen bei SSHelf" } else { "SSHelf ist gesperrt" });
                ui.label(RichText::new(if creating {
                    "Lege ein Master-Passwort fest. Es verschlüsselt alle Schlüssel und Passwörter."
                } else {
                    "Gib dein Master-Passwort ein."
                }).color(c.muted));
                ui.add_space(8.0);
                ui.with_layout(Layout::top_down(Align::Min), |ui| {
                    field_label(ui, c, "Master-Passwort");
                    let r = secret_field(ui, &mut self.lock_pw, "");
                    if std::mem::take(&mut self.lock_focus) {
                        r.request_focus();
                    }
                    let enter = ui.input(|i| i.key_pressed(Key::Enter));
                    if creating {
                        field_label(ui, c, "Passwort wiederholen");
                        let r2 = secret_field(ui, &mut self.lock_pw2, "");
                        submit |= r2.lost_focus() && enter;
                    } else {
                        submit |= r.lost_focus() && enter;
                    }
                    if let Some(e) = &self.lock_error {
                        ui.label(RichText::new(e).color(c.danger));
                    }
                    ui.add_space(4.0);
                    let label = if creating { "Tresor anlegen" } else { "Entsperren" };
                    submit |= ui.add_sized([ui.available_width(), 34.0], primary_button(c, label)).clicked();
                    if creating {
                        ui.label(
                            RichText::new("Achtung: Ein vergessenes Master-Passwort kann nicht wiederhergestellt werden.")
                                .size(12.0)
                                .color(c.warning),
                        );
                    }
                });
            });
        });
        if submit {
            self.submit_lock();
        }
    }

    // --- Sitzungen -------------------------------------------------------------------------

    fn build_plan(&self, conn: &ConnectionRec) -> Result<Plan> {
        let dek = self.dek.as_ref().context("Tresor ist gesperrt")?;
        let store = self.store.lock();
        let chain = resolve_chain(&self.connections, conn)?;
        let mut hops = Vec::with_capacity(chain.len());
        for c in &chain {
            let auth = match c.auth {
                AuthKind::Agent => HopAuth::Agent(std::env::var_os("SSH_AUTH_SOCK").map(Into::into)),
                AuthKind::Interactive => HopAuth::Interactive,
                AuthKind::Password => HopAuth::Password(match c.id {
                    Some(id) => store.connection_password(id, dek)?,
                    None => None,
                }),
                AuthKind::Key => {
                    let id = c.key_id.ok_or_else(|| {
                        anyhow!("„{}“ hat keinen Schlüssel. Bitte in der Verbindung einen auswählen.", c.name)
                    })?;
                    let name = self.keys.iter().find(|k| k.id == id).map_or("?", |k| k.name.as_str());
                    let (pem, passphrase) = store.key_secret(id, dek)?;
                    HopAuth::Key { name: name.to_owned(), pem, passphrase }
                }
            };
            hops.push(Hop {
                label: c.name.clone(),
                host: c.host.clone(),
                port: c.port,
                username: c.username.clone(),
                auth,
                keepalive_secs: c.keepalive_secs,
            });
        }
        Ok(Plan { hops, startup_cmd: conn.startup_cmd.clone() })
    }

    fn start_session(&mut self, conn: &ConnectionRec, dark: bool) -> Result<u64> {
        let plan = self.build_plan(conn)?;
        let conn_id = conn.id.context("Verbindung ist nicht gespeichert")?;
        let (tx, rx) = mpsc::unbounded_channel();
        let shared = Shared::new(tx.clone(), self.ctx.clone(), dark);
        let abort = ssh::spawn(self.rt.handle(), plan, shared.clone(), self.store.clone(), rx);
        let id = self.next_session;
        self.next_session += 1;
        self.sessions.push(Session {
            id,
            conn_id,
            name: conn.name.clone(),
            shared,
            cmds: tx,
            abort,
            view: ViewState::default(),
        });
        let _ = self.store.lock().touch_connection(conn_id);
        Ok(id)
    }

    fn connect(&mut self, conn_id: i64, dark: bool) {
        let Some(conn) = self.connections.iter().find(|c| c.id == Some(conn_id)).cloned() else {
            return;
        };
        let started = self.start_session(&conn, dark);
        if let Some(id) = self.report(started) {
            self.active = Some(id);
            self.reload();
        }
    }

    /// Ersetzt eine beendete Sitzung im selben Tab durch eine neue.
    fn reconnect(&mut self, session_id: u64, dark: bool) {
        let Some(pos) = self.sessions.iter().position(|s| s.id == session_id) else { return };
        let conn_id = self.sessions[pos].conn_id;
        let Some(conn) = self.connections.iter().find(|c| c.id == Some(conn_id)).cloned() else {
            self.notify("Diese Verbindung gibt es nicht mehr.", true);
            return;
        };
        let started = self.start_session(&conn, dark);
        if let Some(id) = self.report(started) {
            let new = self.sessions.pop().expect("gerade angelegt");
            self.sessions[pos] = new;
            self.active = Some(id);
        }
    }

    fn close_session(&mut self, id: u64) {
        if let Some(pos) = self.sessions.iter().position(|s| s.id == id) {
            self.sessions.remove(pos);
            if self.active == Some(id) {
                self.active = self
                    .sessions
                    .get(pos)
                    .or_else(|| pos.checked_sub(1).and_then(|p| self.sessions.get(p)))
                    .map(|s| s.id);
            }
        }
    }

    fn request_close_session(&mut self, id: u64) {
        let Some(s) = self.sessions.iter().find(|s| s.id == id) else { return };
        if s.shared.status() == Status::Connected {
            self.confirm = Some(Confirm::CloseSession(id, s.name.clone()));
        } else {
            self.close_session(id);
        }
    }

    fn cycle_session(&mut self, delta: i32) {
        if self.sessions.is_empty() {
            return;
        }
        let n = self.sessions.len() as i32;
        let cur = self.active.and_then(|a| self.sessions.iter().position(|s| s.id == a)).unwrap_or(0) as i32;
        self.active = Some(self.sessions[(cur + delta).rem_euclid(n) as usize].id);
    }

    fn open_page(&mut self, page: Page) {
        self.page = page;
        self.active = None;
    }

    fn open_editor(&mut self, rec: ConnectionRec) {
        self.editor = Some(Editor::new(rec));
        self.open_page(Page::Editor);
    }

    // --- Seitenleiste ----------------------------------------------------------------------

    fn ui_sidebar(&mut self, ui: &mut Ui, c: &Colors, dark: bool) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("SSHelf").size(19.0).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add(primary_button(c, "+ Neu"))
                    .on_hover_text("Neue Verbindung anlegen")
                    .clicked()
                {
                    self.open_editor(ConnectionRec::default());
                }
            });
        });
        ui.add(
            TextEdit::singleline(&mut self.search)
                .hint_text("🔍 Suchen…")
                .margin(Margin::symmetric(8, 6))
                .desired_width(f32::INFINITY),
        );
        ui.add_space(2.0);

        let nav_height = 176.0;
        let list_height = (ui.available_height() - nav_height).max(60.0);
        egui::ScrollArea::vertical()
            .id_salt("connections")
            .max_height(list_height)
            .min_scrolled_height(list_height)
            .auto_shrink([false, false])
            .show(ui, |ui| self.ui_connection_list(ui, c, dark));

        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            let theme_label = format!("Design: {}", self.theme.label());
            if self.nav_item(ui, c, "🔒", "Sperren", false).clicked() {
                self.lock();
            }
            if self.nav_item(ui, c, "🌓", &theme_label, false).clicked() {
                self.theme = match self.theme {
                    ThemeChoice::Dark => ThemeChoice::Light,
                    ThemeChoice::Light => ThemeChoice::System,
                    ThemeChoice::System => ThemeChoice::Dark,
                };
                self.apply_theme();
                let _ = self.store.lock().set_setting("theme", self.theme.as_str());
            }
            let cur = if self.active.is_none() { Some(self.page) } else { None };
            if self.nav_item(ui, c, "⚙", "Einstellungen", cur == Some(Page::Settings)).clicked() {
                self.open_page(Page::Settings);
            }
            if self.nav_item(ui, c, "🖧", "Bekannte Hosts", cur == Some(Page::KnownHosts)).clicked() {
                self.open_page(Page::KnownHosts);
            }
            if self.nav_item(ui, c, "🔑", "Schlüssel", cur == Some(Page::Keys)).clicked() {
                self.open_page(Page::Keys);
            }
            ui.separator();
        });
    }

    fn nav_item(&self, ui: &mut Ui, c: &Colors, icon: &str, label: &str, selected: bool) -> egui::Response {
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 30.0), Sense::click());
        let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
        resp.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, label));
        if selected {
            ui.painter().rect_filled(rect, 7.0, c.accent_soft);
        } else if resp.hovered() {
            ui.painter().rect_filled(rect, 7.0, c.panel);
        }
        ui.painter().text(
            rect.left_center() + Vec2::new(10.0, 0.0),
            egui::Align2::LEFT_CENTER,
            icon,
            FontId::proportional(14.0),
            if selected { c.accent } else { c.text },
        );
        ui.painter().text(
            rect.left_center() + Vec2::new(34.0, 0.0),
            egui::Align2::LEFT_CENTER,
            label,
            FontId::proportional(14.0),
            c.text,
        );
        resp
    }

    fn ui_connection_list(&mut self, ui: &mut Ui, c: &Colors, dark: bool) {
        let query = self.search.to_lowercase();
        let visible: Vec<ConnectionRec> = self
            .connections
            .iter()
            .filter(|r| {
                query.is_empty()
                    || [&r.name, &r.host, &r.username, &r.group]
                        .iter()
                        .any(|s| s.to_lowercase().contains(&query))
            })
            .cloned()
            .collect();
        if visible.is_empty() {
            ui.add_space(12.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(if query.is_empty() {
                    "Noch keine Verbindungen"
                } else {
                    "Nichts gefunden"
                }).color(c.muted));
            });
            return;
        }
        let mut last_group: Option<&str> = None;
        for rec in &visible {
            if last_group != Some(rec.group.as_str()) {
                last_group = Some(rec.group.as_str());
                if !rec.group.is_empty() {
                    ui.add_space(4.0);
                    ui.label(RichText::new(rec.group.to_uppercase()).size(11.0).strong().color(c.muted));
                }
            }
            self.ui_connection_row(ui, c, rec, dark);
        }
    }

    fn ui_connection_row(&mut self, ui: &mut Ui, c: &Colors, rec: &ConnectionRec, dark: bool) {
        let id = rec.id.unwrap_or_default();
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 46.0), Sense::click());
        resp.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, rec.name.clone()));
        let open = self.sessions.iter().any(|s| {
            s.conn_id == id && s.shared.status() == Status::Connected
        });
        let selected = self.active.is_some_and(|a| self.sessions.iter().any(|s| s.id == a && s.conn_id == id));
        let hovered = ui.rect_contains_pointer(rect);
        if selected {
            ui.painter().rect_filled(rect, 8.0, c.accent_soft);
        } else if hovered {
            ui.painter().rect_filled(rect, 8.0, c.panel);
        }
        // Avatar
        let center = rect.left_center() + Vec2::new(22.0, 0.0);
        ui.painter().circle_filled(center, 15.0, avatar_color(&rec.name));
        let initial = rec.name.chars().next().unwrap_or('?').to_uppercase().to_string();
        ui.painter().text(center, egui::Align2::CENTER_CENTER, initial, FontId::proportional(14.0), Color32::WHITE);
        if open {
            let dot = center + Vec2::new(11.0, 11.0);
            ui.painter().circle(dot, 4.5, c.success, Stroke::new(1.5, c.sidebar));
        }
        // Text
        let text_x = rect.left() + 46.0;
        let right = if hovered { rect.right() - 100.0 } else { rect.right() - 6.0 };
        let painter = ui.painter().with_clip_rect(egui::Rect::from_min_max(
            egui::pos2(text_x, rect.top()),
            egui::pos2(right, rect.bottom()),
        ));
        painter.text(
            egui::pos2(text_x, rect.top() + 7.0),
            egui::Align2::LEFT_TOP,
            &rec.name,
            FontId::proportional(14.0),
            c.text,
        );
        let port = if rec.port == 22 { String::new() } else { format!(":{}", rec.port) };
        painter.text(
            egui::pos2(text_x, rect.top() + 25.0),
            egui::Align2::LEFT_TOP,
            format!("{}@{}{}", rec.username, rec.host, port),
            FontId::proportional(12.0),
            c.muted,
        );
        // Schnellaktionen bei Mausüber
        let mut action_clicked = false;
        if hovered {
            let size = Vec2::splat(28.0);
            let edit_rect = egui::Rect::from_center_size(rect.right_center() - Vec2::new(18.0, 0.0), size);
            let go_rect = egui::Rect::from_center_size(rect.right_center() - Vec2::new(78.0, 0.0), size);
            let edit_rect = edit_rect.translate(Vec2::new(-30.0, 0.0));
            let delete_rect = egui::Rect::from_center_size(rect.right_center() - Vec2::new(18.0, 0.0), size);
            let trash = RichText::new("🗑").color(c.danger);
            if ui.put(delete_rect, egui::Button::new(trash).frame(false)).on_hover_text("Löschen").clicked() {
                self.confirm = Some(Confirm::DeleteConnection(id, rec.name.clone()));
                action_clicked = true;
            }
            if ui.put(edit_rect, egui::Button::new("✏").frame(false)).on_hover_text("Bearbeiten").clicked() {
                self.open_editor(rec.clone());
                action_clicked = true;
            }
            if ui.put(go_rect, egui::Button::new("▶").frame(false)).on_hover_text("Verbinden").clicked() {
                self.connect(id, dark);
                action_clicked = true;
            }
        }
        if !action_clicked && resp.double_clicked() {
            self.connect(id, dark);
        } else if !action_clicked && resp.clicked() {
            // Ein Klick springt zu einem schon offenen Tab dieser Verbindung.
            if let Some(s) = self.sessions.iter().rev().find(|s| s.conn_id == id) {
                self.active = Some(s.id);
            }
        }
        resp.context_menu(|ui| {
            if ui.button("▶  Verbinden").clicked() {
                self.connect(id, dark);
                ui.close();
            }
            if ui.button("✏  Bearbeiten").clicked() {
                self.open_editor(rec.clone());
                ui.close();
            }
            if ui.button("📋  Duplizieren").clicked() {
                let r = self.store.lock().duplicate_connection(id);
                self.report(r);
                self.reload();
                ui.close();
            }
            ui.separator();
            if ui.add(danger_button(c, "🗑  Löschen")).clicked() {
                self.confirm = Some(Confirm::DeleteConnection(id, rec.name.clone()));
                ui.close();
            }
        });
    }

    // --- Tab-Leiste ------------------------------------------------------------------------

    fn ui_tabs(&mut self, ui: &mut Ui, c: &Colors) {
        let mut activate = None;
        let mut close = None;
        egui::ScrollArea::horizontal().id_salt("tabs").auto_shrink([false, true]).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                for s in &self.sessions {
                    let active = self.active == Some(s.id);
                    let status = s.shared.status();
                    let dot = match status {
                        Status::Connected => c.success,
                        Status::Connecting(_) => c.warning,
                        Status::Closed(_) => c.muted,
                        Status::Failed(_) => c.danger,
                    };
                    let width = ui.fonts_mut(|f| {
                        f.layout_no_wrap(s.name.clone(), FontId::proportional(13.5), c.text).size().x
                    }) + 62.0;
                    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, 32.0), Sense::click());
                    resp.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, s.name.clone()));
                    let hovered = ui.rect_contains_pointer(rect);
                    if active {
                        ui.painter().rect_filled(rect, 7.0, c.accent_soft);
                    } else if hovered {
                        ui.painter().rect_filled(rect, 7.0, c.panel);
                    }
                    ui.painter().circle_filled(rect.left_center() + Vec2::new(13.0, 0.0), 4.0, dot);
                    ui.painter().text(
                        rect.left_center() + Vec2::new(25.0, 0.0),
                        egui::Align2::LEFT_CENTER,
                        &s.name,
                        FontId::proportional(13.5),
                        c.text,
                    );
                    let close_rect = egui::Rect::from_center_size(rect.right_center() - Vec2::new(15.0, 0.0), Vec2::splat(22.0));
                    if ui
                        .put(close_rect, egui::Button::new(RichText::new("×").size(17.0)).frame(false))
                        .on_hover_text("Tab schließen (Strg+Umschalt+W)")
                        .clicked()
                    {
                        close = Some(s.id);
                    } else if resp.clicked() {
                        activate = Some(s.id);
                    }
                    if let Some(title) = s.shared.title() {
                        resp.on_hover_text(title);
                    }
                }
            });
        });
        if let Some(id) = activate {
            self.active = Some(id);
        }
        if let Some(id) = close {
            self.request_close_session(id);
        }
    }

    // --- Terminal-Bereich ------------------------------------------------------------------

    fn ui_session(&mut self, ui: &mut Ui, c: &Colors, id: u64, dark: bool, modal_open: bool) {
        let palette = TermPalette::for_mode(dark);
        let Some(idx) = self.sessions.iter().position(|s| s.id == id) else { return };
        let status = self.sessions[idx].shared.status();
        let mut reconnect = false;
        let mut close = false;

        match &status {
            Status::Connecting(msg) => {
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() * 0.38);
                    ui.spinner();
                    ui.label(RichText::new(msg).color(c.muted));
                });
            }
            Status::Failed(msg) => {
                ui.vertical_centered(|ui| {
                    ui.add_space((ui.available_height() * 0.5 - 120.0).max(16.0));
                    ui.set_max_width(560.0);
                    soft_card(c).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new("Verbindung fehlgeschlagen").size(17.0).strong().color(c.danger));
                        ui.add_space(4.0);
                        ui.label(msg);
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            reconnect = ui.add(primary_button(c, "Erneut versuchen")).clicked();
                            close = ui.button("Tab schließen").clicked();
                        });
                    });
                });
            }
            Status::Connected | Status::Closed(_) => {
                if let Status::Closed(msg) = &status {
                    egui::Panel::bottom(egui::IdSalt::new(("closed", id)))
                        .frame(Frame::new().fill(c.panel).inner_margin(Margin::symmetric(12, 6)))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(msg).color(c.muted));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    close = ui.button("Tab schließen").clicked();
                                    reconnect = ui.add(primary_button(c, "Neu verbinden")).clicked();
                                });
                            });
                        });
                }
                let focus_elsewhere = ui.memory(|m| m.focused().is_some());
                let session = &mut self.sessions[idx];
                let has_prompt = session.shared.prompt().is_some();
                let take_focus = !modal_open && !has_prompt && !focus_elsewhere
                    && status == Status::Connected;
                let shared = session.shared.clone();
                shared.set_dark(dark);
                let cmds = session.cmds.clone();
                term::show(ui, &shared, &cmds, &mut session.view, &palette, self.font_size, take_focus);
            }
        }
        if reconnect {
            self.reconnect(id, dark);
        } else if close {
            self.close_session(id);
        }
    }

    /// Rückfragen einer Sitzung (Hostschlüssel, Passwort, Passphrase, Einmalcode).
    fn ui_prompt(&mut self, ui: &mut Ui, c: &Colors, id: u64) {
        let Some(s) = self.sessions.iter().find(|s| s.id == id) else { return };
        let shared = s.shared.clone();
        let mut guard = shared.prompt();
        let Some(prompt) = guard.as_mut() else { return };
        let mut done: Option<bool> = None;
        let ctx = ui.ctx().clone();
        modal(&format!("prompt{id}"), c).show(&ctx, |ui| {
            ui.set_width(460.0);
            match prompt {
                Prompt::HostKey { host, port, algorithm, fingerprint, .. } => {
                    ui.label(RichText::new("Unbekannter Host").size(17.0).strong());
                    ui.label(format!("Zu {host}:{port} besteht noch keine vertrauenswürdige Verbindung."));
                    ui.label(RichText::new("Prüfe den Fingerabdruck, bevor du vertraust:").color(c.muted));
                    Frame::new().fill(c.surface).corner_radius(6).inner_margin(10).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new(algorithm.as_str()).size(12.0).color(c.muted));
                        ui.label(RichText::new(fingerprint.as_str()).monospace());
                    });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui.add(primary_button(c, "Vertrauen und verbinden")).clicked() {
                            done = Some(true);
                        }
                        if ui.button("Abbrechen").clicked() {
                            done = Some(false);
                        }
                    });
                }
                Prompt::Text { title, message, fields, .. } => {
                    ui.label(RichText::new(title.as_str()).size(17.0).strong());
                    if !message.trim().is_empty() {
                        ui.label(RichText::new(message.trim()).color(c.muted));
                    }
                    let mut enter_on_last = false;
                    let n = fields.len();
                    for (i, f) in fields.iter_mut().enumerate() {
                        field_label(ui, c, &f.label);
                        let value: &mut String = &mut f.value;
                        let r = ui.add(
                            TextEdit::singleline(value)
                                .password(!f.echo)
                                .margin(Margin::symmetric(8, 6))
                                .desired_width(f32::INFINITY),
                        );
                        if i == 0 && !ui.memory(|m| m.focused().is_some()) {
                            r.request_focus();
                        }
                        if i + 1 == n && r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                            enter_on_last = true;
                        }
                    }
                    ui.horizontal(|ui| {
                        if ui.add(primary_button(c, "OK")).clicked() || enter_on_last {
                            done = Some(true);
                        }
                        if ui.button("Abbrechen").clicked() {
                            done = Some(false);
                        }
                    });
                }
            }
        });
        if let Some(ok) = done
            && let Some(p) = guard.take()
        {
            match p {
                Prompt::HostKey { reply, .. } => {
                    let _ = reply.send(ok);
                }
                Prompt::Text { fields, reply, .. } => {
                    let values = ok.then(|| fields.into_iter().map(|f| f.value).collect());
                    let _ = reply.send(values);
                }
            }
        }
    }

    // --- Seiten ----------------------------------------------------------------------------

    fn page_frame(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
        egui::ScrollArea::vertical().id_salt("page").auto_shrink([false, false]).show(ui, |ui| {
            Frame::new().inner_margin(Margin::symmetric(28, 22)).show(ui, |ui| {
                ui.set_max_width(760.0);
                add(ui);
            });
        });
    }

    fn ui_home(&mut self, ui: &mut Ui, c: &Colors, dark: bool) {
        let mut recent: Vec<ConnectionRec> =
            self.connections.iter().filter(|r| r.last_used.is_some()).cloned().collect();
        recent.sort_by_key(|r| std::cmp::Reverse(r.last_used));
        recent.truncate(6);
        let mut go = None;
        let mut create = false;
        let empty = self.connections.is_empty();
        Self::page_frame(ui, |ui| {
            ui.heading("Willkommen");
            if empty {
                ui.label(RichText::new("Lege deine erste Verbindung an, um loszulegen.").color(c.muted));
                ui.add_space(8.0);
                create = ui.add(primary_button(c, "+ Neue Verbindung")).clicked();
            } else if recent.is_empty() {
                ui.label(RichText::new("Doppelklick auf eine Verbindung links öffnet sie in einem neuen Tab.").color(c.muted));
            } else {
                ui.label(RichText::new("Zuletzt verwendet").color(c.muted));
                ui.add_space(4.0);
                for r in &recent {
                    soft_card(c).inner_margin(Margin::symmetric(14, 10)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 2.0;
                                ui.label(RichText::new(&r.name).strong());
                                ui.label(RichText::new(format!("{}@{}:{}", r.username, r.host, r.port)).size(12.0).color(c.muted));
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.button("Verbinden").clicked() {
                                    go = r.id;
                                }
                            });
                        });
                    });
                }
            }
            ui.add_space(18.0);
            ui.label(RichText::new("Tastenkürzel im Terminal").strong());
            egui::Grid::new("shortcuts").num_columns(2).spacing([24.0, 6.0]).show(ui, |ui| {
                for (keys, what) in [
                    ("Strg+Umschalt+C / V", "Kopieren / Einfügen"),
                    ("Strg+Tab", "Nächster Tab"),
                    ("Strg+Umschalt+W", "Tab schließen"),
                    ("Umschalt+Bild↑ / Bild↓", "Im Verlauf blättern"),
                ] {
                    ui.label(RichText::new(keys).monospace().size(12.0));
                    ui.label(RichText::new(what).color(c.muted));
                    ui.end_row();
                }
            });
        });
        if create {
            self.open_editor(ConnectionRec::default());
        }
        if let Some(id) = go {
            self.connect(id, dark);
        }
    }

    fn ui_editor(&mut self, ui: &mut Ui, c: &Colors, dark: bool) {
        let Some(mut ed) = self.editor.take() else {
            self.page = Page::Home;
            return;
        };
        let mut save = false;
        let mut save_connect = false;
        let mut cancel = false;
        let mut import = false;
        let mut delete = None;
        let others: Vec<(i64, String)> = self
            .connections
            .iter()
            .filter(|o| o.id != ed.rec.id)
            .filter_map(|o| o.id.map(|id| (id, o.name.clone())))
            .collect();
        let key_list = self.keys.clone();
        // Eine alte Fehlermeldung verschwindet, sobald weitergetippt wird.
        if ui.input(|i| i.events.iter().any(|e| matches!(e, egui::Event::Text(_) | egui::Event::Paste(_)))) {
            ed.error = None;
        }

        // Die Aktionen bleiben immer sichtbar, das Formular darüber scrollt.
        egui::Panel::bottom("editor_actions")
            .frame(Frame::new().fill(c.sidebar).inner_margin(Margin::symmetric(28, 10)))
            .show(ui, |ui| {
                if let Some(e) = &ed.error {
                    ui.label(RichText::new(e).color(c.danger));
                }
                ui.horizontal(|ui| {
                    save_connect = ui.add(primary_button(c, "Speichern und verbinden")).clicked();
                    save = ui.button("Speichern").clicked();
                    cancel = ui.button("Abbrechen").clicked();
                    if let Some(id) = ed.rec.id {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.add(danger_button(c, "Verbindung löschen")).clicked() {
                                delete = Some((id, ed.rec.name.clone()));
                            }
                        });
                    }
                });
            });

        Self::page_frame(ui, |ui| {
            ui.heading(if ed.rec.id.is_some() { "Verbindung bearbeiten" } else { "Neue Verbindung" });
            ui.add_space(6.0);
            soft_card(c).show(ui, |ui| {
                ui.set_width(ui.available_width());
                split(ui, 0.62, |ui| {
                    field_label(ui, c, "Verbindungsname");
                    text_field(ui, &mut ed.rec.name, "z. B. Webserver Produktion");
                }, |ui| {
                    field_label(ui, c, "Gruppe (optional)");
                    text_field(ui, &mut ed.rec.group, "z. B. Kunde A");
                });
                split(ui, 0.62, |ui| {
                    field_label(ui, c, "Host");
                    text_field(ui, &mut ed.rec.host, "server.example.org oder 192.0.2.10");
                }, |ui| {
                    split(ui, 0.4, |ui| {
                        field_label(ui, c, "Port");
                        text_field(ui, &mut ed.port, "22");
                    }, |ui| {
                        field_label(ui, c, "Benutzer");
                        text_field(ui, &mut ed.rec.username, "root");
                    });
                });
            });
            ui.add_space(8.0);
            soft_card(c).show(ui, |ui| {
                ui.set_width(ui.available_width());
                field_label(ui, c, "Anmeldung");
                ui.horizontal(|ui| {
                    for kind in AuthKind::ALL {
                        ui.selectable_value(&mut ed.rec.auth, kind, kind.label());
                    }
                });
                match ed.rec.auth {
                    AuthKind::Key => {
                        field_label(ui, c, "Schlüssel");
                        ui.horizontal(|ui| {
                            let current = ed
                                .rec
                                .key_id
                                .and_then(|id| key_list.iter().find(|k| k.id == id))
                                .map_or("Bitte wählen…".to_owned(), |k| k.name.clone());
                            egui::ComboBox::from_id_salt("key")
                                .selected_text(current)
                                .width(300.0)
                                .show_ui(ui, |ui| {
                                    for k in &key_list {
                                        ui.selectable_value(&mut ed.rec.key_id, Some(k.id), &k.name);
                                    }
                                });
                            import = ui.button("Schlüssel hinzufügen…").clicked();
                        });
                        if let Some(k) = ed.rec.key_id.and_then(|id| key_list.iter().find(|k| k.id == id)) {
                            ui.label(RichText::new(format!("{}  ·  {}", k.algorithm, k.fingerprint)).size(12.0).color(c.muted));
                        }
                    }
                    AuthKind::Password => {
                        field_label(ui, c, "Passwort");
                        let hint = if ed.rec.has_password && !ed.clear_password {
                            "•••••••• (gespeichert – leer lassen zum Behalten)"
                        } else {
                            "Leer lassen, um beim Verbinden gefragt zu werden"
                        };
                        secret_field(ui, &mut ed.password, hint);
                        if ed.rec.has_password {
                            ui.checkbox(&mut ed.clear_password, "Gespeichertes Passwort entfernen");
                        }
                    }
                    AuthKind::Agent => {
                        ui.label(RichText::new("Verwendet die Schlüssel des laufenden SSH-Agenten (SSH_AUTH_SOCK).").color(c.muted));
                    }
                    AuthKind::Interactive => {
                        ui.label(RichText::new("Nichts speichern: Passwort oder Einmalcode werden beim Verbinden abgefragt.").color(c.muted));
                    }
                }
            });
            ui.add_space(8.0);
            soft_card(c).show(ui, |ui| {
                ui.set_width(ui.available_width());
                field_label(ui, c, "Jump-Host (optional)");
                let current = ed
                    .rec
                    .jump_id
                    .and_then(|id| others.iter().find(|(i, _)| *i == id))
                    .map_or("Direkt verbinden".to_owned(), |(_, n)| n.clone());
                egui::ComboBox::from_id_salt("jump").selected_text(current).width(300.0).show_ui(ui, |ui| {
                    ui.selectable_value(&mut ed.rec.jump_id, None, "Direkt verbinden");
                    for (id, n) in &others {
                        ui.selectable_value(&mut ed.rec.jump_id, Some(*id), n);
                    }
                });
                split(ui, 0.3, |ui| {
                    field_label(ui, c, "Keepalive in s (0 = aus)");
                    text_field(ui, &mut ed.keepalive, "30");
                }, |ui| {
                    field_label(ui, c, "Startbefehl (optional)");
                    text_field(ui, &mut ed.rec.startup_cmd, "z. B. tmux attach");
                });
                field_label(ui, c, "Notizen (optional)");
                ui.add(TextEdit::multiline(&mut ed.rec.notes).desired_rows(3).desired_width(f32::INFINITY).margin(Margin::symmetric(8, 6)));
            });
        });

        if let Some((id, name)) = delete {
            self.confirm = Some(Confirm::DeleteConnection(id, name));
        }
        if import {
            self.key_form = Some(KeyForm { for_editor: true, save_passphrase: true, ..Default::default() });
        }
        if cancel {
            self.page = Page::Home;
            return;
        }
        if save || save_connect {
            match self.save_editor(&mut ed) {
                Ok(id) => {
                    self.reload();
                    self.notify("Verbindung gespeichert", false);
                    self.page = Page::Home;
                    if save_connect {
                        self.connect(id, dark);
                    }
                    return;
                }
                Err(e) => ed.error = Some(format!("{e:#}")),
            }
        }
        self.editor = Some(ed);
    }

    fn save_editor(&mut self, ed: &mut Editor) -> Result<i64> {
        validate(ed, &self.connections)?;
        let dek = self.dek.as_ref().context("Tresor ist gesperrt")?;
        let change = if ed.rec.auth == AuthKind::Password && !ed.password.is_empty() {
            PasswordChange::Set(ed.password.clone())
        } else if ed.clear_password {
            PasswordChange::Clear
        } else {
            PasswordChange::Keep
        };
        self.store.lock().save_connection(&ed.rec, change, dek)
    }

    fn ui_keys(&mut self, ui: &mut Ui, c: &Colors) {
        let list = self.keys.clone();
        let usage = |id: i64, conns: &[ConnectionRec]| conns.iter().filter(|r| r.key_id == Some(id)).count();
        let conns = self.connections.clone();
        let mut new_form = None;
        let mut copy = None;
        let mut del = None;
        let mut rename = None;
        Self::page_frame(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Schlüssel");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(primary_button(c, "Importieren…")).clicked() {
                        new_form = Some(false);
                    }
                    if ui.button("Neu erzeugen…").clicked() {
                        new_form = Some(true);
                    }
                });
            });
            ui.label(RichText::new("Private Schlüssel liegen verschlüsselt in der Datenbank.").color(c.muted));
            ui.add_space(6.0);
            if list.is_empty() {
                ui.label(RichText::new("Noch keine Schlüssel gespeichert.").color(c.muted));
            }
            for k in &list {
                soft_card(c).inner_margin(Margin::symmetric(14, 12)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&k.name).strong());
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.add(danger_button(c, "Löschen")).clicked() {
                                del = Some((k.id, k.name.clone(), usage(k.id, &conns)));
                            }
                            if ui.button("Umbenennen").clicked() {
                                rename = Some((k.id, k.name.clone()));
                            }
                            if ui.button("Öffentlichen Schlüssel kopieren").clicked() {
                                copy = Some(k.public_key.clone());
                            }
                        });
                    });
                    ui.label(RichText::new(&k.fingerprint).monospace().size(12.0).color(c.muted));
                    let protection = match (k.encrypted, k.has_passphrase) {
                        (false, _) => "ohne Passphrase",
                        (true, true) => "Passphrase gespeichert",
                        (true, false) => "Passphrase wird beim Verbinden abgefragt",
                    };
                    let n = usage(k.id, &conns);
                    ui.label(RichText::new(format!("{}  ·  {protection}  ·  {n} Verbindung(en)", k.algorithm)).size(12.0).color(c.muted));
                });
                ui.add_space(4.0);
            }
        });
        if let Some(generate) = new_form {
            self.key_form = Some(KeyForm { generate, save_passphrase: true, ..Default::default() });
        }
        if let Some(text) = copy {
            ui.ctx().copy_text(text);
            self.notify("Öffentlicher Schlüssel kopiert", false);
        }
        if let Some((id, name, n)) = del {
            self.confirm = Some(Confirm::DeleteKey(id, name, n));
        }
        if rename.is_some() {
            self.rename_key = rename;
        }
    }

    fn ui_known_hosts(&mut self, ui: &mut Ui, c: &Colors) {
        let list = self.known_hosts.clone();
        let mut forget = None;
        Self::page_frame(ui, |ui| {
            ui.heading("Bekannte Hosts");
            ui.label(RichText::new("Hostschlüssel, denen du beim Verbinden vertraut hast. Ändert sich einer, wird die Verbindung blockiert.").color(c.muted));
            ui.add_space(6.0);
            if list.is_empty() {
                ui.label(RichText::new("Noch keine Einträge.").color(c.muted));
            }
            for h in &list {
                soft_card(c).inner_margin(Margin::symmetric(14, 10)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            ui.label(RichText::new(format!("{}:{}", h.host, h.port)).strong());
                            ui.label(RichText::new(format!("{}  {}", h.algorithm, h.fingerprint)).monospace().size(11.5).color(c.muted));
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.add(danger_button(c, "Entfernen")).clicked() {
                                forget = Some((h.host.clone(), h.port));
                            }
                        });
                    });
                });
                ui.add_space(4.0);
            }
        });
        if let Some((h, p)) = forget {
            self.confirm = Some(Confirm::ForgetHost(h, p));
        }
    }

    fn ui_settings(&mut self, ui: &mut Ui, c: &Colors) {
        let mut theme_changed = false;
        let mut font_changed = false;
        let mut change_pw = false;
        let db_path = self.store.lock().path().display().to_string();
        if let Some(rx) = &self.db_file_rx
            && let Ok(picked) = rx.try_recv()
        {
            self.db_file_rx = None;
            if let Some(path) = picked {
                self.db_form = path.display().to_string();
            }
        }
        let has_sessions = !self.sessions.is_empty();
        let from_cli = self.db_source == Source::Cli;
        let config_file = self.config_path.display().to_string();
        let picking = self.db_file_rx.is_some();
        let mut close_to_tray = self.config.close_to_tray;
        let tray_problem = self.config.close_to_tray && !self.tray_state.is_alive();
        let tray_error = self.tray_error.clone();
        let (mut tray_changed, mut apply_db, mut pick_db, mut standard_db) = (false, false, false, false);
        let db_form = &mut self.db_form;
        let mut theme_choice = self.theme;
        let mut font_size = self.font_size;
        let form = &mut self.password_form;
        Self::page_frame(ui, |ui| {
            ui.heading("Einstellungen");
            ui.add_space(6.0);
            soft_card(c).show(ui, |ui| {
                ui.set_width(ui.available_width());
                field_label(ui, c, "Design");
                ui.horizontal(|ui| {
                    for t in [ThemeChoice::Dark, ThemeChoice::Light, ThemeChoice::System] {
                        theme_changed |= ui.selectable_value(&mut theme_choice, t, t.label()).changed();
                    }
                });
                field_label(ui, c, "Schriftgröße im Terminal");
                font_changed = ui.add(egui::Slider::new(&mut font_size, 9.0..=28.0).step_by(1.0)).changed();
            });
            ui.add_space(8.0);
            soft_card(c).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Fenster").strong());
                tray_changed = ui.checkbox(&mut close_to_tray, "Beim Schließen in die Statusleiste minimieren").changed();
                ui.label(RichText::new("Das Fenster verschwindet, Verbindungen bleiben bestehen. Beenden geht dann über das Menü des Symbols. Der Tresor bleibt dabei entsperrt.").size(12.5).color(c.muted));
                if tray_problem {
                    let detail = tray_error.as_deref().map_or(String::new(), |e| format!(" ({e})"));
                    ui.label(RichText::new(format!(
                        "Es steht gerade keine Statusleiste bereit, das Schließen beendet die Anwendung{detail}. Unter GNOME ist dafür die Erweiterung „AppIndicator“ nötig."
                    )).size(12.5).color(c.warning));
                }
            });
            ui.add_space(8.0);
            soft_card(c).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Datenbank").strong());
                field_label(ui, c, "Aktuell verwendet");
                ui.label(RichText::new(&db_path).monospace().size(12.0));
                field_label(ui, c, "Neuer Pfad");
                text_field(ui, db_form, "/pfad/zur/sshelf.db");
                ui.horizontal(|ui| {
                    apply_db = ui.add_enabled(!has_sessions, primary_button(c, "Datenbank wechseln…")).clicked();
                    pick_db = ui.add_enabled(!picking, egui::Button::new("Durchsuchen…")).clicked();
                    standard_db = ui.button("Standardort eintragen").clicked();
                });
                if has_sessions {
                    ui.label(RichText::new("Zum Wechseln zuerst alle Tabs schließen.").size(12.5).color(c.warning));
                }
                if from_cli {
                    ui.label(RichText::new("Gestartet mit --db: Das hat beim Start Vorrang vor dieser Einstellung.").size(12.5).color(c.warning));
                }
                ui.label(RichText::new(format!(
                    "Gespeichert in {config_file} (Abschnitt [database], Schlüssel path). Verschlüsselt sind Schlüssel und Passwörter; Namen, Hosts und Benutzer sind lesbar."
                )).size(12.5).color(c.muted));
            });
            ui.add_space(8.0);
            soft_card(c).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Master-Passwort ändern").strong());
                field_label(ui, c, "Aktuelles Passwort");
                secret_field(ui, &mut form.current, "");
                field_label(ui, c, "Neues Passwort");
                secret_field(ui, &mut form.new, "");
                field_label(ui, c, "Neues Passwort wiederholen");
                secret_field(ui, &mut form.repeat, "");
                if let Some(e) = &form.error {
                    ui.label(RichText::new(e).color(c.danger));
                }
                change_pw = ui.button("Passwort ändern").clicked();
            });
        });
        if tray_changed {
            self.set_close_to_tray(close_to_tray);
        }
        if apply_db {
            self.request_db_change();
        }
        if standard_db {
            let result = config::default_db_path();
            if let Some(path) = self.report(result) {
                self.db_form = path.display().to_string();
            }
        }
        if pick_db {
            let (tx, rx) = std::sync::mpsc::channel();
            let repaint = ui.ctx().clone();
            std::thread::spawn(move || {
                let _ = tx.send(rfd::FileDialog::new().set_title("Datenbank wählen").pick_file());
                repaint.request_repaint();
            });
            self.db_file_rx = Some(rx);
        }
        if theme_changed {
            self.theme = theme_choice;
            self.apply_theme();
            let _ = self.store.lock().set_setting("theme", self.theme.as_str());
        }
        if font_changed {
            self.font_size = font_size;
            let _ = self.store.lock().set_setting("font_size", &font_size.to_string());
        }
        if change_pw {
            match self.change_password() {
                Ok(()) => {
                    self.password_form = PasswordForm::default();
                    self.notify("Master-Passwort geändert", false);
                }
                Err(e) => self.password_form.error = Some(format!("{e:#}")),
            }
        }
    }

    fn change_password(&mut self) -> Result<()> {
        let f = &self.password_form;
        if f.new.chars().count() < MIN_PASSWORD {
            bail!("Das neue Passwort muss mindestens {MIN_PASSWORD} Zeichen haben.");
        }
        if *f.new != *f.repeat {
            bail!("Die neuen Passwörter stimmen nicht überein.");
        }
        let mut store = self.store.lock();
        let current = store.load_vault()?.context("Kein Tresor vorhanden")?;
        if Dek::unlock(&f.current, &current)?.is_none() {
            bail!("Das aktuelle Passwort ist falsch.");
        }
        let dek = self.dek.as_ref().context("Tresor ist gesperrt")?;
        store.save_vault(&dek.wrap(&f.new)?)
    }

    // --- Dialoge ---------------------------------------------------------------------------

    fn ui_key_dialog(&mut self, ui: &mut Ui, c: &Colors) {
        // Ergebnis des Dateidialogs abholen.
        if let Some(rx) = &self.file_rx
            && let Ok(picked) = rx.try_recv()
        {
            self.file_rx = None;
            if let (Some(path), Some(form)) = (picked, self.key_form.as_mut()) {
                form.path = path.display().to_string();
                load_key_file(form);
            }
        }
        let Some(mut form) = self.key_form.take() else { return };
        let mut close = false;
        let mut submit = false;
        let mut pick = false;
        let ctx = ui.ctx().clone();
        modal("key_form", c).show(&ctx, |ui| {
            ui.set_width(520.0);
            ui.label(RichText::new(if form.generate { "Neuen Schlüssel erzeugen" } else { "Schlüssel importieren" }).size(17.0).strong());
            ui.horizontal(|ui| {
                ui.selectable_value(&mut form.generate, false, "Importieren");
                ui.selectable_value(&mut form.generate, true, "Neu erzeugen (Ed25519)");
            });
            field_label(ui, c, "Name");
            text_field(ui, &mut form.name, "z. B. Laptop 2026");
            if !form.generate {
                field_label(ui, c, "Datei");
                ui.horizontal(|ui| {
                    let w = ui.available_width() - 196.0;
                    ui.add(TextEdit::singleline(&mut form.path).hint_text("~/.ssh/id_ed25519").margin(Margin::symmetric(8, 6)).desired_width(w));
                    if ui.button("Laden").clicked() {
                        load_key_file(&mut form);
                    }
                    pick = ui.add_enabled(self.file_rx.is_none(), egui::Button::new("Durchsuchen…")).clicked();
                });
                field_label(ui, c, "Privater Schlüssel (oder hier einfügen)");
                let pem: &mut String = &mut form.pem;
                egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                    ui.add(
                        TextEdit::multiline(pem)
                            .font(egui::TextStyle::Monospace)
                            .hint_text("-----BEGIN OPENSSH PRIVATE KEY-----")
                            .desired_rows(6)
                            .desired_width(f32::INFINITY)
                            .margin(Margin::symmetric(8, 6)),
                    );
                });
                field_label(ui, c, "Passphrase (falls der Schlüssel geschützt ist)");
                secret_field(ui, &mut form.passphrase, "");
                ui.checkbox(&mut form.save_passphrase, "Passphrase verschlüsselt speichern");
            } else {
                ui.label(RichText::new("Der öffentliche Schlüssel kann danach kopiert und auf dem Server in ~/.ssh/authorized_keys eingetragen werden.").color(c.muted));
            }
            if let Some(e) = &form.error {
                ui.label(RichText::new(e).color(c.danger));
            }
            ui.horizontal(|ui| {
                submit = ui.add(primary_button(c, if form.generate { "Erzeugen" } else { "Importieren" })).clicked();
                close = ui.button("Abbrechen").clicked();
            });
        });
        if pick {
            let (tx, rx) = std::sync::mpsc::channel();
            let repaint = ctx.clone();
            std::thread::spawn(move || {
                let mut dialog = rfd::FileDialog::new().set_title("Privaten Schlüssel wählen");
                if let Some(home) = std::env::var_os("HOME") {
                    dialog = dialog.set_directory(std::path::Path::new(&home).join(".ssh"));
                }
                let _ = tx.send(dialog.pick_file());
                repaint.request_repaint();
            });
            self.file_rx = Some(rx);
        }
        if close {
            return;
        }
        if submit {
            match self.finish_key_form(&form) {
                Ok(id) => {
                    self.reload();
                    if form.for_editor
                        && let Some(ed) = self.editor.as_mut()
                    {
                        ed.rec.key_id = Some(id);
                    }
                    self.notify("Schlüssel gespeichert", false);
                    return;
                }
                Err(e) => form.error = Some(format!("{e:#}")),
            }
        }
        self.key_form = Some(form);
    }

    fn finish_key_form(&self, form: &KeyForm) -> Result<i64> {
        let new = if form.generate {
            keys::generate(&form.name)?
        } else {
            keys::prepare_import(&form.name, &form.pem, &form.passphrase, form.save_passphrase)?
        };
        let dek = self.dek.as_ref().context("Tresor ist gesperrt")?;
        self.store.lock().insert_key(&new, dek)
    }

    fn ui_rename_dialog(&mut self, ui: &mut Ui, c: &Colors) {
        let Some((id, mut name)) = self.rename_key.take() else { return };
        let mut save = false;
        let mut cancel = false;
        let ctx = ui.ctx().clone();
        modal("rename_key", c).show(&ctx, |ui| {
            ui.set_width(360.0);
            ui.label(RichText::new("Schlüssel umbenennen").size(17.0).strong());
            text_field(ui, &mut name, "");
            ui.horizontal(|ui| {
                save = ui.add(primary_button(c, "Speichern")).clicked();
                cancel = ui.button("Abbrechen").clicked();
            });
        });
        if cancel {
            return;
        }
        if save && !name.trim().is_empty() {
            let r = self.store.lock().rename_key(id, name.trim());
            self.report(r);
            self.reload();
            return;
        }
        self.rename_key = Some((id, name));
    }

    fn ui_confirm(&mut self, ui: &mut Ui, c: &Colors) {
        let Some(confirm) = self.confirm.take() else { return };
        let (title, text, action): (&str, String, &str) = match &confirm {
            Confirm::DeleteConnection(id, n) => {
                let mut text = format!("„{n}“ wird dauerhaft gelöscht.");
                let dependents: Vec<&str> = self
                    .connections
                    .iter()
                    .filter(|r| r.jump_id == Some(*id))
                    .map(|r| r.name.as_str())
                    .collect();
                if !dependents.is_empty() {
                    text += &format!(
                        "\n\nAchtung: {} nutzt diese Verbindung als Jump-Host und verbindet danach direkt.",
                        dependents.join(", ")
                    );
                }
                if self.sessions.iter().any(|s| s.conn_id == *id) {
                    text += "\n\nOffene Tabs bleiben verbunden, können danach aber nicht neu verbinden.";
                }
                ("Verbindung löschen?", text, "Löschen")
            }
            Confirm::DeleteKey(_, n, used) => (
                "Schlüssel löschen?",
                if *used > 0 {
                    format!("„{n}“ wird dauerhaft gelöscht. {used} Verbindung(en) verwenden ihn und brauchen danach einen anderen Schlüssel.")
                } else {
                    format!("„{n}“ wird dauerhaft gelöscht.")
                },
                "Löschen",
            ),
            Confirm::CloseSession(_, n) => ("Tab schließen?", format!("Die Verbindung „{n}“ ist noch aktiv und wird getrennt."), "Trennen"),
            Confirm::ForgetHost(h, p) => ("Eintrag entfernen?", format!("Beim nächsten Verbinden mit {h}:{p} wird der Fingerabdruck erneut abgefragt."), "Entfernen"),
        };
        let mut yes = false;
        let mut no = false;
        let ctx = ui.ctx().clone();
        modal("confirm", c).show(&ctx, |ui| {
            ui.set_width(400.0);
            ui.label(RichText::new(title).size(17.0).strong());
            ui.label(text);
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                yes = ui.add(egui::Button::new(RichText::new(action).color(c.on_accent).strong()).fill(c.danger).stroke(Stroke::NONE)).clicked();
                no = ui.button("Abbrechen").clicked();
            });
        });
        if no {
            return;
        }
        if !yes {
            self.confirm = Some(confirm);
            return;
        }
        match confirm {
            Confirm::DeleteConnection(id, _) => {
                let r = self.store.lock().delete_connection(id);
                self.report(r);
                self.reload();
                // Ein offener Editor würde sonst ins Leere speichern.
                if self.editor.as_ref().is_some_and(|e| e.rec.id == Some(id)) {
                    self.editor = None;
                    if self.page == Page::Editor {
                        self.page = Page::Home;
                    }
                }
            }
            Confirm::DeleteKey(id, _, _) => {
                let r = self.store.lock().delete_key(id);
                self.report(r);
                self.reload();
            }
            Confirm::CloseSession(id, _) => self.close_session(id),
            Confirm::ForgetHost(h, p) => {
                let r = self.store.lock().forget_host(&h, p);
                self.report(r);
                self.reload();
            }
        }
    }

    fn ui_toast(&mut self, ui: &mut Ui, c: &Colors) {
        let Some((text, error, at)) = &self.toast else { return };
        let ttl = if *error { Duration::from_secs(8) } else { Duration::from_secs(3) };
        if at.elapsed() > ttl {
            self.toast = None;
            return;
        }
        ui.ctx().request_repaint_after(Duration::from_millis(500));
        let ctx = ui.ctx().clone();
        egui::Area::new(egui::Id::unique("toast"))
            .anchor(egui::Align2::CENTER_TOP, Vec2::new(0.0, 14.0))
            .order(egui::Order::Tooltip)
            .show(&ctx, |ui| {
                Frame::new()
                    .fill(c.panel)
                    .stroke(Stroke::new(1.0, if *error { c.danger } else { c.border }))
                    .corner_radius(8)
                    .inner_margin(Margin::symmetric(14, 9))
                    .show(ui, |ui| {
                        ui.set_max_width(560.0);
                        ui.label(RichText::new(text.as_str()).color(if *error { c.danger } else { c.text }));
                    });
            });
    }

    fn handle_shortcuts(&mut self, ui: &mut Ui) {
        let ctrl_shift = Modifiers::CTRL | Modifiers::SHIFT;
        let (next, prev, close) = ui.input_mut(|i| {
            let prev = i.consume_key(ctrl_shift, Key::Tab) || i.consume_key(Modifiers::CTRL, Key::PageUp);
            let next = i.consume_key(Modifiers::CTRL, Key::Tab) || i.consume_key(Modifiers::CTRL, Key::PageDown);
            (next, prev, i.consume_key(ctrl_shift, Key::W))
        });
        if next {
            self.cycle_session(1);
        }
        if prev {
            self.cycle_session(-1);
        }
        if close && let Some(id) = self.active {
            self.request_close_session(id);
        }
    }

    /// Zeichnet die gesamte Oberfläche.
    pub fn draw(&mut self, ui: &mut Ui) {
        let dark = ui.visuals().dark_mode;
        let c = theme::colors(dark);
        self.handle_window_events(ui);

        if self.db_problem.is_some() {
            egui::CentralPanel::default().frame(Frame::new().fill(c.surface)).show(ui, |ui| self.ui_db_problem(ui, &c));
            return;
        }
        if self.dek.is_none() {
            egui::CentralPanel::default().frame(Frame::new().fill(c.surface)).show(ui, |ui| self.ui_lock(ui, &c));
            self.ui_toast(ui, &c);
            return;
        }

        let modal_open = self.key_form.is_some() || self.confirm.is_some() || self.rename_key.is_some() || self.db_dialog.is_some();
        if !modal_open {
            self.handle_shortcuts(ui);
        }

        egui::Panel::left("sidebar")
            .exact_size(272.0)
            .resizable(false)
            .frame(Frame::new().fill(c.sidebar).inner_margin(Margin::same(12)).stroke(Stroke::new(1.0, c.border)))
            .show(ui, |ui| self.ui_sidebar(ui, &c, dark));

        if !self.sessions.is_empty() {
            egui::Panel::top("tabs")
                .frame(Frame::new().fill(c.sidebar).inner_margin(Margin::symmetric(8, 5)))
                .show(ui, |ui| self.ui_tabs(ui, &c));
        }

        let active = self.active.filter(|a| self.sessions.iter().any(|s| s.id == *a));
        let term_bg = TermPalette::for_mode(dark).bg;
        let fill = if active.is_some() { term_bg } else { c.surface };
        egui::CentralPanel::default().frame(Frame::new().fill(fill)).show(ui, |ui| {
            if let Some(id) = active {
                self.ui_session(ui, &c, id, dark, modal_open);
            } else {
                match self.page {
                    Page::Home => self.ui_home(ui, &c, dark),
                    Page::Editor => self.ui_editor(ui, &c, dark),
                    Page::Keys => self.ui_keys(ui, &c),
                    Page::KnownHosts => self.ui_known_hosts(ui, &c),
                    Page::Settings => self.ui_settings(ui, &c),
                }
            }
        });

        if let Some(id) = self.active {
            self.ui_prompt(ui, &c, id);
        }
        self.ui_key_dialog(ui, &c);
        self.ui_rename_dialog(ui, &c);
        self.ui_db_dialog(ui, &c);
        self.ui_confirm(ui, &c);
        self.ui_toast(ui, &c);
    }
}

fn load_key_file(form: &mut KeyForm) {
    let raw = form.path.trim();
    let expanded = match raw.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME").map_or(raw.into(), |h| std::path::Path::new(&h).join(rest)),
        None => std::path::PathBuf::from(raw),
    };
    match std::fs::read_to_string(&expanded) {
        Ok(text) => {
            *form.pem = text;
            form.error = None;
            if form.name.trim().is_empty() {
                form.name = expanded.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            }
        }
        Err(e) => form.error = Some(format!("Datei kann nicht gelesen werden: {e}")),
    }
}

#[cfg(test)]
impl App {
    pub fn test_unlocked(&self) -> bool {
        self.dek.is_some()
    }
    pub fn test_status(&self) -> Option<Status> {
        self.sessions.last().map(|s| s.shared.status())
    }
    pub fn test_screen(&self) -> String {
        self.sessions.last().map(|s| s.shared.screen_text()).unwrap_or_default()
    }
    pub fn test_connections(&self) -> &[ConnectionRec] {
        &self.connections
    }
    pub fn test_keys(&self) -> &[KeyRec] {
        &self.keys
    }
    pub fn test_known_hosts(&self) -> &[KnownHost] {
        &self.known_hosts
    }
    pub fn test_db_path(&self) -> PathBuf {
        self.store.lock().path().to_owned()
    }
    pub fn test_has_problem(&self) -> bool {
        self.db_problem.is_some()
    }
    pub fn test_session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(id: i64, jump: Option<i64>) -> ConnectionRec {
        ConnectionRec { id: Some(id), name: format!("c{id}"), host: "h".into(), jump_id: jump, ..Default::default() }
    }

    #[test]
    fn chain_order_is_outermost_first() {
        let all = [conn(1, None), conn(2, Some(1)), conn(3, Some(2))];
        let names: Vec<_> = resolve_chain(&all, &all[2]).unwrap().into_iter().map(|c| c.name).collect();
        assert_eq!(names, ["c1", "c2", "c3"]);
    }

    #[test]
    fn jump_cycles_are_rejected() {
        let all = [conn(1, Some(2)), conn(2, Some(1))];
        assert!(resolve_chain(&all, &all[0]).is_err());
        let own = conn(5, Some(5));
        assert!(resolve_chain(std::slice::from_ref(&own), &own).is_err());
    }

    #[test]
    fn editor_validation_catches_bad_input() {
        let ok = ConnectionRec { name: "a".into(), host: "h".into(), username: "u".into(), auth: AuthKind::Agent, ..Default::default() };
        assert!(validate(&mut Editor::new(ok.clone()), &[]).is_ok());
        let mut bad_port = Editor::new(ok.clone());
        bad_port.port = "70000".into();
        assert!(validate(&mut bad_port, &[]).is_err());
        assert!(validate(&mut Editor::new(ConnectionRec { host: "a b".into(), ..ok.clone() }), &[]).is_err());
        assert!(validate(&mut Editor::new(ConnectionRec { auth: AuthKind::Key, key_id: None, ..ok.clone() }), &[]).is_err());
    }
}
