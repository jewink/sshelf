//! End-to-End-Tests: echte Oberfläche (headless), echtes SSH gegen einen lokalen `sshd`
//! bzw. einen In-Process-Server für Passwort, Rückfragen und Zwei-Faktor-Anmeldung.

use crate::app::App;
use crate::config::{Config, Source};
use crate::ssh::{self, Cmd, Hop, HopAuth, Plan};
use crate::store::{ConnectionRec, PasswordChange, Store};
use crate::term::{Prompt, Shared, Status};
use crate::{keys, vault::Dek};
use eframe::egui::{self, Key, Role};
use egui_kittest::{Harness, kittest::{By, Queryable}};
use parking_lot::Mutex;
use russh::keys::{Algorithm, PrivateKey};
use russh::{Channel, ChannelId, MethodKind, MethodSet, server};
use std::borrow::Cow;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

fn temp_dir(tag: &str) -> PathBuf {
    let mut b = [0u8; 6];
    getrandom::fill(&mut b).unwrap();
    let id: String = b.iter().map(|x| format!("{x:02x}")).collect();
    let d = std::env::temp_dir().join(format!("sshelf-{tag}-{id}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn user() -> String {
    std::env::var("USER").unwrap()
}

/// Ein echter OpenSSH-Server auf einem freien Port.
struct Sshd {
    child: Child,
    dir: PathBuf,
    port: u16,
}

impl Sshd {
    fn start() -> Sshd {
        let dir = temp_dir("sshd");
        let port = free_port();
        for (kind, name) in [("ed25519", "host_key"), ("ed25519", "client_key")] {
            let ok = Command::new("ssh-keygen")
                .args(["-q", "-t", kind, "-N", "", "-f"])
                .arg(dir.join(name))
                .status()
                .unwrap()
                .success();
            assert!(ok);
        }
        std::fs::copy(dir.join("client_key.pub"), dir.join("authorized_keys")).unwrap();
        let config = format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {d}/host_key\nPidFile {d}/pid\n\
             AuthorizedKeysFile {d}/authorized_keys\nStrictModes no\nUsePAM no\n\
             PasswordAuthentication no\nKbdInteractiveAuthentication no\nAllowTcpForwarding yes\n\
             ForceCommand /bin/bash --noprofile --norc -i\nSetEnv PS1=sshelf$\\ \n",
            d = dir.display()
        );
        std::fs::write(dir.join("sshd_config"), config).unwrap();
        let child = Command::new("/usr/bin/sshd")
            .args(["-D", "-e", "-f"])
            .arg(dir.join("sshd_config"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < end, "sshd startet nicht");
            std::thread::sleep(Duration::from_millis(30));
        }
        Sshd { child, dir, port }
    }

    fn client_pem(&self) -> String {
        std::fs::read_to_string(self.dir.join("client_key")).unwrap()
    }

    fn hop(&self, label: &str) -> Hop {
        Hop {
            label: label.into(),
            host: "127.0.0.1".into(),
            port: self.port,
            username: user(),
            auth: HopAuth::Key { name: "k".into(), pem: Zeroizing::new(self.client_pem()), passphrase: None },
            keepalive_secs: 0,
        }
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Eine Sitzung ohne Oberfläche, Rückfragen beantwortet `answer`.
struct Headless {
    shared: Arc<Shared>,
    cmds: mpsc::UnboundedSender<Cmd>,
    _rt: tokio::runtime::Runtime,
    store: Arc<Mutex<Store>>,
    _dir: PathBuf,
}

impl Drop for Headless {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

fn headless(plan: Plan) -> Headless {
    let dir = temp_dir("db");
    let store = Arc::new(Mutex::new(Store::open(&dir.join("t.db")).unwrap()));
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let shared = Shared::new(tx.clone(), egui::Context::default(), true);
    ssh::spawn(rt.handle(), plan, shared.clone(), store.clone(), rx);
    Headless { shared, cmds: tx, _rt: rt, store, _dir: dir }
}

/// Wartet auf das Ende des Verbindungsaufbaus. Vertraut Hostschlüsseln und liefert `answers`
/// der Reihe nach auf Textfragen. Gibt die Titel der gestellten Fragen zurück.
fn drive(h: &Headless, answers: &[&str]) -> (Status, Vec<String>) {
    let mut answers = answers.iter();
    let mut asked = Vec::new();
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(p) = h.shared.prompt().take() {
            match p {
                Prompt::HostKey { reply, .. } => {
                    let _ = reply.send(true);
                }
                Prompt::Text { title, message, fields, reply } => {
                    asked.push(format!("{title}|{message}"));
                    let values = answers
                        .next()
                        .map(|a| fields.iter().map(|_| Zeroizing::new(a.to_string())).collect());
                    let _ = reply.send(values);
                }
            }
        }
        let status = h.shared.status();
        if !matches!(status, Status::Connecting(_)) {
            return (status, asked);
        }
        assert!(Instant::now() < end, "Zeitüberschreitung, Status: {status:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_screen(shared: &Shared, needle: &str) {
    let end = Instant::now() + Duration::from_secs(15);
    while !shared.screen_text().contains(needle) {
        assert!(Instant::now() < end, "„{needle}“ erscheint nicht:\n{}", shared.screen_text());
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn run_cmd(h: &Headless, line: &str) {
    h.cmds.send(Cmd::Input(format!("{line}\n").into_bytes())).unwrap();
}

// --- Echter sshd ---------------------------------------------------------------------------

#[test]
fn key_auth_shell_and_resize_against_real_sshd() {
    let sshd = Sshd::start();
    let h = headless(Plan { hops: vec![sshd.hop("ziel")], startup_cmd: "echo start-$((40+2))".into() });
    assert_eq!(drive(&h, &[]).0, Status::Connected);
    wait_screen(&h.shared, "start-42");
    h.cmds.send(Cmd::Resize { cols: 111, rows: 33, px_w: 1000, px_h: 700 }).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    run_cmd(&h, "stty size");
    wait_screen(&h.shared, "33 111");
    assert_eq!(h.store.lock().known_hosts().unwrap().len(), 1, "Hostschlüssel gespeichert");
    run_cmd(&h, "exit 7");
    let end = Instant::now() + Duration::from_secs(10);
    while matches!(h.shared.status(), Status::Connected) {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(matches!(h.shared.status(), Status::Closed(m) if m.contains('7')));
}

#[test]
fn encrypted_key_prompts_for_passphrase_and_retries() {
    let sshd = Sshd::start();
    let keyfile = sshd.dir.join("enc");
    assert!(Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "geheim", "-f"]).arg(&keyfile).status().unwrap().success());
    let pubkey = std::fs::read_to_string(keyfile.with_extension("pub")).unwrap();
    std::fs::write(sshd.dir.join("authorized_keys"), pubkey).unwrap();
    let mut hop = sshd.hop("ziel");
    hop.auth = HopAuth::Key {
        name: "enc".into(),
        pem: Zeroizing::new(std::fs::read_to_string(&keyfile).unwrap()),
        passphrase: None,
    };
    let h = headless(Plan { hops: vec![hop], startup_cmd: String::new() });
    let (status, asked) = drive(&h, &["falsch", "geheim"]);
    assert_eq!(status, Status::Connected);
    assert_eq!(asked.len(), 2);
    assert!(asked[1].contains("falsch"), "{asked:?}");
}

#[test]
fn jump_host_tunnels_to_target() {
    let jump = Sshd::start();
    let target = Sshd::start();
    // Das Ziel akzeptiert nur seinen eigenen Schlüssel, der Weg führt durch den Jump-Host.
    let h = headless(Plan { hops: vec![jump.hop("jump"), target.hop("ziel")], startup_cmd: String::new() });
    assert_eq!(drive(&h, &[]).0, Status::Connected);
    run_cmd(&h, "echo tunnel-$((40+2)) $SSH_CONNECTION");
    wait_screen(&h.shared, "tunnel-42");
    assert_eq!(h.store.lock().known_hosts().unwrap().len(), 2, "beide Hosts geprüft");
}

#[test]
fn changed_host_key_is_blocked() {
    let sshd = Sshd::start();
    let h = {
        let dir = temp_dir("db");
        let store = Store::open(&dir.join("t.db")).unwrap();
        store.trust_host_key("127.0.0.1", sshd.port, "ssh-ed25519", "ssh-ed25519 ANDERER", "SHA256:alt").unwrap();
        let store = Arc::new(Mutex::new(store));
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let shared = Shared::new(tx.clone(), egui::Context::default(), true);
        ssh::spawn(rt.handle(), Plan { hops: vec![sshd.hop("ziel")], startup_cmd: String::new() }, shared.clone(), store.clone(), rx);
        Headless { shared, cmds: tx, _rt: rt, store, _dir: dir }
    };
    let (status, _) = drive(&h, &[]);
    let Status::Failed(msg) = status else { panic!("muss blockiert werden: {status:?}") };
    assert!(msg.contains("geändert") && msg.contains("SHA256:alt"), "{msg}");
}

#[test]
fn rejected_host_key_aborts() {
    let sshd = Sshd::start();
    let h = headless(Plan { hops: vec![sshd.hop("ziel")], startup_cmd: String::new() });
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(Prompt::HostKey { reply, .. }) = h.shared.prompt().take() {
            let _ = reply.send(false);
            break;
        }
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(10));
    }
    let (status, _) = drive(&h, &[]);
    assert!(matches!(&status, Status::Failed(m) if m.contains("abgelehnt")), "{status:?}");
    assert!(h.store.lock().known_hosts().unwrap().is_empty());
}

#[test]
fn ssh_agent_authentication() {
    let sshd = Sshd::start();
    // Unix-Socket-Pfade sind auf etwa 100 Zeichen begrenzt.
    let base = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    let sock = base.join(format!("sshelf-test-{}.sock", sshd.port));
    let mut agent = Command::new("ssh-agent").arg("-D").arg("-a").arg(&sock).stdout(Stdio::null()).spawn().unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    while !sock.exists() {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(20));
    }
    let added = Command::new("ssh-add")
        .arg(sshd.dir.join("client_key"))
        .env("SSH_AUTH_SOCK", &sock)
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(added.success());
    let mut hop = sshd.hop("ziel");
    let sock2 = sock.clone();
    hop.auth = HopAuth::Agent(Some(sock));
    let h = headless(Plan { hops: vec![hop], startup_cmd: String::new() });
    let status = drive(&h, &[]).0;
    let _ = agent.kill();
    let _ = agent.wait();
    let _ = std::fs::remove_file(sock2);
    assert_eq!(status, Status::Connected);
}

#[test]
fn unreachable_host_reports_error() {
    let port = free_port();
    let h = headless(Plan {
        hops: vec![Hop {
            label: "weg".into(),
            host: "127.0.0.1".into(),
            port,
            username: "x".into(),
            auth: HopAuth::Interactive,
            keepalive_secs: 0,
        }],
        startup_cmd: String::new(),
    });
    let (status, _) = drive(&h, &[]);
    assert!(matches!(&status, Status::Failed(m) if m.contains(&port.to_string())), "{status:?}");
}

// --- In-Process-Server für Passwort und Rückfragen ------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// Nur Passwort.
    Password,
    /// Nur Keyboard-Interactive.
    Interactive,
    /// Erst Passwort, dann Einmalcode.
    TwoFactor,
}

struct TestServer {
    mode: Mode,
    password_ok: bool,
}

fn methods(m: &[MethodKind]) -> Option<MethodSet> {
    Some(MethodSet::from(m))
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Reject {
            proceed_with_methods: match self.mode {
                Mode::Password | Mode::TwoFactor => methods(&[MethodKind::Password]),
                Mode::Interactive => methods(&[MethodKind::KeyboardInteractive]),
            },
            partial_success: false,
        })
    }

    async fn auth_password(&mut self, _: &str, password: &str) -> Result<server::Auth, Self::Error> {
        if password != "richtig" {
            return Ok(server::Auth::Reject { proceed_with_methods: methods(&[MethodKind::Password]), partial_success: false });
        }
        Ok(if self.mode == Mode::TwoFactor {
            self.password_ok = true;
            server::Auth::Reject { proceed_with_methods: methods(&[MethodKind::KeyboardInteractive]), partial_success: true }
        } else {
            server::Auth::Accept
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _: &str,
        _: &str,
        response: Option<server::Response<'a>>,
    ) -> Result<server::Auth, Self::Error> {
        match response {
            None => Ok(server::Auth::Partial {
                name: "Zwei-Faktor".into(),
                instructions: "Bitte Code eingeben".into(),
                prompts: Cow::Owned(vec![("Code:".into(), false)]),
            }),
            Some(mut answers) => {
                let ok = answers.next().is_some_and(|b| b.as_ref() == b"123456");
                Ok(if ok {
                    server::Auth::Accept
                } else {
                    server::Auth::Reject { proceed_with_methods: methods(&[MethodKind::KeyboardInteractive]), partial_success: false }
                })
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        _: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut server::Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"angemeldet-ok\r\n".to_vec())
    }
}

/// Startet den Testserver im übergebenen Runtime-Handle.
fn start_test_server(rt: &tokio::runtime::Runtime, mode: Mode) -> u16 {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::from_millis(1)),
        ..Default::default()
    });
    // Direkt auf Port 0 öffnen: Ein vorher ermittelter freier Port kann bei parallelen Tests
    // inzwischen von einem anderen Test belegt sein.
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    rt.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let config = config.clone();
            tokio::spawn(async move {
                let handler = TestServer { mode, password_ok: false };
                if let Ok(session) = server::run_stream(config, socket, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    port
}

fn with_test_server(mode: Mode, auth: HopAuth, answers: &[&str]) -> (Status, Vec<String>, Arc<Shared>) {
    let server_rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
    let port = start_test_server(&server_rt, mode);
    let hop = Hop { label: "test".into(), host: "127.0.0.1".into(), port, username: "u".into(), auth, keepalive_secs: 0 };
    let h = headless(Plan { hops: vec![hop], startup_cmd: String::new() });
    let (status, asked) = drive(&h, answers);
    let shared = h.shared.clone();
    if status == Status::Connected {
        wait_screen(&shared, "angemeldet-ok");
    }
    std::mem::forget(server_rt);
    (status, asked, shared)
}

#[test]
fn saved_password_connects_without_asking() {
    let saved = HopAuth::Password(Some(Zeroizing::new("richtig".into())));
    let (status, asked, _) = with_test_server(Mode::Password, saved, &[]);
    assert_eq!(status, Status::Connected);
    assert!(asked.is_empty(), "{asked:?}");
}

#[test]
fn wrong_saved_password_falls_back_to_prompt() {
    let saved = HopAuth::Password(Some(Zeroizing::new("veraltet".into())));
    let (status, asked, _) = with_test_server(Mode::Password, saved, &["richtig"]);
    assert_eq!(status, Status::Connected);
    assert_eq!(asked.len(), 1);
    assert!(asked[0].contains("falsch"), "{asked:?}");
}

#[test]
fn password_gives_up_after_three_attempts() {
    let (status, asked, _) = with_test_server(Mode::Password, HopAuth::Password(None), &["a", "b", "c", "d"]);
    assert!(matches!(&status, Status::Failed(m) if m.contains("fehlgeschlagen")), "{status:?}");
    assert_eq!(asked.len(), 3);
}

#[test]
fn cancelling_a_prompt_aborts() {
    let (status, asked, _) = with_test_server(Mode::Password, HopAuth::Password(None), &[]);
    assert!(matches!(&status, Status::Failed(m) if m.contains("abgebrochen")), "{status:?}");
    assert_eq!(asked.len(), 1);
}

#[test]
fn keyboard_interactive_login() {
    let (status, asked, _) = with_test_server(Mode::Interactive, HopAuth::Interactive, &["123456"]);
    assert_eq!(status, Status::Connected);
    assert!(asked[0].contains("Zwei-Faktor") && asked[0].contains("Code eingeben"), "{asked:?}");
}

#[test]
fn password_then_one_time_code() {
    let saved = HopAuth::Password(Some(Zeroizing::new("richtig".into())));
    let (status, asked, _) = with_test_server(Mode::TwoFactor, saved, &["123456"]);
    assert_eq!(status, Status::Connected);
    assert_eq!(asked.len(), 1, "{asked:?}");
}

// --- Die Oberfläche von vorne bis hinten -----------------------------------------------------

type Gui<'a> = Harness<'a, Option<App>>;

fn gui<'a>(db: &Path, dark: bool) -> Gui<'a> {
    let config_path = db.with_file_name("config.ini");
    let config = Config::load(&config_path).unwrap();
    let start = App::open_start_db(db.to_owned(), Source::Cli);
    let app = App::new(start, config_path, config, Source::Cli).unwrap();
    window(app, dark)
}

/// Öffnet ein Fenster für eine bestehende App, wie nach dem Klick auf das Statusleisten-Symbol.
fn window<'a>(app: App, dark: bool) -> Gui<'a> {
    let mut attached = false;
    Harness::builder()
        .with_size(egui::vec2(1180.0, 760.0))
        .with_theme(if dark { egui::Theme::Dark } else { egui::Theme::Light })
        .with_accessibility_check(false)
        // Das Terminal zeigt absichtlich auch Zeichen, die keine eingebaute Schrift hat (CJK).
        .allow_missing_glyphs()
        .build_ui_state(
            move |ui, state: &mut Option<App>| {
                let app = state.as_mut().unwrap();
                if !attached {
                    app.attach(ui.ctx());
                    attached = true;
                }
                app.draw(ui);
            },
            Some(app),
        )
}

fn app<'h>(h: &'h Gui<'_>) -> &'h App {
    h.state().as_ref().unwrap()
}

fn settle(h: &mut Gui<'_>) {
    h.run_steps(4);
}

fn shot(h: &mut Gui<'_>, name: &str) {
    let Some(dir) = std::env::var_os("SSHELF_SHOTS") else { return };
    h.run_steps(2);
    match h.render() {
        Ok(img) => img.save(Path::new(&dir).join(format!("{name}.png"))).unwrap(),
        Err(e) => eprintln!("Kein Screenshot möglich: {e}"),
    }
}

fn click(h: &mut Gui<'_>, label: &str) {
    h.get_by_label(label).scroll_to_me();
    settle(h);
    h.get_by_label(label).click();
    settle(h);
}

/// Alle Eingabefelder in Reihenfolge der Oberfläche.
fn inputs(h: &Gui<'_>) -> usize {
    h.query_all(input_filter()).count()
}

fn input_filter<'a>() -> By<'a> {
    By::new().predicate(|n| matches!(n.role(), Role::TextInput | Role::PasswordInput | Role::MultilineTextInput))
}

fn focus_field(h: &mut Gui<'_>, index: usize) {
    {
        let n = inputs(h);
        let f = h.query_all(input_filter()).nth(index);
        f.unwrap_or_else(|| panic!("Feld {index} fehlt, {n} vorhanden")).focus();
    }
    settle(h);
}

fn fill(h: &mut Gui<'_>, index: usize, text: &str) {
    focus_field(h, index);
    // Über Einfügen, damit auch mehrzeilige Texte unverändert ankommen.
    h.event(egui::Event::Paste(text.to_owned()));
    settle(h);
}

/// Ersetzt den gesamten Inhalt eines Feldes.
fn replace(h: &mut Gui<'_>, index: usize, text: &str) {
    focus_field(h, index);
    h.key_press_modifiers(egui::Modifiers::CTRL | egui::Modifiers::COMMAND, Key::A);
    if text.is_empty() {
        h.key_press(Key::Backspace);
    } else {
        h.event(egui::Event::Paste(text.to_owned()));
    }
    settle(h);
}

fn pump(h: &mut Gui<'_>, what: &str, mut until: impl FnMut(&mut Gui<'_>) -> bool) {
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        h.step();
        if until(h) {
            return;
        }
        assert!(Instant::now() < end, "Zeitüberschreitung bei: {what}\nBildschirm:\n{}", app(h).test_screen());
        std::thread::sleep(Duration::from_millis(15));
    }
}

fn type_line(h: &mut Gui<'_>, text: &str) {
    h.event(egui::Event::Text(text.to_owned()));
    h.key_press(Key::Enter);
    h.step();
}

fn wait_for_text(h: &mut Gui<'_>, needle: &str) {
    pump(h, needle, |h| app(h).test_screen().contains(needle));
}

/// Ohne dieses Feature ist die Zwischenablage still funktionslos, und die Oberflächentests merken
/// es nicht, weil sie Einfügen-Ereignisse selbst erzeugen.
#[test]
fn clipboard_feature_is_enabled() {
    let manifest = include_str!("../Cargo.toml");
    let eframe = manifest.lines().find(|l| l.starts_with("eframe")).unwrap();
    assert!(eframe.contains("\"clipboard\""), "{eframe}");
}

/// Alle in der Oberfläche verwendeten Symbole müssen in den eingebauten Schriften vorhanden sein.
#[test]
fn ui_icons_exist_in_builtin_fonts() {
    let ctx = egui::Context::default();
    let mut output = ctx.run_ui(Default::default(), |ui| {
        ui.fonts_mut(|f| {
            for c in "🔑🔒🌓⚙🖧🔍✏▶📋🗑×+«»ℹ".chars() {
                assert!(f.has_glyph(&egui::FontId::proportional(14.0), c), "Symbol fehlt: {c}");
            }
        });
    });
    output.textures_delta.clear();
}

/// Der komplette Weg eines Benutzers: Tresor anlegen, Schlüssel einfügen, Verbindung anlegen,
/// verbinden, Hostschlüssel bestätigen, im Terminal arbeiten, sperren, neu starten.
#[test]
fn full_user_journey_through_the_gui() {
    let sshd = Sshd::start();
    let dir = temp_dir("gui");
    let db = dir.join("sshelf.db");
    {
        let mut h = gui(&db, true);
        settle(&mut h);
        shot(&mut h, "01-tresor-anlegen");

        // Zu kurzes Passwort wird abgelehnt, danach klappt es.
        fill(&mut h, 0, "kurz");
        fill(&mut h, 1, "kurz");
        click(&mut h, "Tresor anlegen");
        assert!(!app(&h).test_unlocked());
        h.get_by_label_contains("mindestens");
        fill(&mut h, 0, "-master-passwort");
        fill(&mut h, 1, "-master-passwort");
        click(&mut h, "Tresor anlegen");
        assert!(app(&h).test_unlocked());
        settle(&mut h);
        shot(&mut h, "02-leer");

        // Editor: Pflichtfelder werden geprüft.
        click(&mut h, "+ Neu");
        click(&mut h, "Speichern");
        h.get_by_label_contains("Verbindungsnamen");

        fill(&mut h, 1, "Testserver");
        fill(&mut h, 2, "Labor");
        fill(&mut h, 3, "127.0.0.1");
        // Port-Feld: Standardwert 22 ersetzen.
        replace(&mut h, 4, &sshd.port.to_string());

        // Schlüssel direkt aus dem Editor heraus importieren.
        click(&mut h, "Schlüssel hinzufügen…");
        shot(&mut h, "03-schluessel-import");
        // Die letzten vier Felder gehören zum Dialog: Name, Datei, Schlüsseltext, Passphrase.
        let n = inputs(&h);
        assert!(n >= 4);
        let (name_idx, pem_idx) = (n - 4, n - 2);
        fill(&mut h, name_idx, "Laborschlüssel");
        fill(&mut h, pem_idx, &sshd.client_pem());
        h.get_all_by_label("Importieren").last().unwrap().click();
        settle(&mut h);
        assert_eq!(app(&h).test_keys().len(), 1, "Schlüssel gespeichert");
        shot(&mut h, "04-editor");

        // Speichern und verbinden; zuerst kommt die Hostschlüssel-Frage.
        click(&mut h, "Speichern und verbinden");
        assert_eq!(app(&h).test_connections().len(), 1);
        pump(&mut h, "Hostschlüssel-Frage", |h| h.query_by_label_contains("Unbekannter Host").is_some());
        shot(&mut h, "05-hostschluessel");
        click(&mut h, "Vertrauen und verbinden");
        pump(&mut h, "Verbunden", |h| app(h).test_status() == Some(Status::Connected));
        wait_for_text(&mut h, "sshelf$");

        // Tippen läuft bis zum Server und zurück.
        type_line(&mut h, "echo gui-$((40+2))");
        wait_for_text(&mut h, "gui-42");

        // Das Terminal hat die reale Größe des Fensters ausgehandelt.
        type_line(&mut h, "stty size");
        pump(&mut h, "stty", |h| {
            let t = app(h).test_screen();
            t.lines().any(|l| {
                let p: Vec<_> = l.trim().split(' ').collect();
                p.len() == 2 && p[0].parse::<u32>().is_ok_and(|r| r > 30) && p[1].parse::<u32>().is_ok_and(|c| c > 80)
            })
        });

        // Strg+C kommt von egui als Copy-Ereignis und muss das laufende Programm abbrechen.
        type_line(&mut h, "sleep 300; echo nicht-abgebrochen");
        std::thread::sleep(Duration::from_millis(200));
        h.event(egui::Event::Copy);
        h.step();
        type_line(&mut h, "echo abgebrochen-$((40+2))");
        wait_for_text(&mut h, "abgebrochen-42");
        assert!(!app(&h).test_screen().contains("\nnicht-abgebrochen"));

        // Tab und Pfeiltasten dürfen nicht vom Fokus-System von egui verschluckt werden.
        h.event(egui::Event::Text("echo tab".to_owned()));
        h.key_press(Key::Backspace);
        h.key_press(Key::Backspace);
        h.key_press(Key::Backspace);
        h.event(egui::Event::Text("ok-$((40+2))".to_owned()));
        h.key_press(Key::Enter);
        h.step();
        wait_for_text(&mut h, "ok-42");
        // Tabulator-Vervollständigung braucht die Tab-Taste am Server.
        type_line(&mut h, &format!("cd {} && mkdir tabtest-dir-x", sshd.dir.display()));
        h.step();
        std::thread::sleep(Duration::from_millis(200));
        h.event(egui::Event::Text("cd tabtest-d".to_owned()));
        h.key_press(Key::Tab);
        h.step();
        std::thread::sleep(Duration::from_millis(300));
        h.key_press(Key::Enter);
        h.step();
        type_line(&mut h, "echo tabok-$(basename $PWD)");
        wait_for_text(&mut h, "tabok-tabtest-dir-x");

        // Einfügen: Der Inhalt kommt vom Fenstersystem als Antwort auf die Anforderung.
        let ctrl_shift = egui::Modifiers::CTRL | egui::Modifiers::COMMAND | egui::Modifiers::SHIFT;
        h.key_press_modifiers(ctrl_shift, Key::V);
        h.step();
        h.event(egui::Event::Paste("echo eingefuegt-$((40+2))".to_owned()));
        h.step();
        h.key_press(Key::Enter);
        h.step();
        wait_for_text(&mut h, "eingefuegt-42");

        // Einfügen über das Kontextmenü.
        let terminal = egui::pos2(800.0, 500.0);
        h.hover_at(terminal);
        h.step();
        h.event(egui::Event::PointerButton { pos: terminal, button: egui::PointerButton::Secondary, pressed: true, modifiers: Default::default() });
        h.step();
        h.event(egui::Event::PointerButton { pos: terminal, button: egui::PointerButton::Secondary, pressed: false, modifiers: Default::default() });
        settle(&mut h);
        click(&mut h, "Einfügen");
        h.event(egui::Event::Paste("echo menue-$((40+2))".to_owned()));
        h.step();
        h.key_press(Key::Enter);
        h.step();
        wait_for_text(&mut h, "menue-42");

        // Mittlere Maustaste: Primary-Selection.
        h.event(egui::Event::MiddleClickPaste { pos: terminal, text: "echo mitte-$((40+2))".to_owned() });
        h.step();
        h.key_press(Key::Enter);
        h.step();
        wait_for_text(&mut h, "mitte-42");

        // Ein Bild mit Farben und Rahmen, zum Beurteilen der Darstellung.
        type_line(&mut h, "clear");
        type_line(
            &mut h,
            r#"printf '\e[1mFett\e[0m \e[3mKursiv\e[0m \e[4mUnterstrichen\e[0m \e[9mDurch\e[0m \e[2mBlass\e[0m \e[7mInvers\e[0m\n'; for i in 0 1 2 3 4 5 6 7; do printf '\e[4%dm  \e[0m' $i; done; for i in 0 1 2 3 4 5 6 7; do printf '\e[10%dm  \e[0m' $i; done; echo; for i in 1 2 3 4 5 6; do printf '\e[3%dmFarbe%d \e[0m' $i $i; done; echo; printf '┌────────┬───────┐\n│ Umlaut │ äöüß€ │\n├────────┼───────┤\n│ Breit  │ 日本語│\n└────────┴───────┘\n▀▄█░▒▓ ✓ → λ\n'; printf 'Nerd:     \e[44m Prompt \e[34;46m\e[30m ~/pfad \e[0;36m\e[0m  Emoji: 🚀 ☕  Pfeile: ⇄ ⌘ ⏎  Mathe: ∑ ∞ ≈\n'; printf '[+] Pulling 3/3\n \e[32m✔\e[0m redis Pulled\n \e[34m⠋\e[0m web  Pulling\n \e[34m⠼\e[0m db   Downloading\n \e[31m✘\e[0m alt  Error\n'; ls --color=always -la / | head -8; echo fertig-$((40+2))"#,
        );
        wait_for_text(&mut h, "fertig-42");
        shot(&mut h, "06-terminal-dunkel");

        // Markieren mit Ziehen über den oberen Rand: Das Terminal scrollt mit, sodass auch
        // Zeilen außerhalb des sichtbaren Bereichs in die Auswahl kommen.
        type_line(&mut h, "clear; for i in $(seq 1 150); do echo zeile-$i; done");
        wait_for_text(&mut h, "zeile-150");
        assert_eq!(app(&h).test_display_offset(), 0);
        let from = egui::pos2(700.0, 600.0);
        h.hover_at(from);
        h.step();
        h.event(egui::Event::PointerButton { pos: from, button: egui::PointerButton::Primary, pressed: true, modifiers: Default::default() });
        h.step();
        // Deutlich über das Terminal hinaus (in die Tableiste) ziehen und dort halten.
        let above = egui::pos2(700.0, 20.0);
        for _ in 0..40 {
            h.hover_at(above);
            h.step();
        }
        let scrolled = app(&h).test_display_offset();
        h.event(egui::Event::PointerButton { pos: above, button: egui::PointerButton::Primary, pressed: false, modifiers: Default::default() });
        h.step();
        assert!(scrolled > 10, "beim Markieren über den Rand muss das Terminal scrollen, Versatz {scrolled}");
        let selected = app(&h).test_selection().unwrap_or_default();
        assert!(selected.contains("zeile-150") || selected.contains("zeile-14"), "Auswahl reicht bis unten");
        let first_visible_before = 150 - 40; // grob: vorher sichtbarer Anfang
        let earliest = selected.lines().filter_map(|l| l.trim().strip_prefix("zeile-")?.parse::<u32>().ok()).min().unwrap_or(999);
        assert!(earliest < first_visible_before, "Auswahl enthält Zeilen aus dem Verlauf, früheste {earliest}");
        // Tippen springt wieder ans Ende.
        type_line(&mut h, "clear");
        settle(&mut h);

        // Sperren versteckt alles, die Sitzung läuft weiter.
        click(&mut h, "Sperren");
        assert!(!app(&h).test_unlocked());
        shot(&mut h, "07-gesperrt");
        fill(&mut h, 0, "falsches-passwort");
        click(&mut h, "Entsperren");
        assert!(!app(&h).test_unlocked());
        h.get_by_label_contains("falsch");
        replace(&mut h, 0, "kurz-master-passwort");
        click(&mut h, "Entsperren");
        assert!(app(&h).test_unlocked());
        settle(&mut h);
        assert_eq!(app(&h).test_status(), Some(Status::Connected), "Sitzung überlebt das Sperren");
        type_line(&mut h, "echo nach-sperre-$((40+2))");
        wait_for_text(&mut h, "nach-sperre-42");

        // Seiten für die Sichtprüfung.
        click(&mut h, "Schlüssel & Hosts");
        shot(&mut h, "08-schluessel");
        click(&mut h, "Bekannte Hosts");
        assert_eq!(app(&h).test_known_hosts().len(), 1);
        shot(&mut h, "09-bekannte-hosts");
        click(&mut h, "Einstellungen");
        shot(&mut h, "10-einstellungen");
        click(&mut h, "Hell");
        settle(&mut h);
        shot(&mut h, "11-einstellungen-hell");
        click(&mut h, "Schlüssel & Hosts");
        shot(&mut h, "11b-schluessel-hell");
        click(&mut h, "Einstellungen");

        // Zurück zum Tab: hell dargestellt, dann ausloggen und neu verbinden.
        h.get_all_by_label("Testserver").next().unwrap().click();
        settle(&mut h);
        type_line(&mut h, "echo hell-$((40+2)); ls --color=always /");
        wait_for_text(&mut h, "hell-42");
        shot(&mut h, "12-terminal-hell");
        click(&mut h, "Design: Hell");
        click(&mut h, "Design: System");
        h.get_all_by_label("Testserver").next().unwrap().click();
        settle(&mut h);
        type_line(&mut h, "exit");
        pump(&mut h, "Sitzungsende", |h| matches!(app(h).test_status(), Some(Status::Closed(_))));
        settle(&mut h);
        shot(&mut h, "13-beendet");
        click(&mut h, "Neu verbinden");
        pump(&mut h, "Wiederverbinden ohne Rückfrage", |h| app(h).test_status() == Some(Status::Connected));
        wait_for_text(&mut h, "sshelf$");
        assert_eq!(app(&h).test_session_count(), 1, "Neu verbinden nutzt denselben Tab");

        // Tab schließen fragt bei aktiver Verbindung nach.
        h.key_press_modifiers(egui::Modifiers::CTRL | egui::Modifiers::SHIFT, Key::W);
        settle(&mut h);
        click(&mut h, "Trennen");
        assert_eq!(app(&h).test_session_count(), 0);
    }

    // Neustart: Alles ist noch da und die Datenbank enthält keinen Klartext.
    let pem = sshd.client_pem();
    let marker = pem.lines().nth(1).unwrap();
    let raw = std::fs::read(&db).unwrap();
    assert!(!raw.windows(marker.len()).any(|w| w == marker.as_bytes()), "Schlüssel im Klartext!");

    let mut h = gui(&db, true);
    settle(&mut h);
    fill(&mut h, 0, "kurz-master-passwort");
    click(&mut h, "Entsperren");
    assert!(app(&h).test_unlocked());
    assert_eq!(app(&h).test_connections().len(), 1);
    assert_eq!(app(&h).test_keys().len(), 1);
    settle(&mut h);
    shot(&mut h, "14-neustart");
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tray_icon_is_valid_and_can_be_inspected() {
    let size = 256;
    let rgba = crate::desktop::rgba(size);
    assert_eq!(rgba.len(), (size * size * 4) as usize);
    assert_eq!(&rgba[0..4], &[0, 0, 0, 0], "Ecken sind durchsichtig");
    if let Some(dir) = std::env::var_os("SSHELF_SHOTS") {
        image::RgbaImage::from_raw(size, size, rgba).unwrap().save(Path::new(&dir).join("30-icon.png")).unwrap();
    }
}

/// Legt Tresor und eine Verbindung über die Oberfläche an.
fn setup_with_connection(h: &mut Gui<'_>, name: &str) {
    settle(h);
    fill(h, 0, "master-passwort");
    fill(h, 1, "master-passwort");
    click(h, "Tresor anlegen");
    create_connection(h, name, None);
}

fn create_connection(h: &mut Gui<'_>, name: &str, jump: Option<&str>) {
    create_connection_in(h, name, jump, None);
}

fn create_connection_in(h: &mut Gui<'_>, name: &str, jump: Option<&str>, group: Option<&str>) {
    click(h, "+ Neu");
    fill(h, 1, name);
    if let Some(group) = group {
        fill(h, 2, group);
    }
    fill(h, 3, "127.0.0.1");
    click(h, "Nachfragen");
    if let Some(jump) = jump {
        // Bei dieser Anmeldeart ist die Jump-Host-Auswahl die letzte Auswahlliste.
        h.get_all_by_role(Role::ComboBox).last().unwrap().click();
        settle(h);
        h.get_all_by_label(jump).last().unwrap().click();
        settle(h);
    }
    click(h, "Speichern");
}

fn hover_row(h: &mut Gui<'_>, name: &str) {
    let pos = h.get_all_by_label(name).next().unwrap().rect().center();
    h.hover_at(pos);
    settle(h);
}

#[test]
fn connections_can_be_deleted_from_list_and_editor() {
    let dir = temp_dir("del");
    let mut h = gui(&dir.join("sshelf.db"), true);
    setup_with_connection(&mut h, "Eins");
    create_connection(&mut h, "Zwei", None);
    create_connection(&mut h, "Drei", Some("Eins"));
    assert_eq!(app(&h).test_connections().len(), 3);

    // Über das Symbol in der Liste; Abbrechen lässt alles stehen.
    hover_row(&mut h, "Zwei");
    shot(&mut h, "20-zeile-mit-loeschen");
    click(&mut h, "🗑");
    click(&mut h, "Abbrechen");
    assert_eq!(app(&h).test_connections().len(), 3);
    hover_row(&mut h, "Zwei");
    click(&mut h, "🗑");
    click(&mut h, "Löschen");
    assert_eq!(app(&h).test_connections().len(), 2);

    // Über den Editor, mit Warnung wegen des Jump-Hosts. Danach ist der Editor zu.
    hover_row(&mut h, "Eins");
    click(&mut h, "✏");
    click(&mut h, "Verbindung löschen");
    h.get_by_label_contains("Drei nutzt diese Verbindung als Jump-Host");
    shot(&mut h, "21-loeschen-bestaetigen");
    click(&mut h, "Löschen");
    let left = app(&h).test_connections();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].name, "Drei");
    assert_eq!(left[0].jump_id, None);
    assert!(h.query_by_label("Verbindung löschen").is_none());
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn database_path_can_be_changed_in_settings() {
    let dir = temp_dir("dbswitch");
    let db = dir.join("sshelf.db");
    let config_file = dir.join("config.ini");
    let mut h = gui(&db, true);
    setup_with_connection(&mut h, "Eins");
    click(&mut h, "Einstellungen");
    shot(&mut h, "22-einstellungen");
    // Nach dem Suchfeld der Seitenleiste das erste Eingabefeld der Seite.
    let path_field = 1;

    // Fremde Datei: wird abgelehnt und nicht verändert, die Konfiguration bleibt leer.
    let foreign = dir.join("fremd.db");
    std::fs::write(&foreign, "keine datenbank, aber eine datei mit etwas inhalt").unwrap();
    let before = std::fs::read(&foreign).unwrap();
    replace(&mut h, path_field, foreign.to_str().unwrap());
    click(&mut h, "Datenbank wechseln…");
    click(&mut h, "Diese Datenbank verwenden");
    h.get_by_label_contains("keine gültige");
    assert_eq!(std::fs::read(&foreign).unwrap(), before);
    assert_eq!(Config::load(&config_file).unwrap().db_path, None);
    assert_eq!(app(&h).test_db_path(), db);
    click(&mut h, "Abbrechen");

    // Kopieren in eine neue Datei: gleiches Passwort, gleiche Daten, Pfad gespeichert.
    let copy = dir.join("neu/kopie.db");
    replace(&mut h, path_field, copy.to_str().unwrap());
    click(&mut h, "Datenbank wechseln…");
    click(&mut h, "Daten dorthin kopieren");
    assert!(!app(&h).test_unlocked(), "Nach dem Wechsel wird neu entsperrt");
    assert_eq!(app(&h).test_db_path(), copy);
    assert_eq!(Config::load(&config_file).unwrap().db_path, Some(copy.clone()));
    assert!(db.exists(), "Die alte Datei bleibt erhalten");
    fill(&mut h, 0, "master-passwort");
    click(&mut h, "Entsperren");
    assert!(app(&h).test_unlocked());
    assert_eq!(app(&h).test_connections().len(), 1);

    // Leer beginnen: neue Datei, neuer Tresor.
    click(&mut h, "Einstellungen");
    let empty = dir.join("leer.db");
    replace(&mut h, path_field, empty.to_str().unwrap());
    click(&mut h, "Datenbank wechseln…");
    click(&mut h, "Leer beginnen");
    h.get_by_label("Tresor anlegen");
    fill(&mut h, 0, "anderes-passwort");
    fill(&mut h, 1, "anderes-passwort");
    click(&mut h, "Tresor anlegen");
    assert_eq!(app(&h).test_connections().len(), 0);

    // Zurück zu einer vorhandenen Datei, mit deren Passwort.
    click(&mut h, "Einstellungen");
    replace(&mut h, path_field, copy.to_str().unwrap());
    click(&mut h, "Datenbank wechseln…");
    click(&mut h, "Diese Datenbank verwenden");
    fill(&mut h, 0, "master-passwort");
    click(&mut h, "Entsperren");
    assert_eq!(app(&h).test_connections().len(), 1);
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn database_cannot_be_switched_with_open_tabs() {
    let sshd = Sshd::start();
    let dir = temp_dir("dbtabs");
    let mut h = gui(&dir.join("sshelf.db"), true);
    settle(&mut h);
    fill(&mut h, 0, "master-passwort");
    fill(&mut h, 1, "master-passwort");
    click(&mut h, "Tresor anlegen");
    add_sshd_connection(&mut h, &sshd);
    click(&mut h, "Einstellungen");
    h.get_by_label_contains("alle Tabs schließen");
    let disabled = By::new().predicate(|n| n.is_disabled() && n.label().is_some_and(|l| l.contains("Datenbank wechseln")));
    assert_eq!(h.query_all(disabled).count(), 1);
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Legt eine Verbindung zum `sshd` an, verbindet und wartet auf die Eingabeaufforderung.
fn add_sshd_connection(h: &mut Gui<'_>, sshd: &Sshd) {
    click(h, "+ Neu");
    fill(h, 1, "Testserver");
    fill(h, 3, "127.0.0.1");
    replace(h, 4, &sshd.port.to_string());
    click(h, "Schlüssel hinzufügen…");
    let n = inputs(h);
    fill(h, n - 4, "k");
    fill(h, n - 2, &sshd.client_pem());
    h.get_all_by_label("Importieren").last().unwrap().click();
    settle(h);
    click(h, "Speichern und verbinden");
    pump(h, "Hostschlüssel-Frage", |h| h.query_by_label_contains("Unbekannter Host").is_some());
    click(h, "Vertrauen und verbinden");
    pump(h, "Verbunden", |h| app(h).test_status() == Some(Status::Connected));
    wait_for_text(h, "sshelf$");
}

#[test]
fn missing_configured_database_shows_a_choice_instead_of_creating_one() {
    let dir = temp_dir("missing");
    let missing = dir.join("nicht/eingehaengt/sshelf.db");
    let config_path = dir.join("config.ini");
    let config = Config { db_path: Some(missing.clone()), ..Default::default() };
    config.save(&config_path).unwrap();
    let start = App::open_start_db(missing.clone(), Source::Config);
    let app_ = App::new(start, config_path.clone(), config, Source::Config).unwrap();
    let mut h = window(app_, true);
    settle(&mut h);
    assert!(app(&h).test_has_problem());
    assert!(!missing.exists(), "Es darf nichts still angelegt werden");
    shot(&mut h, "23-datenbank-fehlt");

    click(&mut h, "Erneut versuchen");
    assert!(app(&h).test_has_problem());
    assert!(!missing.exists());

    click(&mut h, "Hier neu anlegen");
    assert!(!app(&h).test_has_problem());
    assert!(missing.exists());
    h.get_by_label("Tresor anlegen");
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tray_setting_is_saved_in_the_ini_file() {
    let dir = temp_dir("trayset");
    let mut h = gui(&dir.join("sshelf.db"), true);
    setup_with_connection(&mut h, "Eins");
    click(&mut h, "Einstellungen");
    click(&mut h, "Beim Schließen in die Statusleiste minimieren");
    assert!(Config::load(&dir.join("config.ini")).unwrap().close_to_tray);
    click(&mut h, "Beim Schließen in die Statusleiste minimieren");
    assert!(!Config::load(&dir.join("config.ini")).unwrap().close_to_tray);
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn groups_collapse_and_can_be_picked_in_the_editor() {
    let dir = temp_dir("groups");
    let db = dir.join("sshelf.db");
    let mut h = gui(&db, true);
    setup_with_connection(&mut h, "Ohne");
    create_connection_in(&mut h, "Web 1", None, Some("Kunde A"));
    create_connection_in(&mut h, "Web 2", None, Some("Kunde A"));
    create_connection_in(&mut h, "Mail", None, Some("Kunde B"));

    // Vorhandene Gruppe aus der Liste übernehmen.
    click(&mut h, "+ Neu");
    fill(&mut h, 1, "Web 3");
    fill(&mut h, 3, "127.0.0.1");
    click(&mut h, "Nachfragen");
    h.get_all_by_role(Role::ComboBox).next().unwrap().click();
    settle(&mut h);
    shot(&mut h, "25-gruppe-waehlen");
    h.get_all_by_label("Kunde B").last().unwrap().click();
    settle(&mut h);
    click(&mut h, "Speichern");
    let web3 = app(&h).test_connections().iter().find(|c| c.name == "Web 3").unwrap().clone();
    assert_eq!(web3.group, "Kunde B");

    // Gruppe zuklappen: Einträge verschwinden, andere bleiben, Zustand wird gespeichert.
    click(&mut h, "Gruppe Kunde A");
    assert!(h.query_by_label("Web 1").is_none());
    assert!(h.query_by_label("Mail").is_some() && h.query_by_label("Ohne").is_some());
    shot(&mut h, "26-gruppe-zu");
    // Die Suche zeigt Treffer trotzdem.
    fill(&mut h, 0, "web 2");
    assert!(h.query_by_label("Web 2").is_some());
    replace(&mut h, 0, "");
    assert!(h.query_by_label("Web 2").is_none());
    drop(h);

    let mut h = gui(&db, true);
    settle(&mut h);
    fill(&mut h, 0, "master-passwort");
    click(&mut h, "Entsperren");
    assert!(h.query_by_label("Web 1").is_none(), "zugeklappt bleibt zugeklappt");
    click(&mut h, "Gruppe Kunde A");
    assert!(h.query_by_label("Web 1").is_some());
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sidebar_collapses_resizes_and_remembers() {
    let dir = temp_dir("sidebar");
    let db = dir.join("sshelf.db");
    let mut h = gui(&db, true);
    setup_with_connection(&mut h, "Eins");
    let sidebar = h.get_by_label("Eins").rect();
    assert!(sidebar.width() > 200.0);

    // Breite mit der Maus am rechten Rand ziehen.
    let edge = egui::pos2(272.0, 400.0);
    h.hover_at(edge);
    h.step();
    h.event(egui::Event::PointerButton { pos: edge, button: egui::PointerButton::Primary, pressed: true, modifiers: Default::default() });
    h.step();
    for x in [300.0, 330.0, 360.0] {
        h.hover_at(egui::pos2(x, 400.0));
        h.step();
    }
    h.event(egui::Event::PointerButton { pos: egui::pos2(360.0, 400.0), button: egui::PointerButton::Primary, pressed: false, modifiers: Default::default() });
    settle(&mut h);
    let width = app(&h).test_config().sidebar_width.unwrap();
    assert!((340.0..=380.0).contains(&width), "Breite nach dem Ziehen: {width}");

    // Einklappen: nur noch Symbole, Name als Tooltip; Ausklappen bringt alles zurück.
    click(&mut h, "«");
    assert!(app(&h).test_config().sidebar_collapsed);
    assert!(h.query_by_label("Suchen…").is_none());
    assert!(h.query_by_label("Eins").is_some(), "Verbindung als Symbol vorhanden");
    shot(&mut h, "27-seitenleiste-zu");
    let a = h.into_state().unwrap();
    let config = Config::load(&dir.join("config.ini")).unwrap();
    assert!(config.sidebar_collapsed, "Einklappen wird sofort gespeichert");
    let mut h = window(a, true);
    settle(&mut h);
    click(&mut h, "»");
    assert!(!app(&h).test_config().sidebar_collapsed);
    let mut a = h.into_state().unwrap();
    a.detach();
    let config = Config::load(&dir.join("config.ini")).unwrap();
    assert!((340.0..=380.0).contains(&config.sidebar_width.unwrap()), "Breite gespeichert");
    drop(a);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn window_state_keeps_normal_size_while_maximized() {
    use crate::app::track_window;
    use crate::config::WindowState;
    let mut state = WindowState::default();
    // Wie unter Wayland: ohne inner_rect, die Größe kommt von der Zeichenfläche.
    let mut info = egui::ViewportInfo {
        outer_rect: Some(egui::Rect::from_min_size(egui::pos2(100.0, 50.0), egui::vec2(1300.0, 850.0))),
        maximized: Some(false),
        ..Default::default()
    };
    track_window(&mut state, &info, egui::vec2(1300.0, 820.0));
    assert_eq!(state, WindowState { width: Some(1300.0), height: Some(820.0), x: Some(100.0), y: Some(50.0), maximized: false });
    info.maximized = Some(true);
    track_window(&mut state, &info, egui::vec2(3440.0, 1380.0));
    assert!(state.maximized);
    assert_eq!(state.width, Some(1300.0), "normale Größe bleibt für das Wiederherstellen");
    // Wayland: keine Position, der alte Wert bleibt stehen.
    info.maximized = Some(false);
    info.outer_rect = None;
    track_window(&mut state, &info, egui::vec2(1300.0, 820.0));
    assert_eq!((state.x, state.y), (Some(100.0), Some(50.0)));
}

#[test]
fn desktop_entry_can_be_installed_from_settings() {
    let dir = temp_dir("desk");
    let mut h = gui(&dir.join("sshelf.db"), true);
    setup_with_connection(&mut h, "Eins");
    h.state_mut().as_mut().unwrap().test_set_desktop(crate::desktop::Locations::under(&dir.join("share")));
    click(&mut h, "Einstellungen");
    click(&mut h, "Ins Anwendungsmenü eintragen");
    let loc = crate::desktop::Locations::under(&dir.join("share"));
    assert_eq!(loc.installed_exe(), Some(std::env::current_exe().unwrap()));
    h.get_by_label_contains("Eingetragen:");
    shot(&mut h, "28-einstellungen-symbol");
    click(&mut h, "Eintrag entfernen");
    assert_eq!(loc.installed_exe(), None);
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn terminal_font_can_be_chosen_and_is_remembered() {
    let dir = temp_dir("font");
    let db = dir.join("sshelf.db");
    // Altbestand: Die Größe stand früher in der Datenbank und wird übernommen.
    Store::open(&db).unwrap().set_setting("font_size", "12").unwrap();
    let mut h = gui(&db, true);
    setup_with_connection(&mut h, "Eins");
    assert_eq!(app(&h).test_font_size(), 12.0);

    click(&mut h, "Einstellungen");
    h.get_all_by_role(Role::ComboBox).next().unwrap().click();
    settle(&mut h);
    pump(&mut h, "Schriftsuche", |h| h.query_by_label("Schriften werden gesucht…").is_none());
    settle(&mut h);
    let wanted = ["JetBrains Mono", "Noto Sans Mono", "DejaVu Sans Mono"]
        .into_iter()
        .find(|f| h.query_by_label(f).is_some());
    let Some(wanted) = wanted else {
        eprintln!("Übersprungen: keine bekannte Monospace-Schrift installiert");
        drop(h);
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    assert!(h.query_by_label("Noto Sans").is_none(), "proportionale Schriften stehen nicht in der Liste");
    shot(&mut h, "29-schriftauswahl");
    h.get_by_label(wanted).click();
    settle(&mut h);
    shot(&mut h, "29b-vorschau");
    let config = Config::load(&dir.join("config.ini")).unwrap();
    assert_eq!(config.terminal_font, wanted);
    drop(h);

    let mut h = gui(&db, true);
    settle(&mut h);
    fill(&mut h, 0, "master-passwort");
    click(&mut h, "Entsperren");
    assert_eq!(app(&h).test_config().terminal_font, wanted, "Schrift beim Neustart geladen");
    assert_eq!(app(&h).test_font_size(), 12.0);
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn collapsed_rail_keeps_groups_collapsed() {
    let dir = temp_dir("railgroups");
    let mut h = gui(&dir.join("sshelf.db"), true);
    setup_with_connection(&mut h, "Ohne");
    create_connection_in(&mut h, "Web 1", None, Some("Kunde A"));
    create_connection_in(&mut h, "Mail", None, Some("Kunde B"));
    click(&mut h, "Gruppe Kunde A");
    assert!(h.query_by_label("Web 1").is_none());

    // Einklappen: Die zugeklappte Gruppe bleibt zu, die offene zeigt ihre Verbindung.
    click(&mut h, "«");
    assert!(h.query_by_label("Web 1").is_none(), "zugeklappte Gruppe darf in der Leiste nicht aufgehen");
    assert!(h.query_by_label("Mail").is_some() && h.query_by_label("Ohne").is_some());
    shot(&mut h, "33-leiste-gruppen");
    // In der Leiste aufklappen; das gilt dann auch für die ausgeklappte Seitenleiste.
    click(&mut h, "Gruppe Kunde A");
    assert!(h.query_by_label("Web 1").is_some());
    click(&mut h, "»");
    assert!(h.query_by_label("Web 1").is_some());
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn about_page_shows_version_and_github_link() {
    let dir = temp_dir("about");
    let mut h = gui(&dir.join("sshelf.db"), true);
    setup_with_connection(&mut h, "Eins");
    click(&mut h, "Über");
    h.get_by_label_contains(&format!("Version {}", env!("CARGO_PKG_VERSION")));
    h.get_by_label("https://github.com/jewink/sshelf");
    shot(&mut h, "34-ueber");
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keys_and_known_hosts_share_one_entry() {
    let dir = temp_dir("keystabs");
    let mut h = gui(&dir.join("sshelf.db"), true);
    setup_with_connection(&mut h, "Eins");
    assert!(h.query_by_label("Bekannte Hosts").is_none(), "kein eigener Eintrag mehr in der Seitenleiste");
    click(&mut h, "Schlüssel & Hosts");
    h.get_by_label("Importieren…");
    click(&mut h, "Bekannte Hosts");
    h.get_by_label_contains("Hostschlüssel, denen du");
    click(&mut h, "Schlüssel");
    h.get_by_label("Importieren…");
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Das Fenster geht zu und wieder auf: Tresor und SSH-Sitzung laufen ohne Fenster weiter.
#[test]
fn sessions_survive_while_the_window_is_closed() {
    let sshd = Sshd::start();
    let dir = temp_dir("hidden");
    let mut h = gui(&dir.join("sshelf.db"), true);
    settle(&mut h);
    fill(&mut h, 0, "master-passwort");
    fill(&mut h, 1, "master-passwort");
    click(&mut h, "Tresor anlegen");
    add_sshd_connection(&mut h, &sshd);
    type_line(&mut h, "sleep 1; echo im-hintergrund-$((40+2))");

    let mut a = h.into_state().unwrap();
    a.detach();
    std::thread::sleep(Duration::from_millis(1500));

    let mut h = window(a, true);
    settle(&mut h);
    assert!(app(&h).test_unlocked(), "Kein erneutes Entsperren nötig");
    assert_eq!(app(&h).test_status(), Some(Status::Connected));
    wait_for_text(&mut h, "im-hintergrund-42");
    type_line(&mut h, "echo wieder-da-$((40+2))");
    wait_for_text(&mut h, "wieder-da-42");
    shot(&mut h, "24-nach-wiederoeffnen");
    drop(h);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Stellt sicher, dass ein hinterlegtes Passwort wirklich aus der Datenbank bis zum Server kommt.
#[test]
fn stored_connection_with_generated_key_roundtrip() {
    let dir = temp_dir("store");
    let store = Store::open(&dir.join("t.db")).unwrap();
    let (dek, _) = Dek::create("x").unwrap();
    let key = keys::generate("neu").unwrap();
    let id = store.insert_key(&key, &dek).unwrap();
    let conn = ConnectionRec { name: "a".into(), host: "h".into(), key_id: Some(id), ..Default::default() };
    store.save_connection(&conn, PasswordChange::Keep, &dek).unwrap();
    let (pem, pass) = store.key_secret(id, &dek).unwrap();
    assert!(pass.is_none());
    assert!(russh::keys::decode_secret_key(&pem, None).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}
