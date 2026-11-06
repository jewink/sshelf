//! SSHelf – schlanke SSH-Verbindungsverwaltung mit eingebautem Terminal.

mod app;
mod config;
mod desktop;
mod fonts;
mod glyphs;
#[cfg(feature = "selfshot")]
mod selfshot;
mod keys;
mod ssh;
mod store;
mod term;
mod theme;
mod tray;
mod vault;

#[cfg(test)]
mod e2e_tests;

use anyhow::{Context, Result, bail};
use eframe::egui;
use std::path::PathBuf;

// Beim Bauen auf einem sehr aktuellen System würden einige Mathefunktionen die neuen Versionen aus
// glibc 2.43 verlangen und das Programm dadurch auf fast allen anderen Systemen unstartbar machen.
// Die alten Versionen berechnen dasselbe, darum werden sie festgelegt. Greift, weil der
// Release-Build (LTO, eine Codegen-Unit) allen Rust-Code in einer Objektdatei zusammenführt.
// Prüfen mit: objdump -T sshelf | grep GLIBC_2.4
#[cfg(all(target_arch = "x86_64", target_env = "gnu"))]
std::arch::global_asm!(
    ".symver atan2f, atan2f@GLIBC_2.2.5",
    ".symver acosf, acosf@GLIBC_2.2.5",
);

const HELP: &str = "SSHelf – SSH-Verbindungen verwalten

Aufruf: sshelf [--db DATEI] [--config DATEI]

  --db DATEI      Diese Datenbank verwenden
  --config DATEI  Diese Konfiguration verwenden (Standard: ~/.config/sshelf/config.ini)
  --install-desktop    Mit Symbol ins Anwendungsmenü eintragen
  --uninstall-desktop  Eintrag und Symbol wieder entfernen
  -h, --help      Diese Hilfe anzeigen
  -V, --version   Version anzeigen

Datenbank: --db, sonst [database] path aus der Konfiguration, sonst sshelf.db
neben dem Programm (falls vorhanden), sonst ~/.local/share/sshelf/sshelf.db.";

/// Das eigentliche `App` lebt länger als ein einzelnes Fenster.
struct Window<'a>(&'a mut app::App);

impl eframe::App for Window<'_> {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.0.draw(ui);
    }
}

fn run() -> Result<()> {
    #[cfg(feature = "selfshot")]
    if let Ok(path) = std::env::var("SSHELF_SELFSHOT") {
        return selfshot::run(path);
    }
    let mut db = None;
    let mut config_path = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--db" => db = Some(PathBuf::from(args.next().context("--db braucht einen Pfad")?)),
            "--config" => config_path = Some(PathBuf::from(args.next().context("--config braucht einen Pfad")?)),
            "--install-desktop" => {
                let exe = std::env::current_exe().context("Programmpfad ermitteln")?;
                desktop::Locations::user()?.install(&exe)?;
                println!("SSHelf ist im Anwendungsmenü eingetragen.");
                return Ok(());
            }
            "--uninstall-desktop" => {
                desktop::Locations::user()?.uninstall()?;
                println!("Eintrag entfernt.");
                return Ok(());
            }
            "-h" | "--help" => {
                println!("{HELP}");
                return Ok(());
            }
            "-V" | "--version" => {
                println!("sshelf {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            other => bail!("Unbekannte Option: {other}\n\n{HELP}"),
        }
    }
    let config_path = match config_path {
        Some(p) => p,
        None => config::default_config_path()?,
    };
    let config = config::Config::load(&config_path)?;
    let (path, source) = config::resolve(db, &config)?;
    let mut app = app::App::new(app::App::open_start_db(path, source), config_path, config, source)?;

    let icon = desktop::rgba(128);
    // Bleibt das Symbol in der Statusleiste, läuft diese Schleife weiter: Das Fenster wird
    // geschlossen und bei Bedarf neu erzeugt, Sitzungen und Tresor bleiben dabei erhalten.
    loop {
        let options = eframe::NativeOptions {
            viewport: app.viewport_builder(&icon),
            // Den Schriftrückfall meldet die App selbst an (fonts.rs), auch für die Tests.
            system_font_fallback: false,
            ..Default::default()
        };
        eframe::run_native(
            "SSHelf",
            options,
            Box::new(|cc| {
                app.attach(&cc.egui_ctx);
                Ok(Box::new(Window(&mut app)))
            }),
        )
        .map_err(|e| anyhow::anyhow!("Fenster konnte nicht geöffnet werden: {e}"))?;
        app.detach();
        if !app.stay_in_tray() || !app.tray_state().wait_for_show() {
            return Ok(());
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Fehler: {e:#}");
        std::process::exit(1);
    }
}
