//! Einstellungen, die schon vor dem Öffnen der Datenbank bekannt sein müssen. Sie liegen in einer
//! INI-Datei, standardmäßig `~/.config/sshelf/config.ini`.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Config {
    pub db_path: Option<PathBuf>,
    pub close_to_tray: bool,
}

/// Woher der Datenbankpfad stammt.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Source {
    Cli,
    Config,
    Portable,
    Default,
}

pub fn default_config_path() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "sshelf").context("Kein Home-Verzeichnis gefunden")?;
    Ok(dirs.config_dir().join("config.ini"))
}

pub fn default_db_path() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "sshelf").context("Kein Home-Verzeichnis gefunden")?;
    Ok(dirs.data_dir().join("sshelf.db"))
}

fn portable_db_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.join("sshelf.db");
    path.exists().then_some(path)
}

/// Löst `~/` auf.
pub fn expand(raw: &str) -> PathBuf {
    let raw = raw.trim();
    match (raw.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => Path::new(&home).join(rest),
        _ => PathBuf::from(raw),
    }
}

/// Prüft einen eingegebenen Pfad. Ein Ordner bekommt den Standard-Dateinamen angehängt.
pub fn normalize_db_path(raw: &str) -> Result<PathBuf> {
    if raw.trim().is_empty() {
        bail!("Bitte einen Pfad eingeben.");
    }
    let path = expand(raw);
    if !path.is_absolute() {
        bail!("Bitte einen vollständigen Pfad angeben (beginnend mit / oder ~/).");
    }
    Ok(if path.is_dir() { path.join("sshelf.db") } else { path })
}

/// Reihenfolge: Kommandozeile, Konfiguration, `sshelf.db` neben dem Programm, Standardort.
pub fn resolve(cli: Option<PathBuf>, config: &Config) -> Result<(PathBuf, Source)> {
    if let Some(path) = cli {
        return Ok((path, Source::Cli));
    }
    if let Some(path) = &config.db_path {
        return Ok((path.clone(), Source::Config));
    }
    if let Some(path) = portable_db_path() {
        return Ok((path, Source::Portable));
    }
    Ok((default_db_path()?, Source::Default))
}

impl Config {
    pub fn parse(text: &str) -> Config {
        let mut config = Config::default();
        let mut section = String::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name.trim().to_lowercase();
                continue;
            }
            let Some((key, value)) = line.split_once('=') else { continue };
            let value = value.trim().trim_matches('"');
            match (section.as_str(), key.trim().to_lowercase().as_str()) {
                ("database", "path") if !value.is_empty() => config.db_path = Some(expand(value)),
                ("window", "close_to_tray") => {
                    config.close_to_tray = matches!(value.to_lowercase().as_str(), "true" | "yes" | "on" | "1");
                }
                _ => {}
            }
        }
        config
    }

    /// Eine fehlende Datei ist kein Fehler, dann gelten die Standardwerte.
    pub fn load(path: &Path) -> Result<Config> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Config::parse(&text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e).with_context(|| format!("Konfiguration {} lesen", path.display())),
        }
    }

    fn render(&self) -> String {
        let db = self.db_path.as_ref().map_or(String::new(), |p| p.display().to_string());
        format!(
            "; Einstellungen von SSHelf. Kann von Hand bearbeitet werden.\n\n\
             [database]\n\
             ; Pfad zur Datenbank. Leer: sshelf.db neben dem Programm, sonst der Standardort.\n\
             path = {db}\n\n\
             [window]\n\
             ; true: Das Schließen des Fensters minimiert in die Statusleiste.\n\
             close_to_tray = {}\n",
            self.close_to_tray
        )
    }

    /// Schreibt atomar, damit ein Absturz keine halbe Datei hinterlässt.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).with_context(|| format!("Ordner {} anlegen", dir.display()))?;
        }
        let tmp = path.with_extension("ini.tmp");
        std::fs::write(&tmp, self.render()).with_context(|| format!("{} schreiben", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("{} schreiben", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hand_written_files() {
        let c = Config::parse(
            "; Kommentar\n[Database]\n  PATH = \"/daten/mein ssh.db\"\n\n[window]\nclose_to_tray=YES\nunbekannt=1\nkaputte zeile\n",
        );
        assert_eq!(c.db_path, Some(PathBuf::from("/daten/mein ssh.db")));
        assert!(c.close_to_tray);
        assert_eq!(Config::parse(""), Config::default());
        assert_eq!(Config::parse("path=/falsche/sektion"), Config::default());
    }

    #[test]
    fn roundtrip_through_file() {
        let mut b = [0u8; 6];
        getrandom::fill(&mut b).unwrap();
        let dir = std::env::temp_dir().join(format!("sshelf-cfg-{b:02x?}").replace([' ', ',', '[', ']'], ""));
        let file = dir.join("unter/config.ini");
        assert_eq!(Config::load(&file).unwrap(), Config::default(), "fehlende Datei ist kein Fehler");
        let c = Config { db_path: Some("/a b/c.db".into()), close_to_tray: true };
        c.save(&file).unwrap();
        assert_eq!(Config::load(&file).unwrap(), c);
        let empty = Config::default();
        empty.save(&file).unwrap();
        assert_eq!(Config::load(&file).unwrap(), empty);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_priorities() {
        let cfg = Config { db_path: Some("/c.db".into()), close_to_tray: false };
        assert_eq!(resolve(Some("/x.db".into()), &cfg).unwrap(), ("/x.db".into(), Source::Cli));
        assert_eq!(resolve(None, &cfg).unwrap(), ("/c.db".into(), Source::Config));
        assert_eq!(resolve(None, &Config::default()).unwrap().1, Source::Default);
    }

    #[test]
    fn normalize_rejects_relative_and_empty() {
        assert!(normalize_db_path(" ").is_err());
        assert!(normalize_db_path("relativ/x.db").is_err());
        assert_eq!(normalize_db_path("/a/b.db").unwrap(), PathBuf::from("/a/b.db"));
        let tmp = std::env::temp_dir();
        assert_eq!(normalize_db_path(tmp.to_str().unwrap()).unwrap(), tmp.join("sshelf.db"));
    }
}
