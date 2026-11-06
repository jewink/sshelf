//! Programmsymbol und Eintrag im Anwendungsmenü.
//!
//! Unter Linux können ausführbare Dateien kein eigenes Symbol enthalten; Dateimanager zeigen für
//! sie immer das Symbol des Dateityps. Ein Symbol erscheint über eine `.desktop`-Datei: im
//! Anwendungsmenü, in Fensterleiste und Titelzeile und, als Starter neben dem Programm abgelegt,
//! auch im Dateimanager.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Das Symbol als Vektorgrafik. Muss zu [`rgba`] passen.
pub const SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">
  <defs>
    <linearGradient id="bg" x1="0" y1="16" x2="0" y2="240" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#434C5E"/>
      <stop offset="1" stop-color="#2E3440"/>
    </linearGradient>
  </defs>
  <rect x="16" y="16" width="224" height="224" rx="52" fill="url(#bg)" stroke="#4C566A" stroke-width="4"/>
  <path d="M76 92 L120 128 L76 164" fill="none" stroke="#88C0D0" stroke-width="22" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M136 164 H180" fill="none" stroke="#ECEFF4" stroke-width="22" stroke-linecap="round"/>
</svg>
"##;

const BG_TOP: [f32; 3] = [0x43 as f32, 0x4c as f32, 0x5e as f32];
const BG_BOTTOM: [f32; 3] = [0x2e as f32, 0x34 as f32, 0x40 as f32];
const BORDER: [f32; 3] = [0x4c as f32, 0x56 as f32, 0x6a as f32];
const FROST: [f32; 3] = [0x88 as f32, 0xc0 as f32, 0xd0 as f32];
const SNOW: [f32; 3] = [0xec as f32, 0xef as f32, 0xf4 as f32];

fn sd_round_rect(px: f32, py: f32) -> f32 {
    // Mitte 128/128, halbe Kantenlänge 112, Radius 52 (wie im SVG).
    let qx = (px - 128.0).abs() - (112.0 - 52.0);
    let qy = (py - 128.0).abs() - (112.0 - 52.0);
    let outside = (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt();
    outside + qx.max(qy).min(0.0) - 52.0
}

fn dist_segment(px: f32, py: f32, a: (f32, f32), b: (f32, f32)) -> f32 {
    let (dx, dy) = (b.0 - a.0, b.1 - a.1);
    let t = (((px - a.0) * dx + (py - a.1) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0);
    ((px - a.0 - t * dx).powi(2) + (py - a.1 - t * dy).powi(2)).sqrt()
}

/// Farbe und Deckkraft an einem Punkt der 256er-Vorlage.
fn sample(px: f32, py: f32) -> Option<[f32; 3]> {
    let d = sd_round_rect(px, py);
    if d > 2.0 {
        return None;
    }
    if dist_segment(px, py, (76.0, 92.0), (120.0, 128.0)) <= 11.0 || dist_segment(px, py, (120.0, 128.0), (76.0, 164.0)) <= 11.0 {
        return Some(FROST);
    }
    if dist_segment(px, py, (136.0, 164.0), (180.0, 164.0)) <= 11.0 {
        return Some(SNOW);
    }
    if d >= -2.0 {
        return Some(BORDER);
    }
    let t = ((py - 16.0) / 224.0).clamp(0.0, 1.0);
    Some([0, 1, 2].map(|i| BG_TOP[i] + (BG_BOTTOM[i] - BG_TOP[i]) * t))
}

/// Das Symbol als RGBA-Pixel in beliebiger Größe, geglättet durch 4×4-Abtastung je Pixel.
pub fn rgba(size: u32) -> Vec<u8> {
    const N: u32 = 4;
    let scale = 256.0 / size as f32;
    let mut out = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let mut sum = [0.0f32; 3];
            let mut hits = 0u32;
            for sy in 0..N {
                for sx in 0..N {
                    let px = (x as f32 + (sx as f32 + 0.5) / N as f32) * scale;
                    let py = (y as f32 + (sy as f32 + 0.5) / N as f32) * scale;
                    if let Some(c) = sample(px, py) {
                        for i in 0..3 {
                            sum[i] += c[i];
                        }
                        hits += 1;
                    }
                }
            }
            if hits == 0 {
                out.extend_from_slice(&[0, 0, 0, 0]);
            } else {
                let h = hits as f32;
                out.extend_from_slice(&[
                    (sum[0] / h) as u8,
                    (sum[1] / h) as u8,
                    (sum[2] / h) as u8,
                    (255 * hits / (N * N)) as u8,
                ]);
            }
        }
    }
    out
}

/// Quoting für `Exec=` nach der Desktop-Entry-Spezifikation.
fn exec_quote(path: &Path) -> String {
    let mut out = String::from("\"");
    for ch in path.display().to_string().chars() {
        match ch {
            '"' | '`' | '$' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            '%' => out.push_str("%%"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn entry(exe: &Path, icon: &str) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nName=SSHelf\nGenericName=SSH-Verbindungen\n\
         Comment=SSH-Verbindungen verwalten und öffnen\nExec={}\nIcon={icon}\nTerminal=false\n\
         Categories=Network;RemoteAccess;\nKeywords=ssh;terminal;remote;server;\n\
         StartupWMClass=sshelf\nStartupNotify=true\n",
        exec_quote(exe)
    )
}

/// Wo Menüeintrag und Symbol liegen (`$XDG_DATA_HOME`, meist `~/.local/share`).
pub struct Locations {
    pub desktop_file: PathBuf,
    pub icon_file: PathBuf,
}

impl Locations {
    pub fn user() -> Result<Locations> {
        let base = directories::BaseDirs::new().context("Kein Home-Verzeichnis gefunden")?;
        Ok(Locations::under(base.data_dir()))
    }

    pub fn under(data_dir: &Path) -> Locations {
        Locations {
            // Der Name muss zur App-ID „sshelf“ passen, damit Wayland das Fenster zuordnet.
            desktop_file: data_dir.join("applications/sshelf.desktop"),
            icon_file: data_dir.join("icons/hicolor/scalable/apps/sshelf.svg"),
        }
    }

    fn write_icon(&self) -> Result<()> {
        let dir = self.icon_file.parent().context("Ungültiger Pfad")?;
        std::fs::create_dir_all(dir).with_context(|| format!("Ordner {} anlegen", dir.display()))?;
        std::fs::write(&self.icon_file, SVG).with_context(|| format!("{} schreiben", self.icon_file.display()))?;
        // Signalisiert GTK-basierten Oberflächen, dass sich das Symbolthema geändert hat.
        if let Some(theme) = self.icon_file.ancestors().nth(3) {
            let _ = std::fs::File::open(theme).and_then(|f| f.set_modified(std::time::SystemTime::now()));
        }
        Ok(())
    }

    /// Trägt SSHelf mit Symbol ins Anwendungsmenü ein.
    pub fn install(&self, exe: &Path) -> Result<()> {
        self.write_icon()?;
        let dir = self.desktop_file.parent().context("Ungültiger Pfad")?;
        std::fs::create_dir_all(dir).with_context(|| format!("Ordner {} anlegen", dir.display()))?;
        std::fs::write(&self.desktop_file, entry(exe, "sshelf"))
            .with_context(|| format!("{} schreiben", self.desktop_file.display()))
    }

    pub fn uninstall(&self) -> Result<()> {
        for f in [&self.desktop_file, &self.icon_file] {
            match std::fs::remove_file(f) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("{} löschen", f.display())),
            }
        }
        Ok(())
    }

    /// Auf welches Programm zeigt der vorhandene Menüeintrag?
    pub fn installed_exe(&self) -> Option<PathBuf> {
        let text = std::fs::read_to_string(&self.desktop_file).ok()?;
        let exec = text.lines().find_map(|l| l.strip_prefix("Exec="))?;
        let inner = exec.trim().strip_prefix('"')?.strip_suffix('"')?;
        let mut path = String::new();
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => path.extend(chars.next()),
                '%' => {
                    chars.next();
                    path.push('%');
                }
                _ => path.push(ch),
            }
        }
        Some(PathBuf::from(path))
    }

    /// Legt `SSHelf.desktop` neben das Programm. Dateimanager zeigen diesen Starter mit Symbol.
    pub fn write_launcher_next_to(&self, exe: &Path) -> Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        self.write_icon()?;
        let dir = exe.parent().context("Ungültiger Programmpfad")?;
        let launcher = dir.join("SSHelf.desktop");
        // Absoluter Symbolpfad: funktioniert auch, wenn das Symbolthema den Namen nicht kennt.
        std::fs::write(&launcher, entry(exe, &self.icon_file.display().to_string()))
            .with_context(|| format!("{} schreiben", launcher.display()))?;
        // Ohne Ausführungsrecht lehnen KDE und GNOME das Starten ab.
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))?;
        Ok(launcher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PathBuf {
        let mut b = [0u8; 6];
        getrandom::fill(&mut b).unwrap();
        let id: String = b.iter().map(|x| format!("{x:02x}")).collect();
        std::env::temp_dir().join(format!("sshelf-desktop-{id}"))
    }

    #[test]
    fn install_status_and_uninstall() {
        let dir = temp();
        let loc = Locations::under(&dir.join("share"));
        assert_eq!(loc.installed_exe(), None);
        let exe = dir.join("Mein Ordner/100% \"echt\"/sshelf");
        loc.install(&exe).unwrap();
        let text = std::fs::read_to_string(&loc.desktop_file).unwrap();
        assert!(text.contains("Icon=sshelf\n"), "{text}");
        assert!(text.contains(r#"Exec="#), "{text}");
        assert!(text.contains("100%%"), "Prozent muss verdoppelt werden: {text}");
        assert_eq!(loc.installed_exe(), Some(exe.clone()), "Pfad muss zurückgelesen werden können");
        assert!(std::fs::read_to_string(&loc.icon_file).unwrap().starts_with("<svg"));
        loc.uninstall().unwrap();
        assert!(!loc.desktop_file.exists() && !loc.icon_file.exists());
        loc.uninstall().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn launcher_next_to_program_is_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp();
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let loc = Locations::under(&dir.join("share"));
        let launcher = loc.write_launcher_next_to(&dir.join("bin/sshelf")).unwrap();
        assert_eq!(launcher, dir.join("bin/SSHelf.desktop"));
        assert_eq!(std::fs::metadata(&launcher).unwrap().permissions().mode() & 0o777, 0o755);
        let text = std::fs::read_to_string(&launcher).unwrap();
        assert!(text.contains(&format!("Icon={}", loc.icon_file.display())), "{text}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn raster_icon_matches_the_design() {
        let px = |img: &[u8], size: u32, x: u32, y: u32| {
            let i = ((y * size + x) * 4) as usize;
            [img[i], img[i + 1], img[i + 2], img[i + 3]]
        };
        let img = rgba(256);
        assert_eq!(px(&img, 256, 2, 2)[3], 0, "Ecke durchsichtig");
        assert_eq!(px(&img, 256, 98, 110), [0x88, 0xc0, 0xd0, 255], "Spitze Klammer in Frost-Blau");
        assert_eq!(px(&img, 256, 158, 164), [0xec, 0xef, 0xf4, 255], "Unterstrich hell");
        assert_eq!(px(&img, 256, 200, 60)[3], 255, "Fläche deckend");
        let small = rgba(22);
        assert_eq!(small.len(), 22 * 22 * 4);
    }
}
