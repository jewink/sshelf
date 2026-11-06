//! Schriftrückfall wie bei anderen Terminals: Fehlt den eingebauten Schriften ein Zeichen, wird
//! eine installierte Systemschrift gesucht, die es enthält.
//!
//! Stufe 1 fragt fontconfig nach der passenden Schrift für Schriftsystem und Sprache
//! (`egui_system_font_provider`). Symbole ohne Schriftsystem, etwa die Icons der Nerd Fonts in
//! Shell-Prompts, findet das nur in den Standardfamilien. Stufe 2 durchsucht darum notfalls alle
//! installierten Schriften, Mono-Schriften zuerst.
//!
//! Schriften werden erst beim ersten fehlenden Zeichen geladen und per Memory-Mapping eingebunden.
//! egui fragt je Zeichen höchstens einmal; eine gefundene Schrift deckt danach auch die
//! verwandten Zeichen ab. Ohne passende Systemschrift bleibt es beim Kästchen.

use eframe::egui::epaint::text::{FallbackRequest, FontData, FontFamily, FontInsert, FontPriority, FontProvider, InsertFontFamily};
use egui_system_font_provider::SystemFontProvider;
use fontique::{Collection, CollectionOptions, FamilyId, SourceCache, SourceCacheOptions};
use parking_lot::Mutex;

struct Scan {
    collection: Collection,
    cache: SourceCache,
    /// Familien in Suchreihenfolge: Mono-Schriften zuerst.
    mono_first: Vec<FamilyId>,
}

impl Scan {
    fn new() -> Scan {
        let mut collection = Collection::new(CollectionOptions { shared: false, system_fonts: true });
        let mut names: Vec<String> = collection.family_names().map(str::to_owned).collect();
        names.sort_by_key(|n| (!n.to_lowercase().contains("mono"), n.to_lowercase()));
        let mono_first = names.iter().filter_map(|n| collection.family_id(n)).collect();
        Scan { collection, cache: SourceCache::new(SourceCacheOptions::default()), mono_first }
    }

    fn find(&mut self, c: char, family: &FontFamily) -> Option<FontInsert> {
        let mut order = self.mono_first.clone();
        if *family != FontFamily::Monospace {
            // Für normalen Text proportionale Schriften bevorzugen.
            order.sort_by_key(|id| {
                self.collection.family_name(*id).is_some_and(|n| n.to_lowercase().contains("mono"))
            });
        }
        for id in order {
            let Some(info) = self.collection.family(id) else { continue };
            let Some(font) = info.default_font().or_else(|| info.fonts().first()) else { continue };
            let Some(blob) = font.load(Some(&mut self.cache)) else { continue };
            if !can_render(blob.as_ref(), font.index(), font.charmap_index(), c) {
                continue;
            }
            let name = format!("scan:{}:{}", info.name(), font.index());
            let index = font.index();
            let (blob, _) = blob.into_raw_parts();
            return Some(FontInsert {
                name,
                data: FontData::from_blob(blob, index),
                families: vec![InsertFontFamily { family: family.clone(), priority: FontPriority::Lowest }],
            });
        }
        None
    }
}

/// Hat die Schrift eine zeichenbare Glyphe (Umriss, Farbglyphe oder Bitmap) für `c`?
fn can_render(data: &[u8], index: u32, charmap: fontique::CharmapIndex, c: char) -> bool {
    use skrifa::MetadataProvider as _;
    let Some(glyph) = charmap.charmap(data).and_then(|m| m.map(c)) else { return false };
    let glyph = skrifa::GlyphId::new(glyph);
    if glyph == skrifa::GlyphId::NOTDEF {
        return false;
    }
    let Ok(font) = skrifa::FontRef::from_index(data, index) else { return false };
    font.outline_glyphs().get(glyph).is_some()
        || font.color_glyphs().get(glyph).is_some()
        || font.bitmap_strikes().glyph_for_size(skrifa::instance::Size::unscaled(), glyph).is_some()
}

pub struct TerminalFonts {
    system: SystemFontProvider,
    scan: Mutex<Option<Scan>>,
}

impl TerminalFonts {
    pub fn new() -> TerminalFonts {
        TerminalFonts { system: SystemFontProvider::new(), scan: Mutex::new(None) }
    }
}

impl FontProvider for TerminalFonts {
    fn font_for(&self, request: &FallbackRequest<'_>) -> Option<FontInsert> {
        if let Some(found) = self.system.font_for(request) {
            return Some(found);
        }
        let c = request.cluster.chars().next()?;
        // Steuer- und Leerzeichen hat keine Schrift sinnvoll.
        if c.is_control() || c.is_whitespace() {
            return None;
        }
        let mut scan = self.scan.lock();
        scan.get_or_insert_with(Scan::new).find(c, request.family)
    }
}

/// Name der Schriftfamilie für fetten Terminaltext, falls ein echter Fettschnitt gefunden wurde.
pub const BOLD_FAMILY: &str = "terminal-bold";

/// Sucht den echten Fettschnitt der eingebauten Terminalschrift Hack unter den Systemschriften.
/// KDE installiert Hack standardmäßig. Fehlt er, zeichnet das Terminal fetten Text doppelt.
fn find_hack_bold() -> Option<FontInsert> {
    let mut collection = Collection::new(CollectionOptions { shared: false, system_fonts: true });
    let mut cache = SourceCache::new(SourceCacheOptions::default());
    let family = collection.family_by_name("Hack")?;
    let font = family
        .fonts()
        .iter()
        .find(|f| f.weight().value() >= 650.0 && f.style() == fontique::FontStyle::Normal)?;
    let blob = font.load(Some(&mut cache))?;
    let index = font.index();
    let (blob, _) = blob.into_raw_parts();
    let mut data = FontData::from_blob(blob, index);
    data.tweak = crate::theme::sharp_tweak();
    Some(FontInsert {
        name: "Hack-Bold (System)".into(),
        data,
        families: vec![InsertFontFamily { family: FontFamily::Name(BOLD_FAMILY.into()), priority: FontPriority::Highest }],
    })
}

/// Die Datei des Hack-Fettschnitts für FreeType (siehe `glyphs`). Wird nur einmal gesucht.
pub fn hack_bold_bytes() -> Option<std::sync::Arc<[u8]>> {
    static BOLD: std::sync::OnceLock<Option<std::sync::Arc<[u8]>>> = std::sync::OnceLock::new();
    BOLD.get_or_init(|| {
        let mut collection = Collection::new(CollectionOptions { shared: false, system_fonts: true });
        let mut cache = SourceCache::new(SourceCacheOptions::default());
        let family = collection.family_by_name("Hack")?;
        let font = family
            .fonts()
            .iter()
            .find(|f| f.weight().value() >= 650.0 && f.style() == fontique::FontStyle::Normal)?;
        // FreeType kann nur ganze Dateien öffnen; Sammeldateien (.ttc) hier nicht unterstützt.
        if font.index() != 0 {
            return None;
        }
        let blob = font.load(Some(&mut cache))?;
        Some(std::sync::Arc::from(blob.as_ref()))
    })
    .clone()
}

/// Meldet Schriftrückfall und (falls vorhanden) den Fettschnitt an einem Fenster-Kontext an.
/// Gibt zurück, ob ein echter Fettschnitt verfügbar ist.
pub fn install(ctx: &eframe::egui::Context) -> bool {
    ctx.add_font_provider(std::sync::Arc::new(TerminalFonts::new()));
    match find_hack_bold() {
        Some(bold) => {
            ctx.add_font(bold);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gibt es auf diesem Rechner eine Schrift mit dem Zeichen? Sonst kann der Test nichts prüfen.
    fn installed(c: char) -> bool {
        std::process::Command::new("fc-list")
            .arg(format!(":charset={:x}", c as u32))
            .output()
            .is_ok_and(|o| !o.stdout.is_empty())
    }

    #[test]
    fn finds_fonts_for_scripts_symbols_and_nerd_icons() {
        let fonts = TerminalFonts::new();
        // CJK, Powerline-Pfeil und Git-Zweig aus den Nerd Fonts, Rakete als Emoji.
        for c in ['日', '\u{e0b0}', '\u{e725}', '🚀'] {
            if !installed(c) {
                eprintln!("Übersprungen, keine Schrift mit U+{:04X} installiert", c as u32);
                continue;
            }
            let cluster = c.to_string();
            let found = fonts.font_for(&FallbackRequest { cluster: &cluster, family: &FontFamily::Monospace });
            assert!(found.is_some(), "Keine Schrift gefunden für U+{:04X}", c as u32);
        }
    }

    #[test]
    fn nerd_icons_need_the_full_scan() {
        // Genau das deckt fontconfig allein nicht ab: Symbole ohne Schriftsystem.
        let c = '\u{e725}';
        if !installed(c) {
            eprintln!("Übersprungen, keine Nerd Font installiert");
            return;
        }
        let cluster = c.to_string();
        let request = FallbackRequest { cluster: &cluster, family: &FontFamily::Monospace };
        let found = Scan::new().find(c, &FontFamily::Monospace).expect("Suche über alle Schriften");
        assert!(found.name.starts_with("scan:"), "{}", found.name);
        let _ = request;
    }

    #[test]
    fn real_bold_is_found_when_hack_bold_is_installed() {
        let installed = std::process::Command::new("fc-list")
            .args(["Hack:style=Bold", "family"])
            .output()
            .is_ok_and(|o| !o.stdout.is_empty());
        if !installed {
            eprintln!("Übersprungen, Hack Bold ist nicht installiert");
            return;
        }
        let bold = find_hack_bold().expect("Hack Bold");
        assert!(bold.name.contains("Bold"));
    }

    #[test]
    fn unknown_characters_stay_missing() {
        let fonts = TerminalFonts::new();
        let cluster = '\u{10fffd}'.to_string();
        assert!(fonts.font_for(&FallbackRequest { cluster: &cluster, family: &FontFamily::Monospace }).is_none());
    }
}
