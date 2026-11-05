//! Farben und Stil der Oberfläche, hell und dunkel.

use eframe::egui::{self, Color32, CornerRadius, Margin, Stroke, Visuals};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThemeChoice {
    System,
    Dark,
    Light,
}

impl ThemeChoice {
    pub fn parse(s: &str) -> Self {
        match s {
            "system" => Self::System,
            "light" => Self::Light,
            _ => Self::Dark,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Dark => "dark",
            Self::Light => "light",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::System => "System",
            Self::Dark => "Dunkel",
            Self::Light => "Hell",
        }
    }
}

const NORD0: Color32 = c(0x2e3440);
const NORD1: Color32 = c(0x3b4252);
const NORD2: Color32 = c(0x434c5e);
const NORD3: Color32 = c(0x4c566a);
const NORD4: Color32 = c(0xd8dee9);
const NORD5: Color32 = c(0xe5e9f0);
const NORD6: Color32 = c(0xeceff4);
const NORD7: Color32 = c(0x8fbcbb);
const NORD8: Color32 = c(0x88c0d0);
const NORD9: Color32 = c(0x81a1c1);
const NORD10: Color32 = c(0x5e81ac);
const NORD11: Color32 = c(0xbf616a);
const NORD13: Color32 = c(0xebcb8b);
const NORD14: Color32 = c(0xa3be8c);
const NORD15: Color32 = c(0xb48ead);
/// Eine Stufe dunkler als nord0, für Seitenleiste und Eingabefelder.
const NORD_DEEP: Color32 = c(0x272c36);

/// Farben, die in der App selbst gebraucht werden (zusätzlich zu den egui-Visuals).
#[derive(Clone, Copy)]
pub struct Colors {
    pub accent: Color32,
    pub accent_soft: Color32,
    pub on_accent: Color32,
    pub sidebar: Color32,
    pub surface: Color32,
    pub panel: Color32,
    pub border: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub danger: Color32,
    pub success: Color32,
    pub warning: Color32,
}

pub fn colors(dark: bool) -> Colors {
    if dark {
        // Nord (https://www.nordtheme.com), Akzent ist das Frost-Blau nord9.
        Colors {
            accent: NORD9,
            accent_soft: NORD2,
            on_accent: NORD0,
            sidebar: NORD_DEEP,
            surface: NORD0,
            panel: NORD1,
            border: NORD2,
            text: NORD6,
            // Aufgehellt gegenüber nord3 und nord11, die auf nord1 zu wenig Kontrast für Text haben.
            muted: c(0xaeb8c9),
            danger: c(0xe59aa2),
            success: NORD14,
            warning: NORD13,
        }
    } else {
        // Nord in hell: Snow Storm als Flächen, nord10 als Akzent. Text und Warnfarben sind
        // abgedunkelt, weil die Aurora-Töne auf hellem Grund zu wenig Kontrast haben.
        Colors {
            accent: NORD10,
            accent_soft: c(0xd5e0ec),
            on_accent: Color32::WHITE,
            sidebar: NORD5,
            surface: NORD6,
            panel: Color32::WHITE,
            border: NORD4,
            text: NORD0,
            muted: NORD3,
            danger: c(0xa5434d),
            success: c(0x4f7a3c),
            warning: c(0x8a6412),
        }
    }
}

fn visuals(dark: bool) -> Visuals {
    let c = colors(dark);
    let mut v = if dark { Visuals::dark() } else { Visuals::light() };
    v.override_text_color = Some(c.text);
    v.panel_fill = c.surface;
    v.window_fill = c.panel;
    v.extreme_bg_color = if dark { NORD_DEEP } else { Color32::WHITE };
    v.faint_bg_color = c.panel;
    v.window_stroke = Stroke::new(1.0, c.border);
    v.window_corner_radius = CornerRadius::same(12);
    v.menu_corner_radius = CornerRadius::same(8);
    v.selection.bg_fill = c.accent_soft;
    v.selection.stroke = Stroke::new(1.0, c.accent);
    v.hyperlink_color = c.accent;
    v.slider_trailing_fill = true;
    v.error_fg_color = c.danger;
    v.warn_fg_color = c.warning;
    let radius = CornerRadius::same(7);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = radius;
        w.expansion = 0.0;
    }
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, c.border);
    // bg_fill ist u. a. die Schiene des Sliders, weak_bg_fill die Fläche der Buttons.
    v.widgets.inactive.bg_fill = c.border;
    v.widgets.inactive.weak_bg_fill = c.panel;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, c.border);
    v.widgets.hovered.bg_fill = c.accent_soft;
    v.widgets.hovered.weak_bg_fill = c.accent_soft;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, c.accent);
    v.widgets.active.bg_fill = c.accent_soft;
    v.widgets.active.weak_bg_fill = c.accent_soft;
    v.widgets.active.bg_stroke = Stroke::new(1.0, c.accent);
    v
}

pub fn apply_style(ctx: &egui::Context) {
    ctx.set_visuals_of(egui::Theme::Dark, visuals(true));
    ctx.set_visuals_of(egui::Theme::Light, visuals(false));
    ctx.all_styles_mut(|s| {
        s.spacing.item_spacing = egui::vec2(8.0, 8.0);
        s.spacing.button_padding = egui::vec2(12.0, 6.0);
        s.spacing.interact_size.y = 30.0;
        s.spacing.window_margin = Margin::same(20);
        s.text_styles.insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
        s.text_styles.insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
        s.text_styles.insert(egui::TextStyle::Small, egui::FontId::proportional(12.0));
        s.text_styles.insert(egui::TextStyle::Heading, egui::FontId::proportional(21.0));
        s.text_styles.insert(egui::TextStyle::Monospace, egui::FontId::monospace(13.0));
        s.interaction.selectable_labels = false;
    });
}

/// Systemschrift als Rückfall hinzufügen. Fehlt sie, erscheint für das Zeichen nur ein Kästchen;
/// das Programm selbst kommt ohne installierte Schriften aus.
fn add_fallback_font(ctx: &egui::Context, name: &str, candidates: &[&str]) {
    let Some(bytes) = candidates.iter().find_map(|p| std::fs::read(p).ok()) else { return };
    let data = egui::FontData::from_owned(bytes);
    let families = [egui::FontFamily::Monospace, egui::FontFamily::Proportional]
        .map(|family| egui::epaint::text::InsertFontFamily {
            family,
            priority: egui::epaint::text::FontPriority::Lowest,
        })
        .to_vec();
    ctx.add_font(egui::epaint::text::FontInsert::new(name, data, families));
}

/// Für Symbole wie ✓, die den eingebauten Schriften fehlen. Klein, darum gleich beim Start.
pub fn load_symbol_font(ctx: &egui::Context) {
    add_fallback_font(
        ctx,
        "system-symbols",
        &[
            "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/dejavu-sans-mono-fonts/DejaVuSansMono.ttf",
            "/usr/share/fonts/noto/NotoSansMono-Regular.ttf",
            "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
            "/usr/share/fonts/noto/NotoSansSymbols2-Regular.ttf",
            "/usr/share/fonts/truetype/noto/NotoSansSymbols2-Regular.ttf",
        ],
    );
}

/// CJK-Schriften sind viele Megabyte groß und werden erst geladen, wenn sie gebraucht werden.
pub fn load_cjk_font(ctx: &egui::Context) {
    // Merkt sich pro Fenster-Kontext, ob es schon versucht wurde.
    let tried = egui::Id::unique("cjk-font-tried");
    if ctx.data_mut(|d| *d.get_temp_mut_or_default::<bool>(tried)) {
        return;
    }
    ctx.data_mut(|d| d.insert_temp(tried, true));
    add_fallback_font(
        ctx,
        "system-cjk",
        &[
            "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
            "/usr/share/fonts/wenquanyi/wqy-microhei/wqy-microhei.ttc",
            "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
        ],
    );
}

/// Farbschema des Terminals.
#[derive(Clone, Copy)]
pub struct TermPalette {
    pub fg: Color32,
    pub bg: Color32,
    pub cursor: Color32,
    pub selection: Color32,
    pub ansi: [Color32; 16],
}

const fn c(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

impl TermPalette {
    pub fn for_mode(dark: bool) -> Self {
        if dark {
            Self {
                // Offizielle Belegung der Nord-Terminalthemen.
                fg: NORD4,
                bg: NORD0,
                cursor: NORD4,
                selection: NORD2,
                ansi: [
                    NORD1, NORD11, NORD14, NORD13,
                    NORD9, NORD15, NORD8, NORD5,
                    NORD3, NORD11, NORD14, NORD13,
                    NORD9, NORD15, NORD7, NORD6,
                ],
            }
        } else {
            Self {
                fg: NORD0,
                bg: NORD6,
                cursor: NORD10,
                selection: c(0xc9d6e6),
                ansi: [
                    c(0x24262f), c(0xc4262e), c(0x1a7f37), c(0x956400),
                    NORD10, c(0x8430c4), c(0x0a7a8f), c(0x8a8d9a),
                    c(0x5c5f6c), c(0xdd3b44), c(0x22963f), c(0xad7800),
                    c(0x4c6f96), c(0x9a47da), c(0x128fa6), c(0xb0b3c0),
                ],
            }
        }
    }
}
