//! Terminal-Zustand (alacritty_terminal), Tastatur-/Mauscodierung und Darstellung mit egui.

use crate::ssh::Cmd;
use crate::theme::TermPalette;
use alacritty_terminal::event::{Event, EventListener, WindowSize};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Line, Point, Side};
use alacritty_terminal::selection::{Selection, SelectionType};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Config, Osc52, Term, TermMode};
use alacritty_terminal::vte::ansi::{Color, CursorShape, NamedColor, Processor, Rgb};
use eframe::egui::{self, Color32, FontId, Key, Modifiers, Pos2, Rect, Sense, Stroke, Vec2};
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Connecting(String),
    Connected,
    Closed(String),
    Failed(String),
}

pub struct PromptField {
    pub label: String,
    pub echo: bool,
    pub value: Zeroizing<String>,
}

impl PromptField {
    pub fn new(label: &str, echo: bool) -> Self {
        Self { label: label.into(), echo, value: Zeroizing::new(String::new()) }
    }
    pub fn secret(label: &str) -> Self {
        Self::new(label, false)
    }
}

pub enum Prompt {
    HostKey {
        host: String,
        port: u16,
        algorithm: String,
        fingerprint: String,
        reply: oneshot::Sender<bool>,
    },
    Text {
        title: String,
        message: String,
        fields: Vec<PromptField>,
        reply: oneshot::Sender<Option<Vec<Zeroizing<String>>>>,
    },
}

#[derive(Clone, Copy)]
struct TermSize {
    cols: usize,
    rows: usize,
}

impl Dimensions for TermSize {
    fn total_lines(&self) -> usize {
        self.rows
    }
    fn screen_lines(&self) -> usize {
        self.rows
    }
    fn columns(&self) -> usize {
        self.cols
    }
}

/// Reagiert auf Ereignisse des Terminals. Wird unter der Terminal-Sperre aufgerufen und darf
/// sie deshalb nicht selbst anfordern.
#[derive(Clone)]
pub struct Proxy {
    cmds: mpsc::UnboundedSender<Cmd>,
    title: Arc<Mutex<Option<String>>>,
    dark: Arc<AtomicBool>,
    size: Arc<Mutex<(u16, u16, u16, u16)>>,
}

impl EventListener for Proxy {
    fn send_event(&self, event: Event) {
        match event {
            Event::PtyWrite(text) => {
                let _ = self.cmds.send(Cmd::Input(text.into_bytes()));
            }
            Event::Title(t) => *self.title.lock() = Some(t),
            Event::ResetTitle => *self.title.lock() = None,
            Event::ColorRequest(index, format) => {
                let p = TermPalette::for_mode(self.dark.load(Ordering::Relaxed));
                let c = p.request_color(index);
                let _ = self.cmds.send(Cmd::Input(format(c).into_bytes()));
            }
            Event::TextAreaSizeRequest(format) => {
                let (cols, rows, w, h) = *self.size.lock();
                let size = WindowSize {
                    num_lines: rows,
                    num_cols: cols,
                    cell_width: w / cols.max(1),
                    cell_height: h / rows.max(1),
                };
                let _ = self.cmds.send(Cmd::Input(format(size).into_bytes()));
            }
            // Zwischenablage-Zugriffe (OSC 52) sind in der Konfiguration abgeschaltet.
            _ => {}
        }
    }
}

/// Gemeinsamer Zustand von SSH-Task und Oberfläche.
pub struct Shared {
    term: Mutex<Term<Proxy>>,
    parser: Mutex<Processor>,
    status: Mutex<Status>,
    prompt: Mutex<Option<Prompt>>,
    title: Arc<Mutex<Option<String>>>,
    dark: Arc<AtomicBool>,
    size: Arc<Mutex<(u16, u16, u16, u16)>>,
    /// Fehlt, solange kein Fenster offen ist.
    repaint: Mutex<Option<egui::Context>>,
}

impl Shared {
    pub fn new(cmds: mpsc::UnboundedSender<Cmd>, repaint: egui::Context, dark: bool) -> Arc<Shared> {
        let title = Arc::new(Mutex::new(None));
        let dark = Arc::new(AtomicBool::new(dark));
        let size = Arc::new(Mutex::new((80u16, 24u16, 640u16, 384u16)));
        let proxy = Proxy { cmds, title: title.clone(), dark: dark.clone(), size: size.clone() };
        let config = Config {
            scrolling_history: 10_000,
            // Ein Server darf die Zwischenablage weder lesen noch schreiben.
            osc52: Osc52::Disabled,
            ..Default::default()
        };
        let term = Term::new(config, &TermSize { cols: 80, rows: 24 }, proxy);
        Arc::new(Shared {
            term: Mutex::new(term),
            parser: Mutex::new(Processor::new()),
            status: Mutex::new(Status::Connecting("Verbinde…".into())),
            prompt: Mutex::new(None),
            title,
            dark,
            size,
            repaint: Mutex::new(Some(repaint)),
        })
    }

    pub fn set_repaint(&self, ctx: Option<egui::Context>) {
        *self.repaint.lock() = ctx;
    }

    fn request_repaint(&self) {
        if let Some(ctx) = &*self.repaint.lock() {
            ctx.request_repaint();
        }
    }

    pub fn feed(&self, bytes: &[u8]) {
        let mut term = self.term.lock();
        self.parser.lock().advance(&mut *term, bytes);
        drop(term);
        self.request_repaint();
    }

    pub fn set_status(&self, s: Status) {
        *self.status.lock() = s;
        self.request_repaint();
    }

    pub fn status(&self) -> Status {
        self.status.lock().clone()
    }

    pub fn set_prompt(&self, p: Prompt) {
        *self.prompt.lock() = Some(p);
        self.request_repaint();
    }

    pub fn clear_prompt(&self) {
        *self.prompt.lock() = None;
    }

    pub fn prompt(&self) -> parking_lot::MutexGuard<'_, Option<Prompt>> {
        self.prompt.lock()
    }

    pub fn title(&self) -> Option<String> {
        self.title.lock().clone()
    }

    pub fn size(&self) -> (u16, u16, u16, u16) {
        *self.size.lock()
    }

    pub fn set_dark(&self, dark: bool) {
        self.dark.store(dark, Ordering::Relaxed);
    }

    /// Gesamter sichtbarer Text, für Tests.
    #[cfg(test)]
    pub fn screen_text(&self) -> String {
        let term = self.term.lock();
        let mut out = String::new();
        let mut last = None;
        for c in term.renderable_content().display_iter {
            if last.is_some_and(|l| l != c.point.line) {
                out.push('\n');
            }
            last = Some(c.point.line);
            out.push(c.c);
        }
        out
    }
}

// --- Tastatur ----------------------------------------------------------------------------

fn csi_mod(m: Modifiers) -> u8 {
    1 + u8::from(m.shift) + 2 * u8::from(m.alt) + 4 * u8::from(m.ctrl)
}

fn letter_key(key: Key) -> Option<u8> {
    use Key::*;
    Some(match key {
        A => b'a', B => b'b', C => b'c', D => b'd', E => b'e', F => b'f', G => b'g', H => b'h',
        I => b'i', J => b'j', K => b'k', L => b'l', M => b'm', N => b'n', O => b'o', P => b'p',
        Q => b'q', R => b'r', S => b's', T => b't', U => b'u', V => b'v', W => b'w', X => b'x',
        Y => b'y', Z => b'z',
        _ => return None,
    })
}

/// Übersetzt eine Taste in die Bytes, die ein xterm senden würde. Normale Zeichen kommen nicht
/// hier an, sondern als `Event::Text`.
pub fn encode_key(key: Key, m: Modifiers, mode: TermMode) -> Option<Vec<u8>> {
    let app_cursor = mode.contains(TermMode::APP_CURSOR);
    let plain = !m.shift && !m.alt && !m.ctrl;
    let esc_if_alt = |b: &[u8]| {
        let mut v = Vec::with_capacity(b.len() + 1);
        if m.alt {
            v.push(0x1b);
        }
        v.extend_from_slice(b);
        v
    };
    let cursor = |c: char| -> Vec<u8> {
        if plain {
            if app_cursor { format!("\x1bO{c}") } else { format!("\x1b[{c}") }.into_bytes()
        } else {
            format!("\x1b[1;{}{c}", csi_mod(m)).into_bytes()
        }
    };
    let tilde = |n: u8| -> Vec<u8> {
        if plain { format!("\x1b[{n}~") } else { format!("\x1b[{n};{}~", csi_mod(m)) }.into_bytes()
    };
    let ss3 = |c: char| -> Vec<u8> {
        if plain { format!("\x1bO{c}") } else { format!("\x1b[1;{}{c}", csi_mod(m)) }.into_bytes()
    };
    Some(match key {
        Key::Enter => esc_if_alt(b"\r"),
        Key::Tab if m.shift => b"\x1b[Z".to_vec(),
        Key::Tab => esc_if_alt(b"\t"),
        Key::Backspace if m.ctrl => esc_if_alt(b"\x08"),
        Key::Backspace => esc_if_alt(b"\x7f"),
        Key::Escape => esc_if_alt(b"\x1b"),
        Key::ArrowUp => cursor('A'),
        Key::ArrowDown => cursor('B'),
        Key::ArrowRight => cursor('C'),
        Key::ArrowLeft => cursor('D'),
        Key::Home => cursor('H'),
        Key::End => cursor('F'),
        Key::Insert => tilde(2),
        Key::Delete => tilde(3),
        Key::PageUp => tilde(5),
        Key::PageDown => tilde(6),
        Key::F1 => ss3('P'),
        Key::F2 => ss3('Q'),
        Key::F3 => ss3('R'),
        Key::F4 => ss3('S'),
        Key::F5 => tilde(15),
        Key::F6 => tilde(17),
        Key::F7 => tilde(18),
        Key::F8 => tilde(19),
        Key::F9 => tilde(20),
        Key::F10 => tilde(21),
        Key::F11 => tilde(23),
        Key::F12 => tilde(24),
        _ if m.ctrl => {
            let byte = match key {
                Key::Space => 0,
                Key::OpenBracket => 0x1b,
                Key::Backslash => 0x1c,
                Key::CloseBracket => 0x1d,
                Key::Slash => 0x1f,
                _ => letter_key(key)? - b'a' + 1,
            };
            esc_if_alt(&[byte])
        }
        _ => return None,
    })
}

/// Eingefügten Text für das Terminal aufbereiten. Entfernt die Endmarke aus dem Text, damit
/// eingefügter Inhalt nicht aus dem „Bracketed Paste“-Modus ausbrechen und Befehle ausführen kann.
pub fn encode_paste(text: &str, mode: TermMode) -> Vec<u8> {
    let clean = text.replace("\r\n", "\r").replace('\n', "\r");
    if mode.contains(TermMode::BRACKETED_PASTE) {
        let clean = clean.replace('\x1b', "");
        format!("\x1b[200~{clean}\x1b[201~").into_bytes()
    } else {
        clean.into_bytes()
    }
}

// --- Maus --------------------------------------------------------------------------------

fn encode_mouse(button: u8, col: usize, row: usize, pressed: bool, m: Modifiers, mode: TermMode) -> Option<Vec<u8>> {
    let mut b = button;
    if m.shift { b += 4; }
    if m.alt { b += 8; }
    if m.ctrl { b += 16; }
    if mode.contains(TermMode::SGR_MOUSE) {
        let end = if pressed { 'M' } else { 'm' };
        return Some(format!("\x1b[<{b};{};{}{end}", col + 1, row + 1).into_bytes());
    }
    // Klassisches X10-Format kennt kein „welche Taste wurde losgelassen“.
    let code = if pressed { b } else { (b & !3) | 3 };
    if mode.contains(TermMode::UTF8_MOUSE) {
        let mut s = String::from("\x1b[M");
        s.push(char::from_u32(32 + code as u32)?);
        s.push(char::from_u32(33 + col as u32)?);
        s.push(char::from_u32(33 + row as u32)?);
        return Some(s.into_bytes());
    }
    if col > 222 || row > 222 {
        return None;
    }
    Some(vec![0x1b, b'[', b'M', 32 + code, 33 + col as u8, 33 + row as u8])
}

impl ViewState {
    fn request_paste(&mut self, ctx: &egui::Context) {
        self.paste_requested = Some(Instant::now());
        ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaste);
        // Der Inhalt kommt erst nach diesem Frame an; ohne neuen Frame bliebe er bis zur nächsten
        // Eingabe liegen.
        ctx.request_repaint();
    }

    fn take_paste_request(&mut self) -> bool {
        self.paste_requested.take().is_some_and(|t| t.elapsed() < Duration::from_secs(1))
    }
}

// --- Rahmen- und Blockzeichen -------------------------------------------------------------

/// Linienstärken der Rahmenzeichen U+2500..U+257F, je Zeichen vier Ziffern für links, rechts,
/// oben, unten (0 = keine, 1 = dünn, 2 = dick, 3 = doppelt). Selbst gezeichnet, damit die Linien
/// lückenlos über die Zellgrenzen laufen – bei Schriftzeichen entstehen dort Spalten.
const BOX_TABLE: &str = "\
1100 2200 0011 0022 1100 2200 0011 0022 1100 2200 0011 0022 0101 0201 0102 0202 \
1001 2001 1002 2002 0110 0210 0120 0220 1010 2010 1020 2020 0111 0211 0121 0112 \
0122 0221 0212 0222 1011 2011 1021 1012 1022 2021 2012 2022 1101 2101 1201 2201 \
1102 2102 1202 2202 1110 2110 1210 2210 1120 2120 1220 2220 1111 2111 1211 2211 \
1121 1112 1122 2121 1221 2112 1212 2221 2212 2122 1222 2222 1100 2200 0011 0022 \
3300 0033 0301 0103 0303 3001 1003 3003 0310 0130 0330 3010 1030 3030 0311 0133 \
0333 3011 1033 3033 3301 1103 3303 3310 1130 3330 3311 1133 3333 0101 1001 1010 \
0110 0000 0000 0000 1000 0010 0100 0001 2000 0020 0200 0002 1200 0012 2100 0021 ";

fn box_weights(c: char) -> Option<[u8; 4]> {
    let i = (c as u32).checked_sub(0x2500)? as usize;
    let code = BOX_TABLE.as_bytes().get(i * 5..i * 5 + 4)?;
    let w = [code[0] - b'0', code[1] - b'0', code[2] - b'0', code[3] - b'0'];
    (w != [0; 4]).then_some(w)
}

/// Ausgefüllte Anteile einer Zelle (x0, y0, x1, y1 von 0 bis 1) und Deckkraft für U+2580..U+259F.
fn block_rects(c: char) -> Option<(&'static [[f32; 4]], f32)> {
    const TL: [f32; 4] = [0.0, 0.0, 0.5, 0.5];
    const TR: [f32; 4] = [0.5, 0.0, 1.0, 0.5];
    const BL: [f32; 4] = [0.0, 0.5, 0.5, 1.0];
    const BR: [f32; 4] = [0.5, 0.5, 1.0, 1.0];
    const FULL: [f32; 4] = [0.0, 0.0, 1.0, 1.0];
    Some(match c {
        '▀' => (&[[0.0, 0.0, 1.0, 0.5]], 1.0),
        '▁' => (&[[0.0, 0.875, 1.0, 1.0]], 1.0),
        '▂' => (&[[0.0, 0.75, 1.0, 1.0]], 1.0),
        '▃' => (&[[0.0, 0.625, 1.0, 1.0]], 1.0),
        '▄' => (&[[0.0, 0.5, 1.0, 1.0]], 1.0),
        '▅' => (&[[0.0, 0.375, 1.0, 1.0]], 1.0),
        '▆' => (&[[0.0, 0.25, 1.0, 1.0]], 1.0),
        '▇' => (&[[0.0, 0.125, 1.0, 1.0]], 1.0),
        '█' => (&[FULL], 1.0),
        '▉' => (&[[0.0, 0.0, 0.875, 1.0]], 1.0),
        '▊' => (&[[0.0, 0.0, 0.75, 1.0]], 1.0),
        '▋' => (&[[0.0, 0.0, 0.625, 1.0]], 1.0),
        '▌' => (&[[0.0, 0.0, 0.5, 1.0]], 1.0),
        '▍' => (&[[0.0, 0.0, 0.375, 1.0]], 1.0),
        '▎' => (&[[0.0, 0.0, 0.25, 1.0]], 1.0),
        '▏' => (&[[0.0, 0.0, 0.125, 1.0]], 1.0),
        '▐' => (&[[0.5, 0.0, 1.0, 1.0]], 1.0),
        '░' => (&[FULL], 0.25),
        '▒' => (&[FULL], 0.5),
        '▓' => (&[FULL], 0.75),
        '▔' => (&[[0.0, 0.0, 1.0, 0.125]], 1.0),
        '▕' => (&[[0.875, 0.0, 1.0, 1.0]], 1.0),
        '▖' => (&[BL], 1.0),
        '▗' => (&[BR], 1.0),
        '▘' => (&[TL], 1.0),
        '▙' => (&[TL, BL, BR], 1.0),
        '▚' => (&[TL, BR], 1.0),
        '▛' => (&[TL, TR, BL], 1.0),
        '▜' => (&[TL, TR, BR], 1.0),
        '▝' => (&[TR], 1.0),
        '▞' => (&[TR, BL], 1.0),
        '▟' => (&[TR, BL, BR], 1.0),
        _ => return None,
    })
}

/// Punktmuster der Braille-Zeichen U+2800..U+28FF. Viele Programme nutzen sie für Spinner
/// (z. B. `docker compose pull`: ⠋⠙⠹⠸…) oder feine Grafiken (btop). Die eingebauten Schriften
/// haben sie nicht, darum werden sie selbst gezeichnet.
fn braille_dots(c: char) -> Option<u8> {
    let v = c as u32;
    (0x2800..=0x28ff).contains(&v).then(|| (v - 0x2800) as u8)
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mark {
    Check,
    HeavyCheck,
    Cross,
    HeavyCross,
}

/// Haken und Kreuze, mit denen Werkzeuge Erfolg und Fehler melden (✔ / ✘ bei docker compose).
fn mark(c: char) -> Option<Mark> {
    Some(match c {
        '✓' => Mark::Check,
        '✔' => Mark::HeavyCheck,
        '✗' => Mark::Cross,
        '✘' => Mark::HeavyCross,
        _ => return None,
    })
}

fn is_cell_graphic(c: char) -> bool {
    box_weights(c).is_some() || block_rects(c).is_some() || braille_dots(c).is_some() || mark(c).is_some()
}

/// Zeichnet ein Rahmen- oder Blockzeichen exakt in seine Zelle.
fn paint_cell_graphic(painter: &egui::Painter, cell: Rect, c: char, color: Color32) {
    if let Some(bits) = braille_dots(c) {
        // Bit 0..2 und 6: linke Spalte von oben, Bit 3..5 und 7: rechte Spalte.
        const DOTS: [(f32, f32); 8] = [
            (0.0, 0.0), (0.0, 1.0), (0.0, 2.0), (1.0, 0.0),
            (1.0, 1.0), (1.0, 2.0), (0.0, 3.0), (1.0, 3.0),
        ];
        let step_x = cell.width() / 2.0;
        let step_y = cell.height() / 4.0;
        let radius = (step_x.min(step_y) * 0.36).max(0.8);
        for (i, (col, row)) in DOTS.iter().enumerate() {
            if bits & (1 << i) != 0 {
                let center = Pos2::new(cell.left() + step_x * (col + 0.5), cell.top() + step_y * (row + 0.5));
                painter.circle_filled(center, radius, color);
            }
        }
        return;
    }
    if let Some(m) = mark(c) {
        let heavy = matches!(m, Mark::HeavyCheck | Mark::HeavyCross);
        let w = cell.width().min(cell.height());
        let stroke = Stroke::new(if heavy { (w * 0.2).max(1.6) } else { (w * 0.12).max(1.0) }, color);
        let at = |x: f32, y: f32| Pos2::new(cell.center().x + (x - 0.5) * w, cell.center().y + (y - 0.5) * w);
        match m {
            Mark::Check | Mark::HeavyCheck => {
                painter.line_segment([at(0.14, 0.52), at(0.4, 0.78)], stroke);
                painter.line_segment([at(0.4, 0.78), at(0.88, 0.2)], stroke);
            }
            Mark::Cross | Mark::HeavyCross => {
                painter.line_segment([at(0.2, 0.2), at(0.8, 0.8)], stroke);
                painter.line_segment([at(0.8, 0.2), at(0.2, 0.8)], stroke);
            }
        }
        return;
    }
    if let Some((rects, alpha)) = block_rects(c) {
        let color = color.gamma_multiply(alpha);
        for [x0, y0, x1, y1] in rects {
            let r = Rect::from_min_max(
                Pos2::new(cell.left() + x0 * cell.width(), cell.top() + y0 * cell.height()).round(),
                Pos2::new(cell.left() + x1 * cell.width(), cell.top() + y1 * cell.height()).round(),
            );
            painter.rect_filled(r, 0.0, color);
        }
        return;
    }
    let Some([left, right, up, down]) = box_weights(c) else { return };
    let thin = (cell.height() / 16.0).round().max(1.0);
    let cx = (cell.center().x - thin / 2.0).round() + thin / 2.0;
    let cy = (cell.center().y - thin / 2.0).round() + thin / 2.0;
    let horizontal = |x0: f32, x1: f32, w: u8| {
        let t = if w == 2 { thin * 2.0 } else { thin };
        let offsets: &[f32] = if w == 3 { &[-thin, thin] } else { &[0.0] };
        for o in offsets {
            let r = Rect::from_min_max(Pos2::new(x0, cy + o - t / 2.0), Pos2::new(x1, cy + o + t / 2.0));
            painter.rect_filled(r, 0.0, color);
        }
    };
    let vertical = |y0: f32, y1: f32, w: u8| {
        let t = if w == 2 { thin * 2.0 } else { thin };
        let offsets: &[f32] = if w == 3 { &[-thin, thin] } else { &[0.0] };
        for o in offsets {
            let r = Rect::from_min_max(Pos2::new(cx + o - t / 2.0, y0), Pos2::new(cx + o + t / 2.0, y1));
            painter.rect_filled(r, 0.0, color);
        }
    };
    // Arme laufen bis über die Mitte, damit Ecken und Kreuzungen geschlossen sind.
    let over = |other: u8| match other {
        0 => thin / 2.0,
        2 => thin,
        _ => thin * 1.5,
    };
    let v = up.max(down);
    let h = left.max(right);
    if left > 0 {
        horizontal(cell.left(), cx + over(v), left);
    }
    if right > 0 {
        horizontal(cx - over(v), cell.right(), right);
    }
    if up > 0 {
        vertical(cell.top(), cy + over(h), up);
    }
    if down > 0 {
        vertical(cy - over(h), cell.bottom(), down);
    }
}

// --- Widget ------------------------------------------------------------------------------

/// Pro Sitzung gemerkter Zustand der Darstellung.
#[derive(Default)]
pub struct ViewState {
    scroll_rest: f32,
    selecting: bool,
    pressed_button: Option<u8>,
    last_mouse_cell: Option<(usize, usize)>,
    /// Wann zuletzt Einfügen angefordert wurde. Die Antwort kommt erst in einem späteren Frame;
    /// bei leerer Zwischenablage kommt keine, darum verfällt die Anforderung.
    paste_requested: Option<Instant>,
}

fn rgb(c: Rgb) -> Color32 {
    Color32::from_rgb(c.r, c.g, c.b)
}

fn blend(a: Color32, b: Color32, t: f32) -> Color32 {
    let m = |x: u8, y: u8| (x as f32 * (1.0 - t) + y as f32 * t) as u8;
    Color32::from_rgb(m(a.r(), b.r()), m(a.g(), b.g()), m(a.b(), b.b()))
}

fn resolve(
    color: Color,
    flags: Flags,
    colors: &alacritty_terminal::term::color::Colors,
    p: &TermPalette,
    is_fg: bool,
) -> Color32 {
    match color {
        Color::Spec(c) => rgb(c),
        Color::Indexed(mut i) => {
            // Fett + Grundfarbe wird wie in den meisten Terminals zur hellen Variante.
            if is_fg && i < 8 && flags.contains(Flags::BOLD) {
                i += 8;
            }
            colors[i as usize].map(rgb).unwrap_or_else(|| p.indexed(i))
        }
        Color::Named(mut n) => {
            if is_fg && flags.contains(Flags::BOLD) {
                n = n.to_bright();
            }
            colors[n].map(rgb).unwrap_or_else(|| p.named(n))
        }
    }
}

/// Textstück einer Zeile, das in einem Rutsch gezeichnet wird.
struct Run {
    col: usize,
    text: String,
    fg: Color32,
    bold: bool,
    italic: bool,
}

/// Zeichnet das Terminal und verarbeitet die Eingaben. Gibt `true` zurück, wenn es den Fokus hat.
pub fn show(
    ui: &mut egui::Ui,
    shared: &Shared,
    cmds: &mpsc::UnboundedSender<Cmd>,
    view: &mut ViewState,
    palette: &TermPalette,
    font_size: f32,
    take_focus: bool,
) {
    let font = FontId::monospace(font_size);
    let (cell_w, cell_h) = ui.fonts_mut(|f| (f.glyph_width(&font, 'M'), f.row_height(&font)));
    let (cell_w, cell_h) = (cell_w.max(1.0), cell_h.ceil().max(1.0));

    let full = ui.available_rect_before_wrap();
    let response = ui.allocate_rect(full, Sense::click_and_drag());
    let painter = ui.painter_at(full);
    painter.rect_filled(full, 0.0, palette.bg);

    let rect = full.shrink(6.0);
    let cols = ((rect.width() / cell_w).floor() as usize).clamp(2, 1000);
    let rows = ((rect.height() / cell_h).floor() as usize).clamp(1, 1000);

    if take_focus {
        response.request_focus();
    }
    let focused = response.has_focus();
    if focused {
        ui.memory_mut(|mem| {
            mem.set_focus_lock_filter(
                response.id,
                egui::EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true },
            );
        });
    }
    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::Text);
    }

    let mut term = shared.term.lock();

    // Fenstergröße nachführen.
    let px = (rect.width() as u16, rect.height() as u16);
    if term.columns() != cols || term.screen_lines() != rows {
        term.resize(TermSize { cols, rows });
        *shared.size.lock() = (cols as u16, rows as u16, px.0, px.1);
        let _ = cmds.send(Cmd::Resize { cols: cols as u16, rows: rows as u16, px_w: px.0, px_h: px.1 });
    }

    let mode = *term.mode();
    let send = |b: Vec<u8>| {
        let _ = cmds.send(Cmd::Input(b));
    };

    // --- Eingaben ---
    if focused {
        // egui-winit meldet Strg+C/X/V als Copy/Cut/Paste. Im Terminal sind das Steuerzeichen;
        // Kopieren und Einfügen liegen wie üblich auf Strg+Umschalt+C/V.
        let events = ui.input(|i| i.events.clone());
        let alt = ui.input(|i| i.modifiers.alt);
        let mut typed = false;
        for ev in events {
            match ev {
                egui::Event::Text(t) => {
                    let mut bytes = Vec::with_capacity(t.len() + 1);
                    if alt {
                        bytes.push(0x1b);
                    }
                    bytes.extend_from_slice(t.as_bytes());
                    send(bytes);
                    typed = true;
                }
                egui::Event::Ime(egui::ImeEvent::Commit(t)) => {
                    send(t.into_bytes());
                    typed = true;
                }
                egui::Event::Copy => {
                    send(vec![0x03]);
                    typed = true;
                }
                egui::Event::Cut => {
                    send(vec![0x18]);
                    typed = true;
                }
                egui::Event::Paste(t) => {
                    if view.take_paste_request() {
                        send(encode_paste(&t, mode));
                    } else {
                        send(vec![0x16]);
                    }
                    typed = true;
                }
                egui::Event::Key { key, pressed: true, modifiers, .. } => {
                    if modifiers.ctrl && modifiers.shift {
                        match key {
                            Key::C => {
                                if let Some(s) = term.selection_to_string() {
                                    ui.ctx().copy_text(s);
                                }
                                continue;
                            }
                            Key::V => {
                                view.request_paste(ui.ctx());
                                continue;
                            }
                            _ => {}
                        }
                    }
                    if modifiers.shift && !modifiers.ctrl && !modifiers.alt {
                        match key {
                            Key::PageUp => {
                                term.scroll_display(Scroll::PageUp);
                                continue;
                            }
                            Key::PageDown => {
                                term.scroll_display(Scroll::PageDown);
                                continue;
                            }
                            Key::Insert => {
                                view.request_paste(ui.ctx());
                                continue;
                            }
                            _ => {}
                        }
                    }
                    if let Some(bytes) = encode_key(key, modifiers, mode) {
                        send(bytes);
                        typed = true;
                    }
                }
                _ => {}
            }
        }
        if typed {
            term.selection = None;
            term.scroll_display(Scroll::Bottom);
        }
    }

    // Während das Kontextmenü schließt, hat das Terminal evtl. gerade keinen Fokus.
    if !focused && view.paste_requested.is_some() {
        let pasted = ui.input(|i| {
            i.events.iter().find_map(|e| match e {
                egui::Event::Paste(t) => Some(t.clone()),
                _ => None,
            })
        });
        if let Some(t) = pasted
            && view.take_paste_request()
        {
            send(encode_paste(&t, mode));
            term.selection = None;
            term.scroll_display(Scroll::Bottom);
        }
    }

    // --- Maus ---
    let display_offset = term.grid().display_offset();
    let to_cell = |pos: Pos2| -> (usize, usize, Side) {
        let x = ((pos.x - rect.left()) / cell_w).max(0.0);
        let y = ((pos.y - rect.top()) / cell_h).max(0.0);
        let col = (x as usize).min(cols - 1);
        let row = (y as usize).min(rows - 1);
        let side = if x.fract() < 0.5 { Side::Left } else { Side::Right };
        (col, row, side)
    };
    let to_point = |col: usize, row: usize| Point::new(Line(row as i32 - display_offset as i32), Column(col));
    let modifiers = ui.input(|i| i.modifiers);
    // Umschalt erzwingt wie bei xterm die normale Textauswahl.
    let report_mouse = mode.intersects(TermMode::MOUSE_MODE) && !modifiers.shift;

    if response.hovered() {
        let scroll = ui.input(|i| i.smooth_scroll_delta.y);
        if scroll != 0.0 {
            view.scroll_rest += scroll / cell_h;
            let lines = view.scroll_rest.trunc() as i32;
            view.scroll_rest -= lines as f32;
            if lines != 0 {
                let hover = ui.input(|i| i.pointer.hover_pos());
                if report_mouse {
                    if let Some(p) = hover {
                        let (col, row, _) = to_cell(p);
                        let button = if lines > 0 { 64 } else { 65 };
                        for _ in 0..lines.abs() {
                            if let Some(b) = encode_mouse(button, col, row, true, modifiers, mode) {
                                send(b);
                            }
                        }
                    }
                } else if mode.contains(TermMode::ALT_SCREEN) && mode.contains(TermMode::ALTERNATE_SCROLL) {
                    let arrow = match (lines > 0, mode.contains(TermMode::APP_CURSOR)) {
                        (true, true) => "\x1bOA",
                        (true, false) => "\x1b[A",
                        (false, true) => "\x1bOB",
                        (false, false) => "\x1b[B",
                    };
                    send(arrow.repeat(lines.unsigned_abs() as usize).into_bytes());
                } else {
                    term.scroll_display(Scroll::Delta(lines));
                }
            }
        }
    }

    // Mittlere Maustaste fügt wie unter Linux üblich die Primary-Selection ein. Wertet das Programm
    // im Terminal die Maus selbst aus, bekommt es den Klick (Umschalt erzwingt das Einfügen).
    if !report_mouse {
        let primary = ui.input(|i| {
            i.events.iter().find_map(|e| match e {
                egui::Event::MiddleClickPaste { pos, text } if full.contains(*pos) => Some(text.clone()),
                _ => None,
            })
        });
        if let Some(text) = primary {
            response.request_focus();
            send(encode_paste(&text, mode));
            term.selection = None;
            term.scroll_display(Scroll::Bottom);
        }
    }

    if let Some(pos) = ui.input(|i| i.pointer.interact_pos()) {
        let (col, row, side) = to_cell(pos);
        if report_mouse {
            let buttons = [
                (egui::PointerButton::Primary, 0u8),
                (egui::PointerButton::Middle, 1),
                (egui::PointerButton::Secondary, 2),
            ];
            for (pb, code) in buttons {
                if response.contains_pointer() && ui.input(|i| i.pointer.button_pressed(pb)) {
                    response.request_focus();
                    view.pressed_button = Some(code);
                    if let Some(b) = encode_mouse(code, col, row, true, modifiers, mode) {
                        send(b);
                    }
                }
                if view.pressed_button == Some(code) && ui.input(|i| i.pointer.button_released(pb)) {
                    view.pressed_button = None;
                    if let Some(b) = encode_mouse(code, col, row, false, modifiers, mode) {
                        send(b);
                    }
                }
            }
            let moved = view.last_mouse_cell != Some((col, row));
            view.last_mouse_cell = Some((col, row));
            if moved {
                let report = match view.pressed_button {
                    Some(_) => mode.intersects(TermMode::MOUSE_DRAG | TermMode::MOUSE_MOTION),
                    None => mode.contains(TermMode::MOUSE_MOTION) && response.hovered(),
                };
                if report {
                    let code = view.pressed_button.unwrap_or(3) + 32;
                    if let Some(b) = encode_mouse(code, col, row, true, modifiers, mode) {
                        send(b);
                    }
                }
            }
        } else {
            let primary_pressed = ui.input(|i| i.pointer.primary_pressed());
            if response.contains_pointer() && primary_pressed {
                response.request_focus();
                let clicks = ui.input(|i| {
                    if i.pointer.button_triple_clicked(egui::PointerButton::Primary) {
                        3
                    } else if i.pointer.button_double_clicked(egui::PointerButton::Primary) {
                        2
                    } else {
                        1
                    }
                });
                let ty = match clicks {
                    3 => SelectionType::Lines,
                    2 => SelectionType::Semantic,
                    _ => SelectionType::Simple,
                };
                term.selection = Some(Selection::new(ty, to_point(col, row), side));
                view.selecting = true;
            } else if view.selecting
                && ui.input(|i| i.pointer.primary_down())
                && let Some(sel) = term.selection.as_mut()
            {
                sel.update(to_point(col, row), side);
            }
            if view.selecting && ui.input(|i| i.pointer.primary_released()) {
                view.selecting = false;
                // Markierter Text landet in der Primary-Selection (Einfügen mit mittlerer Taste).
                if let Some(text) = term.selection_to_string().filter(|t| !t.is_empty()) {
                    ui.ctx().output_mut(|o| o.commands.push(egui::OutputCommand::TextSelectionSettled(text)));
                }
            }
        }
    }

    // --- Zeichnen ---
    let content = term.renderable_content();
    let offset = content.display_offset as i32;
    let selection = content.selection;
    let cursor = content.cursor;
    let cursor_row = cursor.point.line.0 + offset;
    let colors = content.colors;

    let origin = rect.min.round();
    let cell_x = |col: usize| (origin.x + col as f32 * cell_w).round();
    let cell_y = |row: i32| origin.y + row as f32 * cell_h;

    let mut text_shapes: Vec<(usize, i32, Run)> = Vec::new();
    let mut lines: Vec<(egui::Pos2, egui::Pos2, Color32)> = Vec::new();
    let mut graphics: Vec<(usize, i32, char, Color32)> = Vec::new();
    let mut wants_cjk = false;
    let mut bg_run: Option<(i32, usize, usize, Color32)> = None;
    let mut current: Option<(i32, Run)> = None;

    let flush_bg = |run: &mut Option<(i32, usize, usize, Color32)>| {
        if let Some((row, a, b, color)) = run.take() {
            let r = Rect::from_min_max(Pos2::new(cell_x(a), cell_y(row)), Pos2::new(cell_x(b), cell_y(row + 1)));
            painter.rect_filled(r, 0.0, color);
        }
    };

    for indexed in content.display_iter {
        let row = indexed.point.line.0 + offset;
        let col = indexed.point.column.0;
        let cell = indexed.cell;
        if cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
            continue;
        }
        let mut fg = resolve(cell.fg, cell.flags, colors, palette, true);
        let mut bg = resolve(cell.bg, cell.flags, colors, palette, false);
        if cell.flags.contains(Flags::DIM) {
            fg = blend(fg, bg, 0.4);
        }
        if cell.flags.contains(Flags::INVERSE) {
            std::mem::swap(&mut fg, &mut bg);
        }
        let selected = selection.is_some_and(|s| s.contains_cell(&indexed, cursor.point, cursor.shape));
        if selected {
            bg = palette.selection;
        }
        let width = if cell.flags.contains(Flags::WIDE_CHAR) { 2 } else { 1 };

        // Hintergründe zu Streifen zusammenfassen.
        let same_bg = matches!(bg_run, Some((r, _, end, c)) if r == row && end == col && c == bg);
        if same_bg {
            if let Some(run) = bg_run.as_mut() {
                run.2 = col + width;
            }
        } else {
            flush_bg(&mut bg_run);
            if bg != palette.bg {
                bg_run = Some((row, col, col + width, bg));
            }
        }

        let c = cell.c;
        let hidden = cell.flags.contains(Flags::HIDDEN);
        let bold = cell.flags.contains(Flags::BOLD);
        let italic = cell.flags.contains(Flags::ITALIC);
        let graphic = is_cell_graphic(c);
        if graphic && !hidden {
            graphics.push((col, row, c, fg));
        }
        wants_cjk |= width == 2 && !hidden;
        let drawable = c != ' ' && c != '\0' && c != '\t' && !hidden && !graphic;

        // Nur druckbares ASCII in einem Rutsch zeichnen, alles andere exakt pro Zelle.
        // So verschieben Ersatzschriften (z. B. für CJK) die Spalten nicht.
        let joinable = drawable
            && c.is_ascii_graphic()
            && matches!(&current, Some((r, run)) if *r == row && run.fg == fg && run.bold == bold
                && run.italic == italic && run.col + run.text.len() == col && run.text.is_ascii());
        if joinable {
            if let Some((_, run)) = current.as_mut() {
                run.text.push(c);
            }
        } else {
            if let Some((r, run)) = current.take() {
                text_shapes.push((run.col, r, run));
            }
            if drawable {
                let mut text = String::new();
                text.push(c);
                if let Some(zw) = cell.zerowidth() {
                    text.extend(zw.iter());
                }
                current = Some((row, Run { col, text, fg, bold, italic }));
            }
        }

        let underline = cell.flags.intersects(Flags::ALL_UNDERLINES);
        let strike = cell.flags.contains(Flags::STRIKEOUT);
        if underline || strike {
            let x0 = cell_x(col);
            let x1 = cell_x(col + width);
            if underline {
                let y = cell_y(row) + cell_h - 1.5;
                lines.push((Pos2::new(x0, y), Pos2::new(x1, y), fg));
            }
            if strike {
                let y = cell_y(row) + cell_h * 0.5;
                lines.push((Pos2::new(x0, y), Pos2::new(x1, y), fg));
            }
        }
    }
    flush_bg(&mut bg_run);
    if let Some((r, run)) = current.take() {
        text_shapes.push((run.col, r, run));
    }

    for (col, row, c, color) in graphics {
        let cell = Rect::from_min_max(Pos2::new(cell_x(col), cell_y(row)), Pos2::new(cell_x(col + 1), cell_y(row + 1)));
        paint_cell_graphic(&painter, cell, c, color);
    }
    if wants_cjk {
        crate::theme::load_cjk_font(ui.ctx());
    }

    // Cursor unter dem Text zeichnen, das Zeichen darunter wird danach invertiert ausgegeben.
    let mut cursor_cell: Option<(usize, i32)> = None;
    if cursor.shape != CursorShape::Hidden && cursor_row >= 0 && (cursor_row as usize) < rows {
        let col = cursor.point.column.0;
        let x = cell_x(col);
        let y = cell_y(cursor_row);
        let r = Rect::from_min_size(Pos2::new(x, y), Vec2::new(cell_w.ceil(), cell_h));
        match (focused, cursor.shape) {
            (true, CursorShape::Beam) => {
                painter.rect_filled(Rect::from_min_size(r.min, Vec2::new(2.0, cell_h)), 0.0, palette.cursor);
            }
            (true, CursorShape::Underline) => {
                painter.rect_filled(
                    Rect::from_min_size(Pos2::new(x, y + cell_h - 2.0), Vec2::new(cell_w, 2.0)),
                    0.0,
                    palette.cursor,
                );
            }
            (true, _) => {
                painter.rect_filled(r, 0.0, palette.cursor);
                cursor_cell = Some((col, cursor_row));
            }
            (false, _) => {
                painter.rect_stroke(
                    r.shrink(0.5),
                    0.0,
                    Stroke::new(1.0, palette.cursor),
                    egui::StrokeKind::Inside,
                );
            }
        }
    }

    let paint_text = |x: f32, y: f32, run_text: &str, color: Color32, bold: bool, italic: bool| {
        let galley = if italic {
            let mut job = egui::text::LayoutJob::default();
            job.append(
                run_text,
                0.0,
                egui::TextFormat { font_id: font.clone(), color, italics: true, ..Default::default() },
            );
            ui.fonts_mut(|f| f.layout_job(job))
        } else {
            ui.fonts_mut(|f| f.layout_no_wrap(run_text.to_owned(), font.clone(), color))
        };
        painter.galley(Pos2::new(x, y), galley.clone(), color);
        if bold {
            // Die eingebaute Schrift hat keinen Fettschnitt, also leicht versetzt doppelt zeichnen.
            painter.galley(Pos2::new(x + 0.6, y), galley, color);
        }
    };

    for (col, row, run) in &text_shapes {
        let y = cell_y(*row);
        // Das Zeichen unter dem Block-Cursor bekommt die Hintergrundfarbe als Textfarbe.
        if let Some((cc, cr)) = cursor_cell
            && cr == *row
            && cc >= *col
            && cc < *col + run.text.chars().count()
            && run.text.is_ascii()
        {
            let i = cc - *col;
            let (a, rest) = run.text.split_at(i);
            let (m, b) = rest.split_at(1);
            if !a.is_empty() {
                paint_text(cell_x(*col), y, a, run.fg, run.bold, run.italic);
            }
            paint_text(cell_x(cc), y, m, palette.bg, run.bold, run.italic);
            if !b.is_empty() {
                paint_text(cell_x(cc + 1), y, b, run.fg, run.bold, run.italic);
            }
            continue;
        }
        if let Some((cc, cr)) = cursor_cell
            && cr == *row
            && cc == *col
        {
            paint_text(cell_x(*col), y, &run.text, palette.bg, run.bold, run.italic);
            continue;
        }
        paint_text(cell_x(*col), y, &run.text, run.fg, run.bold, run.italic);
    }
    for (a, b, c) in lines {
        painter.line_segment([a, b], Stroke::new(1.0, c));
    }

    // Position in der Historie anzeigen, sobald zurückgescrollt wurde.
    let history = term.history_size();
    if offset > 0 && history > 0 {
        let total = (history + rows) as f32;
        let h = (rows as f32 / total * full.height()).max(24.0);
        let top = (history as f32 - offset as f32) / total * full.height();
        let bar = Rect::from_min_size(
            Pos2::new(full.right() - 5.0, full.top() + top),
            Vec2::new(3.0, h),
        );
        painter.rect_filled(bar, 2.0, palette.fg.gamma_multiply(0.45));
    }

    // Kontextmenü (nicht, wenn die Anwendung im Terminal die Maus selbst auswertet).
    let selection_text = term.selection_to_string();
    let any_mouse_mode = report_mouse;
    drop(term);
    if !any_mouse_mode {
        response.context_menu(|ui| {
            if ui.add_enabled(selection_text.is_some(), egui::Button::new("Kopieren")).clicked() {
                if let Some(s) = selection_text.clone() {
                    ui.ctx().copy_text(s);
                }
                ui.close();
            }
            if ui.button("Einfügen").clicked() {
                view.request_paste(ui.ctx());
                ui.close();
            }
        });
    }
}

// Ordnet das Terminal-Farbschema den benannten Farben zu. Liegt hier, weil es die vte-Typen braucht.
impl TermPalette {
    pub fn named(&self, n: NamedColor) -> Color32 {
        use NamedColor::*;
        match n {
            Foreground | BrightForeground => self.fg,
            Background => self.bg,
            Cursor => self.cursor,
            DimForeground => blend(self.fg, self.bg, 0.35),
            Black => self.ansi[0],
            Red => self.ansi[1],
            Green => self.ansi[2],
            Yellow => self.ansi[3],
            Blue => self.ansi[4],
            Magenta => self.ansi[5],
            Cyan => self.ansi[6],
            White => self.ansi[7],
            BrightBlack => self.ansi[8],
            BrightRed => self.ansi[9],
            BrightGreen => self.ansi[10],
            BrightYellow => self.ansi[11],
            BrightBlue => self.ansi[12],
            BrightMagenta => self.ansi[13],
            BrightCyan => self.ansi[14],
            BrightWhite => self.ansi[15],
            DimBlack => blend(self.ansi[0], self.bg, 0.35),
            DimRed => blend(self.ansi[1], self.bg, 0.35),
            DimGreen => blend(self.ansi[2], self.bg, 0.35),
            DimYellow => blend(self.ansi[3], self.bg, 0.35),
            DimBlue => blend(self.ansi[4], self.bg, 0.35),
            DimMagenta => blend(self.ansi[5], self.bg, 0.35),
            DimCyan => blend(self.ansi[6], self.bg, 0.35),
            DimWhite => blend(self.ansi[7], self.bg, 0.35),
        }
    }

    pub fn indexed(&self, i: u8) -> Color32 {
        match i {
            0..=15 => self.ansi[i as usize],
            16..=231 => {
                let i = i - 16;
                let level = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
                Color32::from_rgb(level(i / 36), level((i / 6) % 6), level(i % 6))
            }
            _ => {
                let v = 8 + (i - 232) * 10;
                Color32::from_rgb(v, v, v)
            }
        }
    }

    /// Antwort auf OSC-10/11-Abfragen (Programme wie vim erkennen so den Hintergrund).
    pub fn request_color(&self, index: usize) -> Rgb {
        let c = if index < 256 {
            self.indexed(index as u8)
        } else if index == NamedColor::Background as usize {
            self.bg
        } else if index == NamedColor::Cursor as usize {
            self.cursor
        } else {
            self.fg
        };
        Rgb { r: c.r(), g: c.g(), b: c.b() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: Modifiers = Modifiers::NONE;

    fn key(k: Key, m: Modifiers, mode: TermMode) -> Vec<u8> {
        encode_key(k, m, mode).unwrap()
    }

    #[test]
    fn control_and_special_keys() {
        let n = TermMode::NONE;
        assert_eq!(key(Key::Enter, NONE, n), b"\r");
        assert_eq!(key(Key::Backspace, NONE, n), b"\x7f");
        assert_eq!(key(Key::D, Modifiers::CTRL, n), [4]);
        assert_eq!(key(Key::L, Modifiers::CTRL, n), [12]);
        assert_eq!(key(Key::Delete, NONE, n), b"\x1b[3~");
        assert_eq!(key(Key::F5, NONE, n), b"\x1b[15~");
        assert_eq!(key(Key::F1, NONE, n), b"\x1bOP");
        assert_eq!(key(Key::Tab, Modifiers::SHIFT, n), b"\x1b[Z");
        assert!(encode_key(Key::A, NONE, n).is_none(), "Normale Zeichen kommen als Text");
    }

    #[test]
    fn arrow_keys_follow_cursor_mode_and_modifiers() {
        assert_eq!(key(Key::ArrowUp, NONE, TermMode::NONE), b"\x1b[A");
        assert_eq!(key(Key::ArrowUp, NONE, TermMode::APP_CURSOR), b"\x1bOA");
        assert_eq!(key(Key::ArrowRight, Modifiers::CTRL, TermMode::NONE), b"\x1b[1;5C");
        assert_eq!(key(Key::ArrowLeft, Modifiers::SHIFT, TermMode::APP_CURSOR), b"\x1b[1;2D");
    }

    #[test]
    fn paste_cannot_break_out_of_bracketed_mode() {
        let out = encode_paste("a\n\x1b[201~rm -rf /\n", TermMode::BRACKETED_PASTE);
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("\x1b[200~"));
        assert!(s.ends_with("\x1b[201~"));
        assert_eq!(s.matches("\x1b[201~").count(), 1);
        assert_eq!(encode_paste("a\nb", TermMode::NONE), b"a\rb");
    }

    #[test]
    fn mouse_encoding() {
        let sgr = TermMode::SGR_MOUSE;
        assert_eq!(encode_mouse(0, 4, 9, true, NONE, sgr).unwrap(), b"\x1b[<0;5;10M");
        assert_eq!(encode_mouse(0, 4, 9, false, NONE, sgr).unwrap(), b"\x1b[<0;5;10m");
        assert_eq!(encode_mouse(0, 0, 0, true, NONE, TermMode::NONE).unwrap(), [0x1b, b'[', b'M', 32, 33, 33]);
        assert!(encode_mouse(0, 300, 0, true, NONE, TermMode::NONE).is_none());
    }

    #[test]
    fn box_table_matches_the_characters() {
        assert_eq!(BOX_TABLE.len(), 128 * 5);
        for (c, w) in [
            ('─', [1, 1, 0, 0]),
            ('│', [0, 0, 1, 1]),
            ('┌', [0, 1, 0, 1]),
            ('┐', [1, 0, 0, 1]),
            ('└', [0, 1, 1, 0]),
            ('┘', [1, 0, 1, 0]),
            ('├', [0, 1, 1, 1]),
            ('┤', [1, 0, 1, 1]),
            ('┬', [1, 1, 0, 1]),
            ('┴', [1, 1, 1, 0]),
            ('┼', [1, 1, 1, 1]),
            ('━', [2, 2, 0, 0]),
            ('┏', [0, 2, 0, 2]),
            ('╋', [2, 2, 2, 2]),
            ('═', [3, 3, 0, 0]),
            ('║', [0, 0, 3, 3]),
            ('╔', [0, 3, 0, 3]),
            ('╝', [3, 0, 3, 0]),
            ('╠', [0, 3, 3, 3]),
            ('╬', [3, 3, 3, 3]),
            ('╭', [0, 1, 0, 1]),
            ('╯', [1, 0, 1, 0]),
            ('╰', [0, 1, 1, 0]),
            ('╴', [1, 0, 0, 0]),
            ('╻', [0, 0, 0, 2]),
            ('╿', [0, 0, 2, 1]),
        ] {
            assert_eq!(box_weights(c), Some(w), "{c}");
        }
        assert_eq!(box_weights('a'), None);
        assert_eq!(box_weights('\u{2571}'), None, "Diagonalen zeichnet die Schrift");
    }

    #[test]
    fn braille_and_marks_are_drawn_natively() {
        // Die Spinner von docker compose, dazu Erfolg und Fehler.
        for c in "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏⠿✔✘✓✗".chars() {
            assert!(is_cell_graphic(c), "{c}");
        }
        assert_eq!(braille_dots('⠋'), Some(0b0000_1011));
        assert_eq!(braille_dots('⣿'), Some(0xff));
        assert_eq!(braille_dots('a'), None);
        assert_eq!(mark('✘'), Some(Mark::HeavyCross));
    }

    #[test]
    fn indexed_colors_cover_cube_and_grayscale() {
        let p = TermPalette::for_mode(true);
        assert_eq!(p.indexed(16), Color32::from_rgb(0, 0, 0));
        assert_eq!(p.indexed(231), Color32::from_rgb(255, 255, 255));
        assert_eq!(p.indexed(232), Color32::from_rgb(8, 8, 8));
    }
}
