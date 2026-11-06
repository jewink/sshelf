//! Terminalzeichen mit FreeType rastern, wie Konsole und andere Terminals.
//!
//! Der eingebaute Rasterizer von egui erzeugt bei kleinen Schriftgrößen sichtbar weichere Glyphen.
//! FreeType wird zur Laufzeit geladen (`libfreetype.so.6`, auf jedem Linux-Desktop vorhanden);
//! fehlt es, zeichnet das Terminal wie bisher mit egui. Die Glyphen landen in einer eigenen
//! Textur und werden pixelgenau auf das Zellenraster gesetzt.
//!
//! FreeType hat eine C-Schnittstelle; die benötigten Strukturen sind unten nachgebildet
//! (stabile ABI seit FreeType 2, LP64).

use eframe::egui::{self, Color32, ColorImage, Pos2, Rect, TextureHandle, TextureOptions, Vec2};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::ffi::{c_int, c_long, c_uint, c_ulong, c_void};
use std::sync::Arc;

// --- FreeType-ABI ----------------------------------------------------------------------------

#[repr(C)]
struct Generic {
    data: *mut c_void,
    finalizer: *mut c_void,
}

#[repr(C)]
struct BBox {
    x_min: c_long,
    y_min: c_long,
    x_max: c_long,
    y_max: c_long,
}

#[repr(C)]
struct FaceRec {
    num_faces: c_long,
    face_index: c_long,
    face_flags: c_long,
    style_flags: c_long,
    num_glyphs: c_long,
    family_name: *mut c_void,
    style_name: *mut c_void,
    num_fixed_sizes: c_int,
    available_sizes: *mut c_void,
    num_charmaps: c_int,
    charmaps: *mut c_void,
    generic: Generic,
    bbox: BBox,
    units_per_em: u16,
    ascender: i16,
    descender: i16,
    height: i16,
    max_advance_width: i16,
    max_advance_height: i16,
    underline_position: i16,
    underline_thickness: i16,
    glyph: *mut GlyphSlotRec,
    size: *mut SizeRec,
    // Weitere Felder werden nicht gelesen.
}

#[repr(C)]
struct SizeMetrics {
    x_ppem: u16,
    y_ppem: u16,
    x_scale: c_long,
    y_scale: c_long,
    ascender: c_long,
    descender: c_long,
    height: c_long,
    max_advance: c_long,
}

#[repr(C)]
struct SizeRec {
    face: *mut c_void,
    generic: Generic,
    metrics: SizeMetrics,
}

#[repr(C)]
struct GlyphMetrics {
    width: c_long,
    height: c_long,
    hori_bearing_x: c_long,
    hori_bearing_y: c_long,
    hori_advance: c_long,
    vert_bearing_x: c_long,
    vert_bearing_y: c_long,
    vert_advance: c_long,
}

#[repr(C)]
struct Bitmap {
    rows: c_uint,
    width: c_uint,
    pitch: c_int,
    buffer: *mut u8,
    num_grays: u16,
    pixel_mode: u8,
    palette_mode: u8,
    palette: *mut c_void,
}

#[repr(C)]
struct GlyphSlotRec {
    library: *mut c_void,
    face: *mut c_void,
    next: *mut c_void,
    glyph_index: c_uint,
    generic: Generic,
    metrics: GlyphMetrics,
    linear_hori_advance: c_long,
    linear_vert_advance: c_long,
    advance: [c_long; 2],
    format: c_uint,
    bitmap: Bitmap,
    bitmap_left: c_int,
    bitmap_top: c_int,
    // Weitere Felder werden nicht gelesen.
}

/// Leichtes Hinting wie bei KDE („Leicht“) und den meisten Desktops.
const LOAD_TARGET_LIGHT: i32 = 1 << 16;
const RENDER_MODE_LIGHT: c_uint = 1;
const PIXEL_MODE_MONO: u8 = 1;
const PIXEL_MODE_GRAY: u8 = 2;

fn px26(v: c_long) -> i32 {
    ((v + 32) >> 6) as i32
}

type InitFn = unsafe extern "C" fn(*mut *mut c_void) -> c_int;
type NewMemoryFaceFn = unsafe extern "C" fn(*mut c_void, *const u8, c_long, c_long, *mut *mut FaceRec) -> c_int;
type SetPixelSizesFn = unsafe extern "C" fn(*mut FaceRec, c_uint, c_uint) -> c_int;
type GetCharIndexFn = unsafe extern "C" fn(*mut FaceRec, c_ulong) -> c_uint;
type LoadGlyphFn = unsafe extern "C" fn(*mut FaceRec, c_uint, i32) -> c_int;
type RenderGlyphFn = unsafe extern "C" fn(*mut GlyphSlotRec, c_uint) -> c_int;
type SlotFn = unsafe extern "C" fn(*mut GlyphSlotRec);
type DoneFaceFn = unsafe extern "C" fn(*mut FaceRec) -> c_int;
type DoneLibraryFn = unsafe extern "C" fn(*mut c_void) -> c_int;

struct Api {
    _lib: libloading::Library,
    new_memory_face: NewMemoryFaceFn,
    set_pixel_sizes: SetPixelSizesFn,
    get_char_index: GetCharIndexFn,
    load_glyph: LoadGlyphFn,
    render_glyph: RenderGlyphFn,
    embolden: SlotFn,
    oblique: SlotFn,
    done_face: DoneFaceFn,
    done_library: DoneLibraryFn,
}

impl Api {
    fn load() -> Option<Api> {
        // SAFETY: FreeType ist eine gewöhnliche C-Bibliothek ohne Initialisierungscode beim Laden.
        let lib = unsafe { libloading::Library::new("libfreetype.so.6") }.ok()?;
        // SAFETY: Die Signaturen entsprechen der FreeType-2-API.
        unsafe {
            Some(Api {
                new_memory_face: *lib.get(b"FT_New_Memory_Face\0").ok()?,
                set_pixel_sizes: *lib.get(b"FT_Set_Pixel_Sizes\0").ok()?,
                get_char_index: *lib.get(b"FT_Get_Char_Index\0").ok()?,
                load_glyph: *lib.get(b"FT_Load_Glyph\0").ok()?,
                render_glyph: *lib.get(b"FT_Render_Glyph\0").ok()?,
                embolden: *lib.get(b"FT_GlyphSlot_Embolden\0").ok()?,
                oblique: *lib.get(b"FT_GlyphSlot_Oblique\0").ok()?,
                done_face: *lib.get(b"FT_Done_Face\0").ok()?,
                done_library: *lib.get(b"FT_Done_FreeType\0").ok()?,
                _lib: lib,
            })
        }
    }
}

/// Eine geladene Schrift in einer festen Pixelgröße.
struct Face {
    ptr: *mut FaceRec,
    /// FreeType liest direkt aus diesem Speicher, er muss so lange leben wie das Face.
    _data: Arc<[u8]>,
}

/// Fertig gerastertes Zeichen, Maße in Bildschirmpixeln.
pub struct Bitmap8 {
    pub width: usize,
    pub height: usize,
    pub left: i32,
    pub top: i32,
    pub coverage: Vec<u8>,
}

pub struct FreeType {
    api: Api,
    library: *mut c_void,
    regular: Face,
    bold: Option<Face>,
}

// SAFETY: Alle Zugriffe laufen über einen Mutex im UI-Thread; FreeType-Objekte werden nie
// gleichzeitig benutzt.
unsafe impl Send for FreeType {}

/// Schriftdateien für die Terminalschrift: Normal- und optional Fettschnitt, jeweils Daten und
/// Index innerhalb von Sammeldateien (.ttc).
#[derive(Clone)]
pub struct FontSource {
    pub regular: (Arc<[u8]>, u32),
    pub bold: Option<(Arc<[u8]>, u32)>,
}

impl FontSource {
    /// Das eingebaute Hack, mit dem installierten Hack Bold, falls vorhanden.
    pub fn builtin() -> FontSource {
        FontSource {
            regular: (Arc::from(epaint_default_fonts::HACK_REGULAR), 0),
            bold: crate::fonts::hack_bold_bytes().map(|b| (b, 0)),
        }
    }
}

/// Zellmaße der Terminalschrift in Bildschirmpixeln.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Metrics {
    pub advance: i32,
    pub height: i32,
    pub ascent: i32,
}

impl FreeType {
    /// Lädt FreeType mit der gewählten Schrift (Daten und Index in Sammeldateien).
    pub fn new(source: &FontSource) -> Option<FreeType> {
        let api = Api::load()?;
        let mut library = std::ptr::null_mut();
        // SAFETY: Signatur entspricht FT_Init_FreeType.
        let init: InitFn = unsafe { *api._lib.get::<InitFn>(b"FT_Init_FreeType\0").ok()? };
        // SAFETY: Ausgabeparameter für die neue Bibliothek.
        if unsafe { init(&mut library) } != 0 {
            return None;
        }
        let open = |(data, index): &(Arc<[u8]>, u32)| -> Option<Face> {
            let mut ptr = std::ptr::null_mut();
            // SAFETY: `data` lebt im zurückgegebenen Face weiter.
            let err = unsafe {
                (api.new_memory_face)(library, data.as_ptr(), data.len() as c_long, *index as c_long, &mut ptr)
            };
            (err == 0 && !ptr.is_null()).then(|| Face { ptr, _data: data.clone() })
        };
        let Some(regular) = open(&source.regular) else {
            // SAFETY: Bibliothek wurde oben angelegt und hat noch keine Faces.
            unsafe { (api.done_library)(library) };
            return None;
        };
        let bold = source.bold.as_ref().and_then(open);
        Some(FreeType { api, library, regular, bold })
    }

    fn set_size(&self, face: &Face, px: u32) -> bool {
        // SAFETY: gültiges Face.
        unsafe { (self.api.set_pixel_sizes)(face.ptr, 0, px) == 0 }
    }

    pub fn metrics(&self, px: u32) -> Option<Metrics> {
        if !self.set_size(&self.regular, px) {
            return None;
        }
        // SAFETY: Face und Größe sind gesetzt.
        unsafe {
            let size = &*(*self.regular.ptr).size;
            let m = &size.metrics;
            let index = (self.api.get_char_index)(self.regular.ptr, 'M' as c_ulong);
            if (self.api.load_glyph)(self.regular.ptr, index, LOAD_TARGET_LIGHT) != 0 {
                return None;
            }
            let advance = px26((*(*self.regular.ptr).glyph).advance[0]);
            Some(Metrics { advance: advance.max(1), height: px26(m.height).max(1), ascent: px26(m.ascender) })
        }
    }

    /// Rastert ein Zeichen. `None`, wenn die Schrift es nicht hat (dann übernimmt egui).
    pub fn render(&self, c: char, px: u32, bold: bool, italic: bool) -> Option<Bitmap8> {
        let (face, synthetic_bold) = match (&self.bold, bold) {
            (Some(b), true) => (b, false),
            (_, b) => (&self.regular, b),
        };
        if !self.set_size(face, px) {
            return None;
        }
        // SAFETY: Face ist gültig; die Bitmap gehört FreeType und wird vor dem nächsten Aufruf kopiert.
        unsafe {
            let index = (self.api.get_char_index)(face.ptr, c as c_ulong);
            if index == 0 {
                return None;
            }
            if (self.api.load_glyph)(face.ptr, index, LOAD_TARGET_LIGHT) != 0 {
                return None;
            }
            let slot = (*face.ptr).glyph;
            if synthetic_bold {
                (self.api.embolden)(slot);
            }
            if italic {
                (self.api.oblique)(slot);
            }
            if (self.api.render_glyph)(slot, RENDER_MODE_LIGHT) != 0 {
                return None;
            }
            let bm = &(*slot).bitmap;
            let (width, height) = (bm.width as usize, bm.rows as usize);
            let mut coverage = vec![0u8; width * height];
            if width > 0 && height > 0 && !bm.buffer.is_null() {
                let pitch = bm.pitch as isize;
                for y in 0..height {
                    let row = bm.buffer.offset(pitch * y as isize);
                    for x in 0..width {
                        coverage[y * width + x] = match bm.pixel_mode {
                            PIXEL_MODE_GRAY => *row.add(x),
                            PIXEL_MODE_MONO => {
                                if *row.add(x / 8) & (0x80 >> (x % 8)) != 0 { 255 } else { 0 }
                            }
                            _ => return None,
                        };
                    }
                }
            }
            Some(Bitmap8 { width, height, left: (*slot).bitmap_left, top: (*slot).bitmap_top, coverage })
        }
    }
}

impl Drop for FreeType {
    fn drop(&mut self) {
        // SAFETY: Faces vor der Bibliothek freigeben.
        unsafe {
            (self.api.done_face)(self.regular.ptr);
            if let Some(b) = &self.bold {
                (self.api.done_face)(b.ptr);
            }
            (self.api.done_library)(self.library);
        }
    }
}

// --- Glyphen-Textur --------------------------------------------------------------------------

const ATLAS: usize = 1024;

#[derive(Clone, Copy)]
pub struct Glyph {
    /// Position in der Textur (normiert).
    pub uv: Rect,
    /// Versatz zur linken oberen Zellecke und Größe, in Bildschirmpixeln.
    pub offset: Vec2,
    pub size: Vec2,
}

pub struct GlyphCache {
    ft: FreeType,
    px: u32,
    family: String,
    pub metrics: Metrics,
    atlas: TextureHandle,
    cursor: (usize, usize, usize),
    glyphs: HashMap<(char, bool, bool), Option<Glyph>>,
}

impl GlyphCache {
    fn new(ctx: &egui::Context, ft: FreeType, px: u32, family: &str) -> Option<GlyphCache> {
        let metrics = ft.metrics(px)?;
        let atlas = ctx.load_texture("terminal-glyphs", ColorImage::new([ATLAS, ATLAS], vec![Color32::TRANSPARENT; ATLAS * ATLAS]), TextureOptions::NEAREST);
        Some(GlyphCache { ft, px, family: family.to_owned(), metrics, atlas, cursor: (1, 1, 0), glyphs: HashMap::new() })
    }

    pub fn texture_id(&self) -> egui::TextureId {
        self.atlas.id()
    }

    /// Glyphe holen und bei Bedarf rastern. `None` heißt: egui soll das Zeichen zeichnen.
    pub fn glyph(&mut self, c: char, bold: bool, italic: bool) -> Option<Glyph> {
        if let Some(g) = self.glyphs.get(&(c, bold, italic)) {
            return *g;
        }
        let glyph = self.rasterize(c, bold, italic);
        self.glyphs.insert((c, bold, italic), glyph);
        glyph
    }

    fn rasterize(&mut self, c: char, bold: bool, italic: bool) -> Option<Glyph> {
        let bm = self.ft.render(c, self.px, bold, italic)?;
        let (w, h) = (bm.width, bm.height);
        if w == 0 || h == 0 {
            // Leerzeichen und Ähnliches: nichts zu zeichnen, aber von FreeType abgedeckt.
            return Some(Glyph { uv: Rect::NOTHING, offset: Vec2::ZERO, size: Vec2::ZERO });
        }
        if w + 2 > ATLAS || h + 2 > ATLAS {
            return None;
        }
        // Zeilenweise packen, mit einem Pixel Abstand gegen Überlauf beim Filtern.
        let (mut x, mut y, mut row_h) = self.cursor;
        if x + w + 1 > ATLAS {
            x = 1;
            y += row_h + 1;
            row_h = 0;
        }
        if y + h + 1 > ATLAS {
            // Textur voll: neu beginnen. Selten, betrifft dann nur einen Frame.
            self.glyphs.clear();
            self.atlas.set(ColorImage::new([ATLAS, ATLAS], vec![Color32::TRANSPARENT; ATLAS * ATLAS]), TextureOptions::NEAREST);
            (x, y, row_h) = (1, 1, 0);
        }
        let pixels = bm.coverage.iter().map(|&a| Color32::from_rgba_premultiplied(a, a, a, a)).collect();
        self.atlas.set_partial([x, y], ColorImage::new([w, h], pixels), TextureOptions::NEAREST);
        self.cursor = (x + w + 1, y, row_h.max(h));
        let s = ATLAS as f32;
        Some(Glyph {
            uv: Rect::from_min_size(Pos2::new(x as f32 / s, y as f32 / s), Vec2::new(w as f32 / s, h as f32 / s)),
            offset: Vec2::new(bm.left as f32, (self.metrics.ascent - bm.top) as f32),
            size: Vec2::new(w as f32, h as f32),
        })
    }
}

/// Pro Fenster ein Cache für Schrift und Pixelgröße. `None`, wenn FreeType nicht verfügbar ist.
/// `family` leer heißt: eingebautes Hack. Fehlt die gewählte Schrift, wird Hack verwendet und
/// [`take_missing_font`] meldet das einmal.
pub fn cache(ctx: &egui::Context, px: u32, family: &str) -> Option<Arc<Mutex<GlyphCache>>> {
    type Slot = Option<Arc<Mutex<GlyphCache>>>;
    let id = egui::Id::unique("freetype-glyph-cache");
    let failed = egui::Id::unique("freetype-unavailable");
    if ctx.data(|d| d.get_temp::<bool>(failed)).unwrap_or(false) {
        return None;
    }
    if let Some(Some(c)) = ctx.data(|d| d.get_temp::<Slot>(id)) {
        let current = c.lock();
        if current.px == px && current.family == family {
            drop(current);
            return Some(c);
        }
    }
    let chosen = if family.is_empty() { None } else { crate::fonts::font_source(family) };
    let missing = !family.is_empty() && chosen.is_none();
    let attempt = |source: &FontSource| FreeType::new(source).and_then(|ft| GlyphCache::new(ctx, ft, px, family));
    let created = chosen.as_ref().and_then(attempt).or_else(|| attempt(&FontSource::builtin()));
    match created {
        Some(c) => {
            if missing {
                ctx.data_mut(|d| d.insert_temp(egui::Id::unique("missing-terminal-font"), Some(family.to_owned())));
            }
            let c = Arc::new(Mutex::new(c));
            ctx.data_mut(|d| d.insert_temp::<Slot>(id, Some(c.clone())));
            Some(c)
        }
        None => {
            ctx.data_mut(|d| d.insert_temp(failed, true));
            None
        }
    }
}

/// Name einer gewählten, aber nicht gefundenen Schrift (nur einmal).
pub fn take_missing_font(ctx: &egui::Context) -> Option<String> {
    ctx.data_mut(|d| d.get_temp_mut_or_default::<Option<String>>(egui::Id::unique("missing-terminal-font")).take())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freetype_renders_hack_with_whole_pixel_metrics() {
        let Some(ft) = FreeType::new(&FontSource::builtin()) else {
            eprintln!("Übersprungen: libfreetype.so.6 nicht vorhanden");
            return;
        };
        for px in [12, 14, 16] {
            let m = ft.metrics(px).unwrap();
            // Hack: Vorschub etwa 0,6 em, Zeilenhöhe etwa 1,16 em.
            assert!((m.advance - (px as f32 * 0.602).round() as i32).abs() <= 1, "{px}: {m:?}");
            assert!(m.height >= px as i32 && m.height <= px as i32 * 3 / 2, "{px}: {m:?}");
            assert!(m.ascent > 0 && m.ascent < m.height, "{px}: {m:?}");
            let g = ft.render('M', px, false, false).unwrap();
            assert!(g.width > 0 && g.height > 0 && g.coverage.contains(&255), "{px}: volle Deckung erwartet");
            let bold = ft.render('M', px, true, false).unwrap();
            let sum = |b: &Bitmap8| b.coverage.iter().map(|&a| a as u32).sum::<u32>();
            assert!(sum(&bold) > sum(&g), "Fett muss mehr Farbe haben");
        }
        assert!(ft.render('\u{10fffd}', 12, false, false).is_none(), "Fehlendes Zeichen geht an egui");
        let space = ft.render(' ', 12, false, false).unwrap();
        assert_eq!(space.width * space.height, 0);
    }

    #[test]
    fn glyph_cache_packs_and_reuses() {
        let ctx = egui::Context::default();
        let mut out = ctx.run_ui(Default::default(), |ui| {
            let Some(cache) = super::cache(ui.ctx(), 12, "") else {
                eprintln!("Übersprungen: libfreetype.so.6 nicht vorhanden");
                return;
            };
            let mut c = cache.lock();
            let a = c.glyph('a', false, false).unwrap();
            let b = c.glyph('b', false, false).unwrap();
            assert_ne!(a.uv, b.uv);
            assert_eq!(c.glyph('a', false, false).unwrap().uv, a.uv, "zweiter Aufruf aus dem Cache");
            assert!(c.glyph('\u{10fffd}', false, false).is_none());
            drop(c);
            let same = super::cache(ui.ctx(), 12, "").unwrap();
            assert!(Arc::ptr_eq(&cache, &same));
            let bigger = super::cache(ui.ctx(), 16, "").unwrap();
            assert_eq!(bigger.lock().px, 16);
            // Unbekannte Schrift: Hack wird verwendet und das einmal gemeldet.
            let unknown = super::cache(ui.ctx(), 16, "Gibt Es Nicht Mono").unwrap();
            assert_eq!(unknown.lock().metrics, bigger.lock().metrics);
            assert_eq!(super::take_missing_font(ui.ctx()).as_deref(), Some("Gibt Es Nicht Mono"));
            assert_eq!(super::take_missing_font(ui.ctx()), None);
        });
        out.textures_delta.clear();
    }
}
