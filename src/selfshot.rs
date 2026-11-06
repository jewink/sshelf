//! Diagnose: zeigt ein Terminal mit Beispieltext im echten Renderer, speichert ein Bild nur des
//! eigenen Fensters und beendet sich. Nur mit `--features selfshot` enthalten.
//! Aufruf: SSHELF_SELFSHOT=/pfad/bild.png sshelf

use eframe::egui;
use std::sync::Arc;

const SAMPLE: &str = "\x1b[1;32m[jens@archserver ~]$\x1b[0m cd docker/\r\n\
\x1b[1;32m[jens@archserver docker]$\x1b[0m ls\r\n\
\x1b[1;34matuin      baikal        convertx  dashy  glance     it-tools\x1b[0m\r\n\
\x1b[1;34mauthelia   bentopdf      couchdb   filen  guacamole  kutt\x1b[0m\r\n\
\x1b[1;32m[jens@archserver atuin]$\x1b[0m dcp\r\n\
[+] pull 18/18\r\n \x1b[32m\u{2714}\x1b[0m Image postgres:16-alpine           \x1b[32mPulled\x1b[0m\r\n\
dr-xr-xr-x   1 root root  148 Sep 12 20:59 .\r\n\
Locale: de_DE.UTF-8  Umlaute: \u{e4}\u{f6}\u{fc}\u{df} 0O 1lI\r\n";

struct Shot {
    shared: Arc<crate::term::Shared>,
    cmds: tokio::sync::mpsc::UnboundedSender<crate::ssh::Cmd>,
    view: crate::term::ViewState,
    frames: u32,
    path: String,
}

impl eframe::App for Shot {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.frames += 1;
        let palette = crate::theme::TermPalette::for_mode(true);
        egui::CentralPanel::default().frame(egui::Frame::new().fill(palette.bg)).show(ui, |ui| {
            let size = std::env::var("SSHELF_FONTSIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(14.0);
            let family = std::env::var("SSHELF_FONT").unwrap_or_default();
            crate::term::show(ui, &self.shared, &self.cmds, &mut self.view, &palette, crate::term::TermFont { size, family: &family }, false);
        });
        if self.frames == 20 {
            let path = self.path.clone();
            let callback = egui::ScreenshotCallback::new(move |image: Arc<egui::ColorImage>| {
                let [w, h] = image.size;
                let rgba: Vec<u8> = image.pixels.iter().flat_map(|p| p.to_array()).collect();
                image::RgbaImage::from_raw(w as u32, h as u32, rgba).expect("Bildgröße").save(&path).expect("Bild speichern");
                std::process::exit(0);
            });
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Screenshot(callback));
        }
        ui.ctx().request_repaint();
    }
}

pub fn run(path: String) -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([660.0, 200.0]).with_app_id("sshelf-selfshot"),
        system_font_fallback: false,
        ..Default::default()
    };
    eframe::run_native(
        "SSHelf-Diagnose",
        options,
        Box::new(move |cc| {
            crate::theme::apply_style(&cc.egui_ctx);
            let _ = crate::fonts::install(&cc.egui_ctx);
            cc.egui_ctx.set_theme(egui::ThemePreference::Dark);
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
            let shared = crate::term::Shared::new(tx.clone(), cc.egui_ctx.clone(), true);
            shared.feed(SAMPLE.as_bytes());
            Ok(Box::new(Shot { shared, cmds: tx, view: Default::default(), frames: 0, path }))
        }),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}

