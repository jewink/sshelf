//! Symbol in der Statusleiste, über StatusNotifierItem (reines D-Bus, ohne GTK).
//!
//! Unter Wayland lassen sich Fenster nicht verstecken. Darum wird das Fenster beim „Minimieren“
//! wirklich geschlossen, während der Prozess mit allen Sitzungen weiterläuft (siehe `main`).

use eframe::egui;
use ksni::TrayMethods;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

/// Verbindung zwischen Tray-Thread, Oberfläche und Hauptschleife.
pub struct TrayState {
    quit: AtomicBool,
    show: AtomicBool,
    alive: AtomicBool,
    ctx: Mutex<Option<egui::Context>>,
    wake: Mutex<mpsc::Sender<()>>,
    woken: Mutex<mpsc::Receiver<()>>,
}

impl TrayState {
    pub fn new() -> Arc<TrayState> {
        let (wake, woken) = mpsc::channel();
        Arc::new(TrayState {
            quit: AtomicBool::new(false),
            show: AtomicBool::new(false),
            alive: AtomicBool::new(false),
            ctx: Mutex::new(None),
            wake: Mutex::new(wake),
            woken: Mutex::new(woken),
        })
    }

    fn signal(&self) {
        let _ = self.wake.lock().send(());
        if let Some(ctx) = &*self.ctx.lock() {
            ctx.request_repaint();
        }
    }

    pub fn set_ctx(&self, ctx: Option<egui::Context>) {
        *self.ctx.lock() = ctx;
    }

    /// Steht ein Symbol in der Statusleiste? Nur dann darf das Fenster verschwinden, sonst käme
    /// man nicht mehr an die Anwendung heran.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    pub fn set_alive(&self, alive: bool) {
        self.alive.store(alive, Ordering::Relaxed);
    }

    pub fn quit_requested(&self) -> bool {
        self.quit.load(Ordering::Relaxed)
    }

    pub fn take_show_request(&self) -> bool {
        self.show.swap(false, Ordering::Relaxed)
    }

    /// Wartet bei geschlossenem Fenster. `true`: wieder öffnen, `false`: beenden.
    pub fn wait_for_show(&self) -> bool {
        let woken = self.woken.lock();
        loop {
            if self.quit_requested() {
                return false;
            }
            if self.take_show_request() {
                return true;
            }
            if woken.recv().is_err() {
                return false;
            }
        }
    }
}

struct Tray(Arc<TrayState>);

impl ksni::Tray for Tray {
    fn id(&self) -> String {
        "sshelf".into()
    }

    fn title(&self) -> String {
        "SSHelf".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let (size, rgba) = icon_rgba();
        // ksni erwartet ARGB.
        let data = rgba.as_chunks::<4>().0.iter().flat_map(|p| [p[3], p[0], p[1], p[2]]).collect();
        vec![ksni::Icon { width: size as i32, height: size as i32, data }]
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip { title: "SSHelf".into(), ..Default::default() }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.0.show.store(true, Ordering::Relaxed);
        self.0.signal();
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;
        vec![
            StandardItem {
                label: "Öffnen".into(),
                activate: Box::new(|t: &mut Self| {
                    t.0.show.store(true, Ordering::Relaxed);
                    t.0.signal();
                }),
                ..Default::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            StandardItem {
                label: "Beenden".into(),
                activate: Box::new(|t: &mut Self| {
                    t.0.quit.store(true, Ordering::Relaxed);
                    t.0.signal();
                }),
                ..Default::default()
            }
            .into(),
        ]
    }

    fn watcher_online(&self) {
        self.0.set_alive(true);
    }

    /// Verschwindet die Statusleiste, muss ein verstecktes Fenster zurückkommen.
    fn watcher_offline(&self, _reason: ksni::OfflineReason) -> bool {
        self.0.set_alive(false);
        self.0.show.store(true, Ordering::Relaxed);
        self.0.signal();
        true
    }
}

pub struct TrayHandle(ksni::Handle<Tray>);

impl TrayHandle {
    pub fn stop(self, rt: &tokio::runtime::Runtime, state: &TrayState) {
        state.set_alive(false);
        let shutdown = self.0.shutdown();
        rt.block_on(async {
            let _ = tokio::time::timeout(Duration::from_secs(2), shutdown).await;
        });
    }
}

/// Meldet das Symbol an. Fehlschlag heißt meist: Die Arbeitsumgebung hat keine solche Statusleiste.
pub fn start(rt: &tokio::runtime::Runtime, state: &Arc<TrayState>) -> Result<TrayHandle, String> {
    let tray = Tray(state.clone());
    // Das Zeitlimit muss innerhalb der Runtime entstehen.
    let spawned = rt.block_on(async { tokio::time::timeout(Duration::from_secs(3), tray.spawn()).await });
    match spawned {
        Ok(Ok(handle)) => {
            state.set_alive(true);
            Ok(TrayHandle(handle))
        }
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("Zeitüberschreitung".into()),
    }
}

/// Programmsymbol für die Statusleiste: Kantenlänge und RGBA-Pixel.
pub fn icon_rgba() -> (u32, Vec<u8>) {
    (64, crate::desktop::rgba(64))
}
