// fix.rs — start_fix command
// Spawns ModFixer in blocking thread, streams log+progress via Tauri events

use serde::Serialize;
use tauri::{AppHandle, Emitter};
use wuwa_mod_core as core;
use wuwa_mod_core::ProgressReporter;
use std::sync::{Arc, atomic::{AtomicUsize, AtomicBool, Ordering}};
use std::sync::LazyLock;

#[derive(Clone, Serialize)]
pub struct LogPayload {
    pub level:   String,
    pub message: String,
}

#[derive(Clone, Serialize)]
pub struct ProgressPayload {
    pub current: usize,
    pub total:   usize,
}

// Tauri-side ProgressReporter: emits events to frontend
struct TauriProgress {
    app:       AppHandle,
    current:   Arc<AtomicUsize>,
    total:     Arc<AtomicUsize>,
    last_emit: std::sync::Mutex<std::time::Instant>,
}

impl ProgressReporter for TauriProgress {
    fn set_total(&self, total: usize) {
        self.total.store(total, Ordering::Relaxed);
        let _ = self.app.emit("fix:progress", ProgressPayload {
            current: self.current.load(Ordering::Relaxed),
            total,
        });
    }
    fn increment(&self) {
        let cur = self.current.fetch_add(1, Ordering::Relaxed) + 1;
        let tot = self.total.load(Ordering::Relaxed);
        
        let mut should_emit = cur == tot;
        if !should_emit {
            if let Ok(mut last) = self.last_emit.try_lock() {
                if last.elapsed() > std::time::Duration::from_millis(50) {
                    *last = std::time::Instant::now();
                    should_emit = true;
                }
            }
        }
        
        if should_emit {
            let _ = self.app.emit("fix:progress", ProgressPayload { current: cur, total: tot });
        }
    }
    fn current(&self) -> usize { self.current.load(Ordering::Relaxed) }
    fn total(&self)   -> usize { self.total.load(Ordering::Relaxed) }
}

// Global flag to interrupt the core processing loop
static CANCEL_FLAG: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));

use crate::error::AppError;

#[tauri::command]
pub async fn cancel_fix() -> Result<(), AppError> {
    CANCEL_FLAG.store(true, Ordering::Release);
    Ok(())
}

#[tauri::command]
pub async fn start_fix(
    app:                      AppHandle,
    path:                     String,
    enable_texture_override:  bool,
    enable_stable_texture:    bool,
    enable_fix_aemeath_mech:  bool,
    aero_fix_mode:            u8,
) -> Result<(), AppError> {
    let app2 = app.clone();

    CANCEL_FLAG.store(false, Ordering::Release);
    let cancel_token = CANCEL_FLAG.clone();
    
    // Tap into broadcast log channel
    let (tx, mut rx) = tokio::sync::broadcast::channel::<String>(512);
    if let Ok(mut guard) = crate::GUI_LOG_TX.lock() {
        *guard = Some(tx);
    }

    // Forward log messages to frontend (Batched to prevent IPC bottleneck)
    let app_log = app.clone();
    tokio::spawn(async move {
        let mut batch = Vec::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(50));
        loop {
            tokio::select! {
                res = rx.recv() => match res {
                    Ok(msg) => {
                        let level = if msg.contains("[ERROR]") { "ERROR" }
                                    else if msg.contains("[WARN]") { "WARN" }
                                    else { "INFO" };
                        batch.push(LogPayload {
                            level:   level.to_string(),
                            message: msg,
                        });
                        if batch.len() >= 200 {
                            let _ = app_log.emit("fix:logs", std::mem::take(&mut batch));
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                },
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        let _ = app_log.emit("fix:logs", std::mem::take(&mut batch));
                    }
                }
            }
        }
        // Emit any remaining logs
        if !batch.is_empty() {
            let _ = app_log.emit("fix:logs", batch);
        }
        let _ = app_log.emit("fix:done", ());
    });

    // Run fix in blocking thread
    tokio::task::spawn_blocking(move || {
        let progress = Arc::new(TauriProgress {
            app:       app2.clone(),
            current:   Arc::new(AtomicUsize::new(0)),
            total:     Arc::new(AtomicUsize::new(0)),
            last_emit: std::sync::Mutex::new(std::time::Instant::now()),
        });

        let cfg = core::config_loader::config();
        let fixer = core::ModFixer::new(
            cfg.characters_ref(),
            enable_texture_override,
            enable_stable_texture,
            enable_fix_aemeath_mech,
            aero_fix_mode,
            progress,
            cancel_token,
        );
        let _ = fixer.process_directory(std::path::Path::new(&path));
        // Clear log sender, which drops tx and causes rx to close.
        // The forwarding task will then flush its batch and emit fix:done.
        if let Ok(mut guard) = crate::GUI_LOG_TX.lock() { *guard = None; }
    });

    Ok(())
}
