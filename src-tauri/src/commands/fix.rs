// fix.rs — start_fix command
// Spawns ModFixer in blocking thread, streams log+progress via Tauri events

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use serde::Serialize;
use tauri::{AppHandle, Emitter};
use wuwa_mod_core as core;
use wuwa_mod_core::{EventSink, ProgressReporter};

#[derive(Clone, Serialize)]
pub struct LogPayload {
    pub level: String,
    pub message: String,
}

#[derive(Clone, Serialize)]
pub struct ProgressPayload {
    pub current: usize,
    pub total: usize,
}

// Tauri-side EventSink & ProgressReporter: emits structured events and progress to frontend
struct TauriEventSink {
    app: AppHandle,
    current: Arc<AtomicUsize>,
    total: Arc<AtomicUsize>,
    last_emit: std::sync::Mutex<std::time::Instant>,
    last_filestart: std::sync::Mutex<std::time::Instant>,
}

impl core::EventSink for TauriEventSink {
    fn emit(&self, event: core::PipelineEvent) {
        match event {
            core::PipelineEvent::Start { total, .. } => {
                self.total.store(total, Ordering::Relaxed);
                let _ = self.app.emit("fix:pipeline_event", &event);
                let _ = self.app.emit(
                    "fix:progress",
                    ProgressPayload {
                        current: self.current.load(Ordering::Relaxed),
                        total,
                    },
                );
            }
            core::PipelineEvent::Progress { current, total, .. } => {
                self.current.store(current, Ordering::Relaxed);
                self.total.store(total, Ordering::Relaxed);

                let mut should_emit = current == total;
                if !should_emit {
                    if let Ok(mut last) = self.last_emit.try_lock() {
                        if last.elapsed() > std::time::Duration::from_millis(40) {
                            *last = std::time::Instant::now();
                            should_emit = true;
                        }
                    }
                }

                if should_emit {
                    let _ = self.app.emit("fix:pipeline_event", &event);
                    let _ = self.app.emit("fix:progress", ProgressPayload { current, total });
                }
            }
            core::PipelineEvent::FileStart { current, total, .. } => {
                let mut should_emit = current == total || current <= 1;
                if !should_emit {
                    if let Ok(mut last) = self.last_filestart.try_lock() {
                        if last.elapsed() > std::time::Duration::from_millis(50) {
                            *last = std::time::Instant::now();
                            should_emit = true;
                        }
                    }
                }
                if should_emit {
                    let _ = self.app.emit("fix:pipeline_event", &event);
                }
            }
            // Critical lifecycle and completion events are always dispatched immediately
            _ => {
                let _ = self.app.emit("fix:pipeline_event", &event);
            }
        }
    }
}

impl ProgressReporter for TauriEventSink {
    fn set_total(&self, total: usize) {
        self.emit(core::PipelineEvent::Start {
            mode: "fix".to_string(),
            total,
            session_time: None,
        });
    }

    fn increment(&self) {
        let cur = self.current.fetch_add(1, Ordering::Relaxed) + 1;
        let tot = self.total.load(Ordering::Relaxed);
        let percent = if tot > 0 {
            (cur as f64 / tot as f64 * 1000.0).round() / 10.0
        } else {
            100.0
        };
        self.emit(core::PipelineEvent::Progress {
            current: cur,
            total: tot,
            percent,
            status_text: None,
        });
    }

    fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }

    fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }
}

#[derive(Clone)]
pub struct FixTaskState {
    pub cancel_flag: Arc<std::sync::Mutex<Option<Arc<AtomicBool>>>>,
}

struct FixTaskCleanupGuard {
    cancel_flag: Arc<std::sync::Mutex<Option<Arc<AtomicBool>>>>,
}

impl Drop for FixTaskCleanupGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.cancel_flag.lock() {
            *guard = None;
        }
        crate::GUI_LOG_TX.store(None);
    }
}

use crate::error::AppError;

#[tauri::command]
pub async fn cancel_fix(state: tauri::State<'_, FixTaskState>) -> Result<(), AppError> {
    if let Ok(guard) = state.cancel_flag.lock() {
        if let Some(ref token) = *guard {
            token.store(true, Ordering::Release);
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn start_fix(
    app: AppHandle,
    state: tauri::State<'_, FixTaskState>,
    path: String,
    enable_texture_override: bool,
    enable_stable_texture: bool,
    enable_fix_aemeath_mech: bool,
    enable_rendering33_fix: bool,
    aero_fix_mode: u8,
) -> Result<(), AppError> {
    let app2 = app.clone();

    let cancel_token = Arc::new(AtomicBool::new(false));
    if let Ok(mut guard) = state.cancel_flag.lock() {
        if guard.is_some() {
            return Err(AppError::FileLocked(core::localization::get_text_for_current_lang(
                "app.task_already_running",
                "已有修复任务正在运行，请勿重复触发！",
            )));
        }
        *guard = Some(cancel_token.clone());
    }

    // Tap into broadcast log channel
    let (tx, mut rx) = tokio::sync::broadcast::channel::<String>(512);
    crate::GUI_LOG_TX.store(Some(Arc::new(tx)));

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
                                    else if msg.contains("[DEBUG]") { "DEBUG" }
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

    let cancel_flag_clone = state.cancel_flag.clone();
    // Run fix in blocking thread
    tokio::task::spawn_blocking(move || {
        let _guard = FixTaskCleanupGuard {
            cancel_flag: cancel_flag_clone,
        };

        let event_sink = Arc::new(TauriEventSink {
            app: app2.clone(),
            current: Arc::new(AtomicUsize::new(0)),
            total: Arc::new(AtomicUsize::new(0)),
            last_emit: std::sync::Mutex::new(std::time::Instant::now()),
            last_filestart: std::sync::Mutex::new(std::time::Instant::now()),
        });

        let cfg = core::config_loader::config();
        let fixer = core::ModFixer::with_event_sink(
            cfg.characters_ref(),
            enable_texture_override,
            enable_stable_texture,
            enable_fix_aemeath_mech,
            enable_rendering33_fix,
            aero_fix_mode,
            event_sink,
            cancel_token,
        );
        let _ = fixer.process_directory(std::path::Path::new(&path));
    });

    Ok(())
}
