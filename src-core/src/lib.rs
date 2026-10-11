// src-core/src/lib.rs
// Pure Rust core library — no GUI, no CLI, no Tauri dependencies

#[macro_use]
pub mod localization;
pub mod collector;
pub mod config_loader;
pub mod domain;
pub mod errors;
pub mod events;
pub mod fixers;
pub mod mod_fixer;
pub mod rollback;
pub mod settings;
pub mod shapekey_fixer;
pub mod utils;

// ---------------------------------------------------------------------------
// Progress reporter trait — backward compatibility for callers
// ---------------------------------------------------------------------------
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

pub use events::{
    ChannelEventSink, EventLevel, EventSink, FixSummary, FnEventSink, LegacyProgressAdapter, NullEventSink,
    PipelineEvent, ProgressReporterSinkAdapter, event_channel,
};
pub use mod_fixer::{ModFixer, ProcessFileOutcome};

pub trait ProgressReporter: Send + Sync {
    fn set_total(&self, total: usize);
    fn increment(&self);
    fn current(&self) -> usize;
    fn total(&self) -> usize;
}

/// Simple atomic-based reporter (used by CLI and as default)
pub struct AtomicProgress {
    current: Arc<AtomicUsize>,
    total: Arc<AtomicUsize>,
}

impl AtomicProgress {
    pub fn new() -> Self {
        Self {
            current: Arc::new(AtomicUsize::new(0)),
            total: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Default for AtomicProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressReporter for AtomicProgress {
    fn set_total(&self, total: usize) {
        self.total.store(total, Ordering::Relaxed);
    }
    fn increment(&self) {
        self.current.fetch_add(1, Ordering::Relaxed);
    }
    fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }
    fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }
}

impl EventSink for AtomicProgress {
    fn emit(&self, event: PipelineEvent) {
        match event {
            PipelineEvent::Start { total, .. } => {
                self.set_total(total);
            }
            PipelineEvent::FileSuccess { .. } | PipelineEvent::FileSkipped { .. } | PipelineEvent::FileError { .. } => {
                self.increment();
            }
            PipelineEvent::Progress { current, total, .. } => {
                let cur = self.current();
                if current > cur {
                    for _ in 0..(current - cur) {
                        self.increment();
                    }
                }
                if self.total() != total {
                    self.set_total(total);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_config_loading_and_fallback_masks() {
        crate::config_loader::init_config().await;
        let global_config = crate::config_loader::config();
        let lynae = global_config.characters_ref().get("Lynae").unwrap();
        assert!(lynae.fallback_masks.is_some());
    }
}
