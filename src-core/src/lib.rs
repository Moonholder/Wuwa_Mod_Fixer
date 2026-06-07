// src-core/src/lib.rs
// Pure Rust core library — no GUI, no CLI, no Tauri dependencies

#[macro_use]
pub mod localization;
pub mod config_loader;
pub mod collector;
pub mod rollback;
pub mod settings;
pub mod mod_fixer;

pub use mod_fixer::ModFixer;

// ---------------------------------------------------------------------------
// Progress reporter trait — injected by callers (CLI prints, Tauri emits)
// ---------------------------------------------------------------------------
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

pub trait ProgressReporter: Send + Sync {
    fn set_total(&self, total: usize);
    fn increment(&self);
    fn current(&self) -> usize;
    fn total(&self) -> usize;
}

/// Simple atomic-based reporter (used by CLI and as default)
pub struct AtomicProgress {
    current: Arc<AtomicUsize>,
    total:   Arc<AtomicUsize>,
}

impl AtomicProgress {
    pub fn new() -> Self {
        Self {
            current: Arc::new(AtomicUsize::new(0)),
            total:   Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Default for AtomicProgress {
    fn default() -> Self { Self::new() }
}

impl ProgressReporter for AtomicProgress {
    fn set_total(&self, total: usize) { self.total.store(total, Ordering::Relaxed); }
    fn increment(&self)               { self.current.fetch_add(1, Ordering::Relaxed); }
    fn current(&self) -> usize        { self.current.load(Ordering::Relaxed) }
    fn total(&self) -> usize          { self.total.load(Ordering::Relaxed) }
}
