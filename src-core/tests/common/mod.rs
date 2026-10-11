// src-core/tests/common/mod.rs
// Common test fixtures and helpers for integration tests

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use wuwa_mod_core::config_loader;
use wuwa_mod_core::domain::context::ModContext;
use wuwa_mod_core::{AtomicProgress, ModFixer};

/// Initializes global test configuration.
pub async fn init_test_config() {
    config_loader::init_config().await;
}

/// Creates a test-scoped ModContext instance.
pub fn create_test_context(ini_path: &Path, content: &str) -> ModContext {
    let original_hashes = HashSet::new();
    ModContext::new(
        ini_path,
        content.to_string(),
        original_hashes,
        true,
        true,
        true,
        1,
        true,
    )
}

/// Creates a test-scoped ModFixer instance.
pub fn create_test_fixer() -> ModFixer<'static> {
    let global_config = config_loader::config();
    ModFixer::new(
        global_config.characters_ref(),
        true,
        true,
        true,
        true,
        1,
        Arc::new(AtomicProgress::new()),
        Arc::new(AtomicBool::new(false)),
    )
}
