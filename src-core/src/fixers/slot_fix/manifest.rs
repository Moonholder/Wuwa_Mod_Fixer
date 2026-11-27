// src-core/src/slot_fix/manifest.rs

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use super::session::AmbiguousSlotItem;

/// On-disk manifest allowing a later invocation (or another launcher) to finish
/// phase 2 via `--resolve-session <ts>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotSessionManifest {
    pub session_ts: String,
    pub root: String,
    pub items: Vec<AmbiguousSlotItem>,
}

pub fn manifest_path(session_ts: &str) -> PathBuf {
    crate::settings::app_data_dir()
        .join("slot_sessions")
        .join(format!("{}.json", sanitize_ts(session_ts)))
}

pub fn sanitize_ts(ts: &str) -> String {
    ts.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

pub fn save_session_manifest(root: &Path, session_ts: &str, items: &[AmbiguousSlotItem]) -> Option<PathBuf> {
    if items.is_empty() {
        return None;
    }
    let path = manifest_path(session_ts);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let manifest = SlotSessionManifest {
        session_ts: session_ts.to_string(),
        root: root.to_string_lossy().to_string(),
        items: items.to_vec(),
    };
    let json = serde_json::to_string_pretty(&manifest).ok()?;
    std::fs::write(&path, json).ok()?;
    Some(path)
}

pub fn load_session_manifest(session_ts: &str) -> Option<SlotSessionManifest> {
    let path = manifest_path(session_ts);
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

pub fn clear_session_manifest(session_ts: &str) {
    let _ = std::fs::remove_file(manifest_path(session_ts));
}
