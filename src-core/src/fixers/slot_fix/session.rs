// src-core/src/slot_fix/session.rs

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use serde::{Deserialize, Serialize};

use crate::events::{EventSink, PipelineEvent, SlotFixEvent};

/// What phase 1 does with a genuinely undecidable overlap slot
/// (`Dom(M) ∩ Cod(M)`, e.g. a lone `ps-t7`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlapPolicy {
    /// Default interactive mode: defer the component to phase 2.
    #[default]
    Ask,
    /// Treat every unmarked overlap slot as "not shifted yet"
    /// (`ps-t7 -> ps-t8`, `orig=ps-t7`).
    ShiftAll,
    /// Treat every unmarked overlap slot as "already shifted"
    /// (keep `ps-t7`, pin `orig=ps-t6`).
    KeepAllAndPin,
    /// Leave ambiguous components completely untouched.
    SkipAll,
}

impl OverlapPolicy {
    /// CLI / IPC alias parser (`ask`, `shift`, `keep`, `skip`).
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "ask" | "prompt" => Some(Self::Ask),
            "shift" | "shift-all" | "shift_all" | "old" => Some(Self::ShiftAll),
            "keep" | "keep-all" | "keep_all_and_pin" | "pin" | "new" => Some(Self::KeepAllAndPin),
            "skip" | "skip-all" | "skip_all" | "none" => Some(Self::SkipAll),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::ShiftAll => "shift",
            Self::KeepAllAndPin => "keep",
            Self::SkipAll => "skip",
        }
    }
}

/// One statement preview shown in the phase 2 confirmation UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbiguousLinePreview {
    /// 1-based line number inside the .ini file.
    pub line_number: usize,
    pub raw_code: String,
    /// Slot currently written in the file (`ps-t7`).
    pub current_slot: String,
    /// Slot it would become if interpreted as "not shifted yet".
    pub if_shifted_slot: String,
    /// Slot recorded as `orig` if interpreted as "already shifted".
    pub if_kept_orig_slot: String,
    /// Per-candidate epoch mapping: epoch -> target slot preview.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub epoch_targets: HashMap<u32, String>,
}

/// A whole component whose slot state could not be decided deterministically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbiguousSlotItem {
    /// Stable identity: `sha256(rel_ini_path + "::" + section_name + "::" + rule_id)`.
    pub item_id: String,
    /// Top-level sub-mod folder (used to group the GUI drawer).
    pub mod_folder_name: String,
    /// .ini path relative to the user-selected root.
    pub rel_ini_path: String,
    /// Absolute path, used by phase 2 to write directly.
    pub abs_ini_path: String,
    pub section_name: String,
    pub rule_id: String,
    pub character: String,
    pub rev: u32,
    pub affected_lines: Vec<AmbiguousLinePreview>,
    /// Candidate epochs determined for this component.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_epochs: Vec<u32>,
    /// Optional diagnostic reason when conflict is detected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict_reason: Option<String>,
}

pub fn short_hash_id(rel: &str, section: &str, rule_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(rel.as_bytes());
    hasher.update(b"::");
    hasher.update(section.as_bytes());
    hasher.update(b"::");
    hasher.update(rule_id.as_bytes());
    let digest = hasher.finalize();
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Shared two-phase session state.
///
/// The same instance is cloned into every `ModContext` of one `process_directory`
/// run, so the ambiguity queue and the session timestamp are shared even though
/// files are processed in parallel by rayon.
pub struct SlotFixSession {
    pub session_ts: String,
    pub policy: OverlapPolicy,
    pub root: PathBuf,
    sink: Option<Arc<dyn EventSink>>,
    ambiguous: Mutex<Vec<AmbiguousSlotItem>>,
}

impl Default for SlotFixSession {
    fn default() -> Self {
        Self {
            session_ts: String::new(),
            policy: OverlapPolicy::Ask,
            root: PathBuf::new(),
            sink: None,
            ambiguous: Mutex::new(Vec::new()),
        }
    }
}

impl std::fmt::Debug for SlotFixSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotFixSession")
            .field("session_ts", &self.session_ts)
            .field("policy", &self.policy)
            .field("root", &self.root)
            .finish()
    }
}

impl SlotFixSession {
    pub fn new(session_ts: impl Into<String>, policy: OverlapPolicy, root: PathBuf) -> Self {
        Self {
            session_ts: session_ts.into(),
            policy,
            root,
            sink: None,
            ambiguous: Mutex::new(Vec::new()),
        }
    }

    pub fn with_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    pub fn emit(&self, event: SlotFixEvent) {
        if let Some(sink) = &self.sink {
            sink.emit(PipelineEvent::from(event));
        }
    }

    pub fn push_ambiguous(&self, item: AmbiguousSlotItem) {
        if let Ok(mut guard) = self.ambiguous.lock() {
            if !guard.iter().any(|existing| existing.item_id == item.item_id) {
                guard.push(item);
            }
        }
    }

    pub fn ambiguous_snapshot(&self) -> Vec<AmbiguousSlotItem> {
        self.ambiguous.lock().map(|guard| guard.clone()).unwrap_or_default()
    }

    pub fn take_ambiguous(&self) -> Vec<AmbiguousSlotItem> {
        self.ambiguous
            .lock()
            .map(|mut guard| std::mem::take(&mut *guard))
            .unwrap_or_default()
    }

    pub fn has_ambiguous(&self) -> bool {
        self.ambiguous.lock().map(|guard| !guard.is_empty()).unwrap_or(false)
    }

    /// Path of `ini_path` relative to the session root (forward slashes).
    pub fn rel_path(&self, ini_path: &Path) -> String {
        let rel = if self.root.as_os_str().is_empty() {
            None
        } else {
            ini_path.strip_prefix(&self.root).ok()
        };
        let rel = rel.unwrap_or(ini_path);
        rel.to_string_lossy().replace('\\', "/")
    }

    pub fn mod_folder_of(rel: &str) -> String {
        match rel.split_once('/') {
            Some((head, _)) if !head.is_empty() => head.to_string(),
            _ => String::new(),
        }
    }
}
