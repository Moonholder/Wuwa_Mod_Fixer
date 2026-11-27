// src-core/src/slot_fix/resolve.rs

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};
use serde::{Deserialize, Serialize};

use crate::{
    config_loader::{CharacterConfig, CompiledSlotRule},
    domain::cst::IniCstDocument,
    errors::FixerError,
    utils::fs_utils,
};

use super::{
    engine::{apply_to_document_filtered, ComponentState},
    manifest::{clear_session_manifest, load_session_manifest},
    session::{AmbiguousSlotItem, OverlapPolicy, SlotFixSession},
};

/// User decision for one ambiguous component in phase 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlapDecision {
    /// "Old version": shift statements using epoch 0 closures.
    Shift,
    /// "New version": pin statements at latest revision.
    KeepAndPin,
    /// Explicit epoch selection.
    Epoch(u32),
}

/// Applies one phase-2 decision, reusing the phase 1 session timestamp so that a
/// single `--rollback` reverts both phases atomically.
pub fn resolve_ambiguous_item(
    item: &AmbiguousSlotItem,
    rule: &CompiledSlotRule,
    config: &CharacterConfig,
    decision: OverlapDecision,
    session_ts: &str,
) -> Result<bool, FixerError> {
    let path = Path::new(&item.abs_ini_path);
    if !path.is_file() {
        return Err(FixerError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Ambiguous target disappeared: {}", item.abs_ini_path),
        )));
    }
    let content = std::fs::read_to_string(path)?;
    let mut doc = IniCstDocument::parse(&content);

    let state = match decision {
        OverlapDecision::Shift => ComponentState::DeterminedEpoch(0),
        OverlapDecision::KeepAndPin => ComponentState::DeterminedEpoch(rule.latest_rev),
        OverlapDecision::Epoch(ep) => ComponentState::DeterminedEpoch(ep),
    };

    let session = SlotFixSession::new(session_ts.to_string(), OverlapPolicy::Ask, PathBuf::new());
    let outcome = apply_to_document_filtered(
        &mut doc,
        rule,
        config,
        &HashSet::new(),
        path,
        &session,
        Some((&item.section_name, state)),
    );

    if !outcome.modified {
        return Ok(false);
    }

    let ts = if session_ts.is_empty() {
        chrono::Local::now().format("%Y-%m-%d %H-%M-%S").to_string()
    } else {
        session_ts.to_string()
    };
    // Never clobber the phase 1 snapshot: both phases share the timestamp, so a
    // single rollback has to restore the pristine file.
    fs_utils::create_session_backup_with_time(path, &ts)?;
    std::fs::write(path, doc.to_string())?;
    Ok(true)
}

/// Looks up the compiled slot rule that owns `rule_id` in the loaded config.
pub fn find_rule<'a>(configs: &'a HashMap<String, CharacterConfig>, rule_id: &str) -> Option<&'a CompiledSlotRule> {
    configs
        .values()
        .filter_map(|cfg| cfg.slot_fix.as_ref())
        .find(|rule| rule.rule_id == rule_id)
}

/// Resolves a batch of phase-2 decisions.
///
/// `shift_ids` are interpreted as "old version, shift them", `keep_ids` as
/// "new version, keep and pin". Every item reuses `session_ts`.
pub fn resolve_session(
    session_ts: &str,
    configs: &HashMap<String, CharacterConfig>,
    shift_ids: &[String],
    keep_ids: &[String],
) -> Result<(usize, usize), FixerError> {
    let manifest = load_session_manifest(session_ts).ok_or_else(|| {
        FixerError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("No pending slot-fix session '{session_ts}' found."),
        ))
    })?;

    let shift_set: HashSet<&str> = shift_ids.iter().map(|s| s.as_str()).collect();
    let keep_set: HashSet<&str> = keep_ids.iter().map(|s| s.as_str()).collect();

    let mut changed = 0usize;
    let mut touched = 0usize;
    for item in &manifest.items {
        let decision = if shift_set.contains(item.item_id.as_str()) {
            Some(OverlapDecision::Shift)
        } else if keep_set.contains(item.item_id.as_str()) {
            Some(OverlapDecision::KeepAndPin)
        } else {
            None
        };
        let Some(decision) = decision else { continue };
        let Some(rule) = find_rule(configs, &item.rule_id) else {
            continue;
        };
        let Some(config) = configs.values().find(|cfg| {
            cfg.slot_fix
                .as_ref()
                .map(|r| r.rule_id == item.rule_id)
                .unwrap_or(false)
        }) else {
            continue;
        };
        if resolve_ambiguous_item(item, rule, config, decision, session_ts)? {
            changed += 1;
        }
        touched += 1;
    }

    if touched > 0 {
        clear_session_manifest(session_ts);
    }
    Ok((touched, changed))
}
