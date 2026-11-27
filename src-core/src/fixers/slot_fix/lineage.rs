// src-core/src/slot_fix/lineage.rs

use std::{
    collections::{BTreeSet, HashSet},
    path::{Path, PathBuf},
};

use crate::{
    config_loader::{CharacterConfig, CompiledSlotRule},
    domain::cst::IniCstDocument,
    utils::regex_patterns::RE_HASH,
};

use super::{engine::ComponentState, statement::parse_slot_statement};

/// Locates the earliest `.BAK` snapshot of the given .ini (same directory).
pub fn find_earliest_backup(ini_path: &Path) -> Option<PathBuf> {
    let file_name = ini_path.file_name()?.to_str()?.to_string();
    let dir = match ini_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let prefix = format!("{file_name}_");
    let mut best: Option<(String, PathBuf)> = None;

    for entry in std::fs::read_dir(dir).ok()? {
        let Ok(entry) = entry else { continue };
        let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        if !name.starts_with(&prefix) || !name.ends_with(".BAK") {
            continue;
        }
        let ts = &name[prefix.len()..name.len() - 4];
        // Timestamps are `%Y-%m-%d %H-%M-%S`, i.e. lexicographically sortable.
        if ts.len() < 19 {
            continue;
        }
        if best.as_ref().is_none_or(|(best_ts, _)| ts < best_ts.as_str()) {
            best = Some((ts.to_string(), entry.path()));
        }
    }
    best.map(|(_, path)| path)
}

/// Level 4: reverse-engineer the component state from the earliest backup.
pub fn lineage_state(
    ini_path: &Path,
    section_name: &str,
    rule: &CompiledSlotRule,
    config: &CharacterConfig,
    current_slots: &BTreeSet<String>,
) -> Option<ComponentState> {
    let backup_path = find_earliest_backup(ini_path)?;
    let text = std::fs::read_to_string(&backup_path).ok()?;
    let doc = IniCstDocument::parse(&text);
    let sec = doc.get_section(section_name)?;

    let mut slots: HashSet<String> = HashSet::new();
    for line in &sec.lines {
        if let Some(stmt) = parse_slot_statement(line) {
            slots.insert(stmt.slot);
        }
    }

    // If the backup bound an epoch 0 slot that transitioned into a slot now present
    // in current_slots while the backup slot itself is gone, the file was already shifted.
    if let Some(c0) = rule.closures.get(&0) {
        let moved_away = slots.iter().any(|s_bak| {
            !current_slots.contains(s_bak)
                && c0.get(s_bak).map(|s_dst| current_slots.contains(s_dst)).unwrap_or(false)
        });
        if moved_away {
            return Some(ComponentState::DeterminedEpoch(rule.latest_rev));
        }
    }

    // Otherwise, if the backup still carries a pre-update vb0 hash and writes the
    // very same slot, the current file was never shifted.
    let old_hashes: HashSet<String> = config
        .main_hashes
        .iter()
        .flat_map(|rep| rep.old.iter())
        .map(|h| h.to_ascii_lowercase())
        .collect();
    if !old_hashes.is_empty() {
        let backup_hashes: HashSet<String> = RE_HASH
            .captures_iter(&text)
            .map(|cap| cap[1].to_ascii_lowercase())
            .collect();
        if backup_hashes.iter().any(|h| old_hashes.contains(h)) {
            return Some(ComponentState::DeterminedEpoch(0));
        }
    }
    None
}
