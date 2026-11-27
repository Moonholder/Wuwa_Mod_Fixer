// src-core/src/slot_fix/engine.rs

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::Path,
};

use crate::{
    config_loader::{CharacterConfig, CompiledSlotRule},
    domain::cst::IniCstDocument,
    events::{SlotFixChange, SlotFixEvent, SlotFixStatus},
};

use super::{
    anchor::{compute_stmt_sig, format_wmf_anchor_line, indent_of, parse_wmf_anchor_line, WmfAnchor},
    lineage::lineage_state,
    scope::{compute_scope, find_roots, isolate_shared_sections, lower_index, section_headers},
    session::{short_hash_id, AmbiguousLinePreview, AmbiguousSlotItem, OverlapPolicy, SlotFixSession},
    statement::parse_slot_statement,
};

/// Deterministic verdict for one component scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentState {
    /// Deterministically resolved to epoch `base_rev`.
    DeterminedEpoch(u32),
    /// Ambiguous with multiple candidate epochs having non-equivalent outcomes.
    Ambiguous { candidate_epochs: Vec<u32> },
    /// Conflicting slots from disjoint revisions in the same section.
    MixedEpochConflict,
}

impl Default for ComponentState {
    fn default() -> Self {
        Self::DeterminedEpoch(0)
    }
}

impl ComponentState {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::DeterminedEpoch(_) => "epoch_determined",
            Self::Ambiguous { .. } => "undecidable_overlap",
            Self::MixedEpochConflict => "mixed_epoch_conflict",
        }
    }
}

/// Aggregate result of one `apply_to_document` call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SlotFixOutcome {
    pub modified: bool,
    /// Statements whose slot identifier actually moved.
    pub shifted: usize,
    /// Statements whose slot stayed identical and only an anchor was written.
    pub pinned: usize,
    /// Anchored statements recomputed from `orig` because `rev` changed.
    pub upgraded: usize,
    pub ambiguous: usize,
}

/// One statement rewrite, plus the anchor line that must precede it.
#[derive(Debug, Clone)]
pub struct PlannedWrite {
    pub sec_idx: usize,
    /// Index of the statement line inside `sec.lines`.
    pub line_idx: usize,
    /// Index of the existing anchor line to replace, when `line_idx - 1` already
    /// carries an anchor of this rule (avoids stacking anchors).
    pub anchor_idx: Option<usize>,
    pub new_line: String,
    pub new_anchor_line: String,
    /// `true` when the slot identifier actually changed (otherwise it was pinned).
    pub moved: bool,
}

/// Applies all planned writes, rebuilding each affected section line by line so
/// that inserted anchor lines can never invalidate a planned index.
pub fn apply_planned_writes(ini: &mut IniCstDocument, writes: &[PlannedWrite]) -> usize {
    let mut by_section: HashMap<usize, Vec<&PlannedWrite>> = HashMap::new();
    for write in writes {
        by_section.entry(write.sec_idx).or_default().push(write);
    }

    let mut applied = 0usize;
    for (sec_idx, list) in by_section {
        let Some(sec) = ini.sections.get_mut(sec_idx) else {
            continue;
        };

        let mut per_line: HashMap<usize, &PlannedWrite> = HashMap::new();
        let mut replaced_anchor: HashSet<usize> = HashSet::new();
        for write in list {
            per_line.insert(write.line_idx, write);
            if let Some(anchor_idx) = write.anchor_idx {
                replaced_anchor.insert(anchor_idx);
            }
        }

        let mut rebuilt: Vec<String> = Vec::with_capacity(sec.lines.len() + per_line.len());
        let mut changed = false;
        for (idx, line) in sec.lines.iter().enumerate() {
            if replaced_anchor.contains(&idx) {
                changed = true;
                continue;
            }
            match per_line.get(&idx) {
                Some(write) => {
                    rebuilt.push(write.new_anchor_line.clone());
                    rebuilt.push(write.new_line.clone());
                    changed = true;
                }
                None => rebuilt.push(line.clone()),
            }
        }
        // Only claim a mutation when the rebuilt body really differs: a planned
        // write that happens to be byte identical must not count as a change,
        // otherwise the caller would rewrite (and back up) an unchanged file.
        if changed && rebuilt != sec.lines {
            sec.lines = rebuilt;
            applied += per_line.len();
        }
    }
    applied
}

/// Applies the slot-fix rule to one document, in place.
///
/// `co_mutated_sections` carries the sections whose `vb0` hash was rewritten
/// earlier in this same session (pipeline Step 1) — the Level 2 short-circuit.
pub fn apply_to_document(
    ini: &mut IniCstDocument,
    rule: &CompiledSlotRule,
    config: &CharacterConfig,
    co_mutated_sections: &HashSet<String>,
    ini_path: &Path,
    session: &SlotFixSession,
) -> SlotFixOutcome {
    apply_to_document_filtered(ini, rule, config, co_mutated_sections, ini_path, session, None)
}

/// Same as [`apply_to_document`] but only touches the component owning
/// `only_section` and forces its state — used by phase 2.
pub fn apply_to_document_filtered(
    ini: &mut IniCstDocument,
    rule: &CompiledSlotRule,
    config: &CharacterConfig,
    co_mutated_sections: &HashSet<String>,
    ini_path: &Path,
    session: &SlotFixSession,
    forced: Option<(&str, ComponentState)>,
) -> SlotFixOutcome {
    let mut outcome = SlotFixOutcome::default();

    let mut roots = find_roots(ini, rule);
    if let Some((only_section, _)) = forced {
        let index = lower_index(ini);
        let target = only_section.to_ascii_lowercase();
        let keep: Vec<usize> = roots
            .iter()
            .copied()
            .filter(|root| {
                let scope = compute_scope(ini, &index, *root);
                ini.sections[*root].name.eq_ignore_ascii_case(only_section)
                    || scope
                        .iter()
                        .any(|idx| ini.sections[*idx].name.to_ascii_lowercase() == target)
            })
            .collect();
        roots = keep;
    }
    if roots.is_empty() {
        return outcome;
    }

    // Remember root names: cloning shared sub-sections inserts new sections and
    // invalidates every index after the insertion point.
    let root_names: Vec<String> = roots
        .iter()
        .filter_map(|idx| ini.sections.get(*idx).map(|sec| sec.name.clone()))
        .collect();

    // ── Shared sub-section protection ───────────────────────────────────────
    {
        let index = lower_index(ini);
        let scope_of: HashMap<usize, Vec<usize>> = roots
            .iter()
            .map(|root| (*root, compute_scope(ini, &index, *root)))
            .collect();
        if isolate_shared_sections(ini, &roots, &scope_of, rule) {
            outcome.modified = true;
        }
    }

    let roots: Vec<usize> = root_names
        .iter()
        .filter_map(|name| ini.sections.iter().position(|sec| sec.name.eq_ignore_ascii_case(name)))
        .collect();
    let index = lower_index(ini);
    let co_mutated_lower: HashSet<String> = co_mutated_sections
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();

    for root_idx in roots {
        let Some(root_name) = ini.sections.get(root_idx).map(|sec| sec.name.clone()) else {
            continue;
        };
        let scope = compute_scope(ini, &index, root_idx);
        let component = analyze_component(
            ini,
            &scope,
            rule,
            config,
            &co_mutated_lower,
            ini_path,
            &root_name,
            session,
            forced.as_ref().map(|(s, st)| (*s, st)),
        );

        match component.state {
            ComponentState::Ambiguous { .. } | ComponentState::MixedEpochConflict => {
                outcome.ambiguous += 1;
                if let Some(item) = component.ambiguous_item {
                    session.push_ambiguous(item);
                }
            }
            ComponentState::DeterminedEpoch(_) => {
                if !component.writes.is_empty() {
                    let applied = apply_planned_writes(ini, &component.writes);
                    if applied > 0 {
                        outcome.modified = true;
                        for write in &component.writes {
                            if write.moved {
                                outcome.shifted += 1;
                            } else if write.anchor_idx.is_none() {
                                outcome.pinned += 1;
                            }
                        }
                    }
                }
                outcome.upgraded += component.upgraded_count;
            }
        }

        for event in component.events {
            session.emit(event);
        }
    }

    outcome
}

#[derive(Default)]
pub struct ComponentAnalysis {
    pub state: ComponentState,
    pub writes: Vec<PlannedWrite>,
    pub events: Vec<SlotFixEvent>,
    pub ambiguous_item: Option<AmbiguousSlotItem>,
    pub upgraded_count: usize,
}

/// One unanchored statement collected for the Levels 2..5 funnel.
pub struct Unmarked {
    pub sec_idx: usize,
    pub line_idx: usize,
    pub anchor_idx: Option<usize>,
    pub slot: String,
    pub line_number: usize,
    pub raw_code: String,
}

#[allow(clippy::too_many_arguments)]
pub fn analyze_component(
    ini: &IniCstDocument,
    scope: &[usize],
    rule: &CompiledSlotRule,
    config: &CharacterConfig,
    co_mutated_lower: &HashSet<String>,
    ini_path: &Path,
    root_name: &str,
    session: &SlotFixSession,
    forced: Option<(&str, &ComponentState)>,
) -> ComponentAnalysis {
    let headers = section_headers(ini);
    let rel = session.rel_path(ini_path);
    let mod_folder = {
        let folder = SlotFixSession::mod_folder_of(&rel);
        if folder.is_empty() {
            // The .ini sits directly in the selected root: fall back to its own
            // directory name so the GUI drawer can still group it by mod package.
            ini_path
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default()
        } else {
            folder
        }
    };

    // ── Level 1: the standalone anchor on the preceding line ───────────────
    let mut writes: Vec<PlannedWrite> = Vec::new();
    let mut changes: Vec<SlotFixChange> = Vec::new();
    let mut unmarked: Vec<Unmarked> = Vec::new();
    let mut unmarked_slots: BTreeSet<String> = BTreeSet::new();
    let mut upgraded_count = 0usize;

    for &sec_idx in scope {
        let Some(sec) = ini.sections.get(sec_idx) else {
            continue;
        };
        for (line_idx, raw_line) in sec.lines.iter().enumerate() {
            let Some(stmt) = parse_slot_statement(raw_line) else {
                continue;
            };
            let line_number = headers.get(sec_idx).copied().unwrap_or(0) + 1 + line_idx;

            // The anchor for this statement lives on the line immediately above.
            let prev_idx = line_idx.checked_sub(1);
            let own_anchor = prev_idx.and_then(|idx| {
                let parsed = sec.lines.get(idx).and_then(|line| parse_wmf_anchor_line(line))?;
                if parsed.rule_id == rule.rule_id {
                    Some((idx, parsed))
                } else {
                    None
                }
            });

            let Some((anchor_idx, anchor)) = own_anchor else {
                if rule.is_affected(&stmt.slot) {
                    unmarked.push(Unmarked {
                        sec_idx,
                        line_idx,
                        anchor_idx: None,
                        slot: stmt.slot.clone(),
                        line_number,
                        raw_code: raw_line.trim().to_string(),
                    });
                    unmarked_slots.insert(stmt.slot.clone());
                }
                continue;
            };

            // A user edit invalidates the anchor: demote to "unmarked".
            if anchor.sig != compute_stmt_sig(raw_line) {
                if rule.is_affected(&stmt.slot) {
                    unmarked.push(Unmarked {
                        sec_idx,
                        line_idx,
                        anchor_idx: Some(anchor_idx),
                        slot: stmt.slot.clone(),
                        line_number,
                        raw_code: raw_line.trim().to_string(),
                    });
                    unmarked_slots.insert(stmt.slot.clone());
                }
                continue;
            }
            if anchor.rev == rule.latest_rev {
                // UpToDate: byte-identical, never touched.
                continue;
            }

            // NeedsRevUpgrade: ignore current slot, recompute from orig at base_rev.
            let target = rule
                .closures
                .get(&anchor.base_rev)
                .and_then(|m| m.get(&anchor.orig_slot))
                .cloned()
                .unwrap_or_else(|| stmt.slot.clone());
            let new_line = if target != stmt.slot {
                stmt.rewrite(raw_line, &target)
            } else {
                raw_line.clone()
            };
            let new_anchor_line = format_wmf_anchor_line(
                indent_of(raw_line),
                &WmfAnchor {
                    rule_id: rule.rule_id.clone(),
                    rev: rule.latest_rev,
                    base_rev: anchor.base_rev,
                    orig_slot: anchor.orig_slot.clone(),
                    sig: compute_stmt_sig(&new_line),
                },
            );
            if new_line != *raw_line || new_anchor_line != sec.lines[anchor_idx] {
                upgraded_count += 1;
                changes.push(SlotFixChange {
                    line: line_number,
                    from: stmt.slot.clone(),
                    to: target.clone(),
                    orig: anchor.orig_slot.clone(),
                });
                writes.push(PlannedWrite {
                    sec_idx,
                    line_idx,
                    anchor_idx: Some(anchor_idx),
                    new_line,
                    new_anchor_line,
                    moved: target != stmt.slot,
                });
            }
        }
    }

    if unmarked.is_empty() {
        let mut analysis = ComponentAnalysis {
            state: ComponentState::DeterminedEpoch(rule.latest_rev),
            writes: Vec::new(),
            events: Vec::new(),
            ambiguous_item: None,
            upgraded_count,
        };
        if !writes.is_empty() {
            analysis.writes = writes;
            analysis.events.push(SlotFixEvent {
                status: if analysis.writes.iter().any(|w| w.moved) {
                    SlotFixStatus::Applied
                } else {
                    SlotFixStatus::PinnedExisting
                },
                character: Some(rule.character.clone()),
                item_id: None,
                mod_folder: Some(mod_folder),
                file: rel,
                section: Some(root_name.to_string()),
                rule_id: rule.rule_id.clone(),
                rev: rule.latest_rev,
                reason: Some("anchor_rev_upgrade".to_string()),
                changes,
                overlap_slots: Vec::new(),
                lines: Vec::new(),
            });
        }
        return analysis;
    }

    // ── Levels 2..5: decide the component state ────────────────────────────
    let has_co_mutation = co_mutated_lower.contains(&root_name.to_ascii_lowercase())
        || scope
            .iter()
            .filter_map(|idx| ini.sections.get(*idx))
            .any(|sec| co_mutated_lower.contains(&sec.name.to_ascii_lowercase()));

    let reason: String;
    let state = if let Some((_, forced_state)) = forced {
        reason = "phase2_forced_decision".to_string();
        (*forced_state).clone()
    } else {
        // Compute intersection of valid_epochs for all unmarked tracked slots
        let mut candidate_set: Option<BTreeSet<u32>> = None;
        for slot in &unmarked_slots {
            let epochs = rule.valid_epochs.get(slot).cloned().unwrap_or_default();
            let set: BTreeSet<u32> = epochs.into_iter().collect();
            match &mut candidate_set {
                None => candidate_set = Some(set),
                Some(c) => *c = c.intersection(&set).copied().collect(),
            }
        }
        let candidate_epochs: Vec<u32> = candidate_set.map(|s| s.into_iter().collect()).unwrap_or_default();

        if candidate_epochs.is_empty() {
            // MixedEpochConflict: conflicting slots from disjoint revisions in the same section.
            reason = "mixed_epoch_conflict".to_string();
            ComponentState::MixedEpochConflict
        } else if candidate_epochs.len() == 1 {
            let ep = candidate_epochs[0];
            reason = ComponentState::DeterminedEpoch(ep).reason().to_string();
            ComponentState::DeterminedEpoch(ep)
        } else {
            // candidate_epochs.len() > 1: check outcome equivalence
            let target_for = |ep: u32, slot: &str| -> String {
                rule.closures
                    .get(&ep)
                    .and_then(|m| m.get(slot))
                    .cloned()
                    .unwrap_or_else(|| slot.to_string())
            };
            let outcome_equivalent = unmarked_slots.iter().all(|slot| {
                let first_target = target_for(candidate_epochs[0], slot);
                candidate_epochs.iter().skip(1).all(|&ep| target_for(ep, slot) == first_target)
            });

            if outcome_equivalent {
                let highest_ep = *candidate_epochs.last().unwrap();
                reason = "outcome_equivalent_resolved".to_string();
                ComponentState::DeterminedEpoch(highest_ep)
            } else if has_co_mutation {
                reason = "co_mutated_component".to_string();
                ComponentState::DeterminedEpoch(0)
            } else if let Some(lineage) = lineage_state(ini_path, root_name, rule, config, &unmarked_slots) {
                reason = match lineage {
                    ComponentState::DeterminedEpoch(ep) if ep > 0 => "backup_lineage_shifted",
                    _ => "backup_lineage_unshifted",
                }
                .to_string();
                lineage
            } else {
                match session.policy {
                    OverlapPolicy::Ask => {
                        reason = "undecidable_overlap".to_string();
                        ComponentState::Ambiguous {
                            candidate_epochs: candidate_epochs.clone(),
                        }
                    }
                    OverlapPolicy::ShiftAll => {
                        reason = "policy_shift_all".to_string();
                        let lowest_ep = *candidate_epochs.first().unwrap_or(&0);
                        ComponentState::DeterminedEpoch(lowest_ep)
                    }
                    OverlapPolicy::KeepAllAndPin => {
                        reason = "policy_keep_all_and_pin".to_string();
                        let highest_ep = *candidate_epochs.last().unwrap_or(&rule.latest_rev);
                        ComponentState::DeterminedEpoch(highest_ep)
                    }
                    OverlapPolicy::SkipAll => {
                        reason = "policy_skip_all".to_string();
                        ComponentState::Ambiguous {
                            candidate_epochs: candidate_epochs.clone(),
                        }
                    }
                }
            }
        }
    };

    // SkipAll leaves ambiguous components completely untouched (no shift, no anchor).
    let effectively_skipped = session.policy == OverlapPolicy::SkipAll && forced.is_none();

    match state {
        ComponentState::Ambiguous { ref candidate_epochs } => {
            let mut previews = Vec::new();
            for u in &unmarked {
                let current = u.slot.clone();
                let min_ep = candidate_epochs.first().copied().unwrap_or(0);
                let if_shifted = rule.closures
                    .get(&min_ep)
                    .and_then(|m| m.get(&current))
                    .cloned()
                    .unwrap_or_else(|| current.clone());
                let if_kept = rule
                    .closures
                    .get(&0)
                    .and_then(|m| m.iter().find(|(_, v)| *v == &current).map(|(k, _)| k.clone()))
                    .unwrap_or_else(|| current.clone());

                let mut epoch_targets = HashMap::new();
                for &ep in candidate_epochs {
                    let tgt = rule.closures
                        .get(&ep)
                        .and_then(|m| m.get(&current))
                        .cloned()
                        .unwrap_or_else(|| current.clone());
                    epoch_targets.insert(ep, tgt);
                }

                previews.push(AmbiguousLinePreview {
                    line_number: u.line_number,
                    raw_code: u.raw_code.clone(),
                    current_slot: current,
                    if_shifted_slot: if_shifted,
                    if_kept_orig_slot: if_kept,
                    epoch_targets,
                });
            }
            let item = AmbiguousSlotItem {
                item_id: short_hash_id(&rel, root_name, &rule.rule_id),
                mod_folder_name: mod_folder.clone(),
                rel_ini_path: rel.clone(),
                abs_ini_path: ini_path.to_string_lossy().to_string(),
                section_name: root_name.to_string(),
                rule_id: rule.rule_id.clone(),
                character: rule.character.clone(),
                rev: rule.latest_rev,
                affected_lines: previews.clone(),
                candidate_epochs: candidate_epochs.clone(),
                conflict_reason: None,
            };
            let mut events = Vec::new();
            if !effectively_skipped {
                events.push(SlotFixEvent {
                    status: SlotFixStatus::AmbiguousPending,
                    character: Some(rule.character.clone()),
                    item_id: Some(item.item_id.clone()),
                    mod_folder: Some(mod_folder),
                    file: rel,
                    section: Some(root_name.to_string()),
                    rule_id: rule.rule_id.clone(),
                    rev: rule.latest_rev,
                    reason: Some(reason),
                    changes,
                    overlap_slots: unmarked_slots.iter().cloned().collect(),
                    lines: previews,
                });
            }
            ComponentAnalysis {
                state,
                writes: Vec::new(),
                events,
                ambiguous_item: if effectively_skipped { None } else { Some(item) },
                upgraded_count,
            }
        }
        ComponentState::MixedEpochConflict => {
            let conflict_msg = "Mixed epoch conflict: statements within this section belong to disjoint revisions".to_string();
            let mut previews = Vec::new();
            for u in &unmarked {
                previews.push(AmbiguousLinePreview {
                    line_number: u.line_number,
                    raw_code: u.raw_code.clone(),
                    current_slot: u.slot.clone(),
                    if_shifted_slot: format!("conflict ({})", u.slot),
                    if_kept_orig_slot: u.slot.clone(),
                    epoch_targets: HashMap::new(),
                });
            }
            let item = AmbiguousSlotItem {
                item_id: short_hash_id(&rel, root_name, &rule.rule_id),
                mod_folder_name: mod_folder.clone(),
                rel_ini_path: rel.clone(),
                abs_ini_path: ini_path.to_string_lossy().to_string(),
                section_name: root_name.to_string(),
                rule_id: rule.rule_id.clone(),
                character: rule.character.clone(),
                rev: rule.latest_rev,
                affected_lines: previews.clone(),
                candidate_epochs: Vec::new(),
                conflict_reason: Some(conflict_msg),
            };
            let mut events = Vec::new();
            if !effectively_skipped {
                events.push(SlotFixEvent {
                    status: SlotFixStatus::MixedEpochConflict,
                    character: Some(rule.character.clone()),
                    item_id: Some(item.item_id.clone()),
                    mod_folder: Some(mod_folder),
                    file: rel,
                    section: Some(root_name.to_string()),
                    rule_id: rule.rule_id.clone(),
                    rev: rule.latest_rev,
                    reason: Some("mixed_epoch_conflict".to_string()),
                    changes,
                    overlap_slots: unmarked_slots.iter().cloned().collect(),
                    lines: previews,
                });
            }
            ComponentAnalysis {
                state: ComponentState::MixedEpochConflict,
                writes: Vec::new(),
                events,
                ambiguous_item: if effectively_skipped { None } else { Some(item) },
                upgraded_count,
            }
        }
        ComponentState::DeterminedEpoch(ep) => {
            let mut shifted = 0usize;
            for u in &unmarked {
                let new_slot = rule.closures
                    .get(&ep)
                    .and_then(|m| m.get(&u.slot))
                    .cloned()
                    .unwrap_or_else(|| u.slot.clone());
                let orig_slot = u.slot.clone();

                let sec = &ini.sections[u.sec_idx];
                let raw_line = &sec.lines[u.line_idx];
                let Some(stmt) = parse_slot_statement(raw_line) else {
                    continue;
                };
                let new_line = if new_slot != stmt.slot {
                    stmt.rewrite(raw_line, &new_slot)
                } else {
                    raw_line.clone()
                };
                let new_anchor_line = format_wmf_anchor_line(
                    indent_of(raw_line),
                    &WmfAnchor {
                        rule_id: rule.rule_id.clone(),
                        rev: rule.latest_rev,
                        base_rev: ep,
                        orig_slot: orig_slot.clone(),
                        sig: compute_stmt_sig(&new_line),
                    },
                );

                let moved = new_slot != stmt.slot;
                if moved {
                    shifted += 1;
                }
                changes.push(SlotFixChange {
                    line: u.line_number,
                    from: stmt.slot.clone(),
                    to: new_slot.clone(),
                    orig: orig_slot.clone(),
                });
                writes.push(PlannedWrite {
                    sec_idx: u.sec_idx,
                    line_idx: u.line_idx,
                    anchor_idx: u.anchor_idx,
                    new_line,
                    new_anchor_line,
                    moved,
                });
            }

            let mut events = Vec::new();
            if !writes.is_empty() {
                events.push(SlotFixEvent {
                    status: if shifted > 0 {
                        SlotFixStatus::Applied
                    } else {
                        SlotFixStatus::PinnedExisting
                    },
                    character: Some(rule.character.clone()),
                    item_id: None,
                    mod_folder: Some(mod_folder),
                    file: rel,
                    section: Some(root_name.to_string()),
                    rule_id: rule.rule_id.clone(),
                    rev: rule.latest_rev,
                    reason: Some(reason),
                    changes,
                    overlap_slots: Vec::new(),
                    lines: Vec::new(),
                });
            }
            ComponentAnalysis {
                state: ComponentState::DeterminedEpoch(ep),
                writes,
                events,
                ambiguous_item: None,
                upgraded_count,
            }
        }
    }
}
