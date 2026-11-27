// src-core/src/slot_fix/scope.rs

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::{
    config_loader::CompiledSlotRule,
    domain::cst::{IniCstDocument, IniCstSection},
    utils::ini_parser::parse_line_ref,
};

use super::statement::parse_slot_statement;

pub fn lower_index(ini: &IniCstDocument) -> HashMap<String, usize> {
    ini.sections
        .iter()
        .enumerate()
        .map(|(idx, sec)| (sec.name.to_ascii_lowercase(), idx))
        .collect()
}

/// All `run = <section>` targets of a section (case preserved).
pub fn collect_run_targets(sec: &IniCstSection) -> Vec<String> {
    let mut out = Vec::new();
    for line in &sec.lines {
        let (k, v, _) = parse_line_ref(line);
        if let (Some(k), Some(v)) = (k, v) {
            if k.eq_ignore_ascii_case("run") {
                let target = v.trim().trim_matches('"');
                if !target.is_empty() {
                    out.push(target.to_string());
                }
            }
        }
    }
    out
}

/// Breadth-first collection of every section reachable from `root_idx`.
pub fn compute_scope(ini: &IniCstDocument, index: &HashMap<String, usize>, root_idx: usize) -> Vec<usize> {
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut queue: Vec<usize> = vec![root_idx];
    visited.insert(root_idx);

    while let Some(idx) = queue.pop() {
        for target in collect_run_targets(&ini.sections[idx]) {
            if let Some(&child) = index.get(&target.to_ascii_lowercase()) {
                if visited.insert(child) {
                    queue.push(child);
                }
            }
        }
    }
    visited.into_iter().collect()
}

/// Finds the component entry roots (`[TextureOverride*]` with a matching hash).
pub fn find_roots(ini: &IniCstDocument, rule: &CompiledSlotRule) -> Vec<usize> {
    let hashes = rule.hash_set();
    let mfi: HashSet<String> = rule.match_first_index.iter().map(|s| s.trim().to_string()).collect();
    ini.sections
        .iter()
        .enumerate()
        .filter(|(_, sec)| {
            let lower = sec.name.to_ascii_lowercase();
            if !lower.starts_with("textureoverride") {
                return false;
            }
            if let Some(h) = sec.get_value_ref("hash") {
                if hashes.contains(&h.trim().to_ascii_lowercase()) {
                    return true;
                }
            }
            if !mfi.is_empty() {
                if let Some(v) = sec.get_value_ref("match_first_index") {
                    if mfi.contains(v.trim()) {
                        return true;
                    }
                }
            }
            false
        })
        .map(|(idx, _)| idx)
        .collect()
}

/// Every hash-bearing `[TextureOverride*]` section (used for pollution analysis).
pub fn find_all_hash_roots(ini: &IniCstDocument) -> Vec<usize> {
    ini.sections
        .iter()
        .enumerate()
        .filter(|(_, sec)| {
            let lower = sec.name.to_ascii_lowercase();
            lower.starts_with("textureoverride") && sec.get_value_ref("hash").is_some()
        })
        .map(|(idx, _)| idx)
        .collect()
}

/// True when a section holds at least one statement this engine could rewrite.
///
/// Used to decide whether a shared sub-section actually needs to be cloned:
/// override-trigger lists (`checktextureoverride`) and pure `run` dispatchers
/// carry nothing to shift, so they are never cloned.
pub fn section_has_shiftable_statement(sec: &IniCstSection, rule: &CompiledSlotRule) -> bool {
    sec.lines.iter().any(|line| {
        parse_slot_statement(line)
            .map(|stmt| rule.is_affected(&stmt.slot))
            .unwrap_or(false)
    })
}

/// Rewrites `run = <shared>` into `run = <shared>_<suffix>` inside one section.
pub fn redirect_run_targets(sec: &mut IniCstSection, map: &HashMap<String, String>) -> bool {
    let mut modified = false;
    for line in sec.lines.iter_mut() {
        let (k, v, _) = parse_line_ref(line);
        let (Some(k), Some(v)) = (k, v) else { continue };
        if !k.eq_ignore_ascii_case("run") {
            continue;
        }
        let target = v.trim().trim_matches('"');
        let Some(new_name) = map.get(&target.to_ascii_lowercase()) else {
            continue;
        };
        let Some(eq_pos) = line.find('=') else { continue };
        let after = &line[eq_pos + 1..];
        let Some(rel_start) = after.find(target) else { continue };
        let abs_start = eq_pos + 1 + rel_start;
        let abs_end = abs_start + target.len();
        *line = format!("{}{}{}", &line[..abs_start], new_name, &line[abs_end..]);
        modified = true;
    }
    modified
}

/// Shares one generic sub-section between several characters?
///
/// Clones every `Hiyuki`-scoped section that (a) is also reachable from a
/// *foreign* component root and (b) actually contains statements this engine
/// would rewrite, then repoints the `run` statements. Sections without any
/// shiftable statement — notably `[CommandListTriggerResourceOverrides]` — are
/// left untouched and never cloned.
pub fn isolate_shared_sections(
    ini: &mut IniCstDocument,
    hi_roots: &[usize],
    scope_of: &HashMap<usize, Vec<usize>>,
    rule: &CompiledSlotRule,
) -> bool {
    if hi_roots.is_empty() {
        return false;
    }
    let index = lower_index(ini);
    let all_roots = find_all_hash_roots(ini);
    let hi_root_set: HashSet<usize> = hi_roots.iter().copied().collect();

    let mut hi_scope: HashSet<usize> = HashSet::new();
    for root in hi_roots {
        if let Some(scope) = scope_of.get(root) {
            hi_scope.extend(scope.iter().copied());
        }
    }

    // Capture the scope names before inserting clones, otherwise every index
    // after an insertion point is stale.
    let mut scope_names: HashSet<String> = hi_scope
        .iter()
        .filter_map(|idx| ini.sections.get(*idx))
        .map(|sec| sec.name.to_ascii_lowercase())
        .collect();

    let mut polluted: HashSet<usize> = HashSet::new();
    for root in all_roots {
        if hi_root_set.contains(&root) {
            continue;
        }
        polluted.extend(compute_scope(ini, &index, root));
    }

    let to_clone: Vec<usize> = hi_scope
        .iter()
        .copied()
        .filter(|idx| !hi_root_set.contains(idx) && polluted.contains(idx))
        .filter(|idx| {
            ini.sections
                .get(*idx)
                .map(|sec| section_has_shiftable_statement(sec, rule))
                .unwrap_or(false)
        })
        .collect();
    if to_clone.is_empty() {
        return false;
    }

    let suffix = format!("_{}", rule.rule_id);
    let mut rename: HashMap<String, String> = HashMap::new();
    let mut clones: Vec<(usize, IniCstSection)> = Vec::new();
    for idx in &to_clone {
        let original = &ini.sections[*idx];
        let new_name = format!("{}{}", original.name, suffix);
        if index.contains_key(&new_name.to_ascii_lowercase()) {
            continue;
        }
        rename.insert(original.name.to_ascii_lowercase(), new_name.clone());
        let mut clone = original.clone();
        clone.name = new_name;
        clones.push((*idx, clone));
    }
    if rename.is_empty() {
        return false;
    }

    // Insert adjacent to the original, highest index first so earlier indices stay valid.
    clones.sort_by_key(|(idx, _)| std::cmp::Reverse(*idx));
    for (idx, clone) in clones {
        ini.sections.insert(idx + 1, clone);
    }
    for clone_name in rename.values() {
        scope_names.insert(clone_name.to_ascii_lowercase());
    }

    // Repoint every `run` inside the (new) Hiyuki scope, including the clones.
    let mut modified = false;
    for sec in ini.sections.iter_mut() {
        if scope_names.contains(&sec.name.to_ascii_lowercase()) && redirect_run_targets(sec, &rename) {
            modified = true;
        }
    }
    modified
}

/// 1-based absolute line number of every section header.
pub fn section_headers(ini: &IniCstDocument) -> Vec<usize> {
    let mut headers = Vec::with_capacity(ini.sections.len());
    let mut cursor = ini.pre_lines.len() + 1;
    for sec in &ini.sections {
        cursor += sec.leading_lines.len();
        headers.push(cursor);
        cursor += 1 + sec.lines.len();
    }
    headers
}
