// src-core/src/fixers/derive_redirect.rs

use std::collections::{HashMap, HashSet};

use crate::{
    config_loader::CharacterConfig,
    domain::{
        cst::{IniCstDocument, IniCstSection},
        pipeline::{PipelineFixer, PipelineStage},
        sections::TextureOverrideSectionView,
    },
    errors::FixerError,
    fixers::traits::FixerContext,
};

pub struct DeriveRedirectFixer;

impl PipelineFixer for DeriveRedirectFixer {
    fn name(&self) -> &'static str {
        "DeriveRedirectFixer"
    }

    fn stage(&self) -> PipelineStage {
        PipelineStage::PostProcess
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let cfg = crate::config_loader::config();
        let settings = cfg.settings_ref();

        let should_run =
            ctx.mod_ctx.enable_texture_override || settings.state_texture_removers.iter().any(|s| s == ctx.char_name);

        if should_run {
            let char_cfg = ctx.config;
            let res = Self::run_multi(ctx.ini_mut(), &[char_cfg])?;
            if res {
                ctx.mark_ini_modified();
            }
            Ok(res)
        } else {
            Ok(false)
        }
    }
}

impl DeriveRedirectFixer {
    pub fn run_multi(ini: &mut IniCstDocument, configs: &[&CharacterConfig]) -> Result<bool, FixerError> {
        let mut all_aggregated_states: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
        let mut required_hashes = HashSet::new();

        let mut present_hashes = HashSet::new();
        for sec in &ini.sections {
            if let Some(h) = sec.get_value("hash") {
                present_hashes.insert(h.trim().to_lowercase());
            }
        }

        for config in configs {
            for (base_hash, node) in &config.textures {
                if !node.derive.is_empty() {
                    let mut active_source_hash = None;
                    if present_hashes.contains(&base_hash.to_lowercase()) {
                        active_source_hash = Some(base_hash.clone());
                    } else {
                        for rep in &node.replace {
                            if present_hashes.contains(&rep.to_lowercase()) {
                                active_source_hash = Some(rep.clone());
                                break;
                            }
                        }
                    }

                    let source_hash = active_source_hash.unwrap_or_else(|| base_hash.clone());

                    for (state_name, hashes) in &node.derive {
                        let state_map = all_aggregated_states.entry(state_name.clone()).or_default();
                        let target_list = state_map.entry(source_hash.clone()).or_default();
                        for h in hashes {
                            if !target_list.contains(h) {
                                target_list.push(h.clone());
                            }
                            required_hashes.insert(h.trim().to_lowercase());
                        }
                    }
                }
            }
        }

        if all_aggregated_states.is_empty() {
            return Ok(false);
        }

        let mut modified = false;

        // Synchronize matching base sections across derived state sets.
        let known_state_suffixes: Vec<String> = all_aggregated_states
            .keys()
            .map(|s| format!("_{}", s.to_lowercase()))
            .collect();

        for (state_name, state_map) in all_aggregated_states {
            // Identify canonical base sections while excluding derived sections.
            let base_names: Vec<String> = ini
                .sections
                .iter()
                .filter(|sec| {
                    if !sec.is_texture_override() {
                        return false;
                    }
                    let sec_hash = match sec.get_value("hash") {
                        Some(h) => h.trim().to_lowercase(),
                        None => return false,
                    };
                    if !state_map.contains_key(&sec_hash) {
                        return false;
                    }
                    // Exclude secondary sections bearing derived state suffixes.
                    let sec_name_lower = sec.name.to_lowercase();
                    for suffix_tag in &known_state_suffixes {
                        if sec_name_lower.ends_with(suffix_tag) || sec_name_lower.contains(&format!("{}_", suffix_tag))
                        {
                            return false;
                        }
                    }
                    true
                })
                .map(|sec| sec.name.clone())
                .collect();

            // Process base sections in reverse order to preserve preceding index locations.
            for base_name in base_names.into_iter().rev() {
                let base_hash = {
                    match ini.get_section(&base_name).and_then(|s| s.get_value("hash")) {
                        Some(h) => h.trim().to_lowercase(),
                        None => continue,
                    }
                };

                if let Some(target_hashes) = state_map.get(&base_hash) {
                    let mut sorted_hashes = target_hashes.clone();
                    sorted_hashes.sort();
                    if Self::sync_derived_cluster(
                        ini,
                        &base_name,
                        &state_name,
                        &sorted_hashes,
                        &required_hashes,
                        &known_state_suffixes,
                    ) {
                        modified = true;
                    }
                }
            }
        }

        Ok(modified)
    }

    /// Synchronizes derived section cluster associated with target base section.
    fn sync_derived_cluster(
        ini: &mut IniCstDocument,
        base_name: &str,
        suffix: &str,
        target_hashes: &[String],
        required_hashes: &HashSet<String>,
        known_state_suffixes: &[String],
    ) -> bool {
        let base_idx = match ini.sections.iter().position(|s| s.name == base_name) {
            Some(idx) => idx,
            None => return false,
        };

        let suffix_lower = suffix.to_lowercase();
        let base_prefix_lower = format!("{}_{}", base_name.to_lowercase(), suffix_lower);

        // Extract body control flow AST from base section.
        let body_ast = {
            let base_view = TextureOverrideSectionView::new(&mut ini.sections[base_idx]);
            base_view.extract_body_ast()
        };

        let mut modified = false;

        // Check whether target hash is already covered by an independent override.
        let is_hash_covered_by_independent =
            |sections: &[IniCstSection], target_h: &str, current_d_idx: Option<usize>| -> bool {
                sections.iter().enumerate().any(|(idx, s)| {
                    if Some(idx) == current_d_idx || !s.is_texture_override() {
                        return false;
                    }
                    let s_name_lower = s.name.to_lowercase();
                    if s_name_lower == base_name.to_lowercase()
                        || s_name_lower == base_prefix_lower
                        || s_name_lower.starts_with(&format!("{}_", base_prefix_lower))
                    {
                        return false;
                    }
                    // Suffix-tagged sections do not qualify as independent overrides.
                    for suffix_tag in known_state_suffixes {
                        if s_name_lower.ends_with(suffix_tag) || s_name_lower.contains(&format!("{}_", suffix_tag)) {
                            return false;
                        }
                    }
                    s.get_value("hash")
                        .map_or(false, |sh| sh.trim().eq_ignore_ascii_case(target_h))
                })
            };

        // Prune outdated or redundantly covered derived sections.
        let derive_indices_for_base: Vec<usize> = ini
            .sections
            .iter()
            .enumerate()
            .filter(|(_, sec)| {
                let sec_name_lower = sec.name.to_lowercase();
                sec_name_lower == base_prefix_lower || sec_name_lower.starts_with(&format!("{}_", base_prefix_lower))
            })
            .map(|(i, _)| i)
            .collect();

        for &d_idx in derive_indices_for_base.iter().rev() {
            let sec = &ini.sections[d_idx];
            let sec_hash = sec.get_value("hash").map(|h| h.trim().to_lowercase());

            let is_covered = match &sec_hash {
                Some(h) => is_hash_covered_by_independent(&ini.sections, h, Some(d_idx)),
                None => false,
            };

            let is_outdated = match sec_hash {
                Some(h) => {
                    !required_hashes.contains(&h)
                        || !target_hashes.iter().any(|th| th.eq_ignore_ascii_case(&h))
                        || is_covered
                }
                None => true,
            };

            if is_outdated {
                log::info!("Removing outdated derive section: [{}] at index {}", sec.name, d_idx);
                ini.sections.remove(d_idx);
                modified = true;
            }
        }

        // Reacquire current base section index after mutations.
        let current_base_idx = match ini.sections.iter().position(|s| s.name == base_name) {
            Some(idx) => idx,
            None => return modified,
        };

        // Compute insertion cursor immediately following existing derived cluster.
        let max_derive_idx = ini
            .sections
            .iter()
            .enumerate()
            .filter(|(_, sec)| {
                let sec_name_lower = sec.name.to_lowercase();
                sec_name_lower == base_prefix_lower || sec_name_lower.starts_with(&format!("{}_", base_prefix_lower))
            })
            .map(|(i, _)| i)
            .max()
            .unwrap_or(current_base_idx);

        let mut insert_cursor = max_derive_idx + 1;

        // Generate collision-free unique section identifier.
        let allocate_unique_derive_name = |sections: &[IniCstSection], exclude_idx: Option<usize>| -> String {
            let legacy_zero = format!("{}_{}_0", base_name, suffix);
            let has_legacy_zero = sections
                .iter()
                .enumerate()
                .any(|(i, s)| Some(i) != exclude_idx && s.name.eq_ignore_ascii_case(&legacy_zero));

            let mut candidate_idx = if has_legacy_zero { 1 } else { 0 };
            loop {
                let candidate = if candidate_idx == 0 {
                    format!("{}_{}", base_name, suffix)
                } else {
                    format!("{}_{}_{}", base_name, suffix, candidate_idx)
                };

                let is_occupied = sections
                    .iter()
                    .enumerate()
                    .any(|(i, s)| Some(i) != exclude_idx && s.name.eq_ignore_ascii_case(&candidate));

                if !is_occupied {
                    return candidate;
                }
                candidate_idx += 1;
            }
        };

        // Update existing section in place or insert adjacent derived section.
        for changed_hash in target_hashes {
            let changed_hash_lower = changed_hash.trim().to_lowercase();

            let existing_pos = ini.sections.iter().position(|sec| {
                let s_name_lower = sec.name.to_lowercase();
                if s_name_lower == base_prefix_lower || s_name_lower.starts_with(&format!("{}_", base_prefix_lower)) {
                    if let Some(h) = sec.get_value("hash") {
                        return h.trim().eq_ignore_ascii_case(&changed_hash_lower);
                    }
                }
                false
            });

            if let Some(pos) = existing_pos {
                // Self-heal naming collisions from legacy modifications.
                let is_name_duplicated = ini
                    .sections
                    .iter()
                    .enumerate()
                    .any(|(i, s)| i != pos && s.name.eq_ignore_ascii_case(&ini.sections[pos].name));

                if is_name_duplicated {
                    let new_name = allocate_unique_derive_name(&ini.sections, Some(pos));
                    log::warn!(
                        "De-duplicated existing derive section [{}] by renaming to [{}]",
                        ini.sections[pos].name,
                        new_name
                    );
                    ini.sections[pos].name = new_name;
                    modified = true;
                }

                // Update in place.
                let mut view = TextureOverrideSectionView::new(&mut ini.sections[pos]);
                if view.update_override(changed_hash, "0", &body_ast) {
                    modified = true;
                    log::info!(
                        "Updated in-place derive section [{}] for hash {}",
                        view.name(),
                        changed_hash
                    );
                }
            } else {
                // Skip insertion if hash is already covered independently.
                if is_hash_covered_by_independent(&ini.sections, &changed_hash_lower, None) {
                    log::info!(
                        "Skipping derive section for hash {} on base [{}]: independent override section already present",
                        changed_hash,
                        base_name
                    );
                    continue;
                }

                // Insert derived section at computed cursor.
                let target_header_name = allocate_unique_derive_name(&ini.sections, None);

                let new_sec =
                    TextureOverrideSectionView::create_derived(&target_header_name, changed_hash, "0", &body_ast);

                log::info!(
                    "Inserting adjacent derive section: [{}] at index {} for hash {}",
                    target_header_name,
                    insert_cursor,
                    changed_hash
                );

                ini.sections.insert(insert_cursor, new_sec);
                insert_cursor += 1;
                modified = true;
            }
        }

        modified
    }
}
