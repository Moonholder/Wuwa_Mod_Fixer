// src-core/src/utils/derive_redirect.rs

use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use crate::utils::ini_parser::{IniSection, parse_line};
use log::{debug, info};
use std::collections::{HashMap, HashSet};

pub struct DeriveRedirectFixer;

impl Fixer for DeriveRedirectFixer {
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let mut all_aggregated_states = HashMap::new();

        let mut present_hashes = HashSet::new();
        for sec in &ctx.ini.sections {
            if let Some(h) = sec.get_value("hash") {
                present_hashes.insert(h.trim().to_lowercase());
            }
        }

        for (base_hash, node) in &ctx.config.textures {
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
                    let state_map = all_aggregated_states
                        .entry(state_name.clone())
                        .or_insert_with(HashMap::new);
                    for h in hashes {
                        state_map.insert(h.clone(), source_hash.clone());
                    }
                }
            }
        }

        self.run_redirection(ctx, &all_aggregated_states)
    }
}

impl DeriveRedirectFixer {
    pub fn run_redirection(
        &self,
        ctx: &mut FixerContext,
        all_aggregated_states: &HashMap<String, HashMap<String, String>>,
    ) -> Result<bool, FixerError> {
        if all_aggregated_states.is_empty() {
            return Ok(false);
        }

        let mut modified = false;
        let state_suffixes: Vec<&str> = all_aggregated_states.keys().map(|s| s.as_str()).collect();
        let required_hashes: HashSet<String> = all_aggregated_states.values().flat_map(|m| m.keys().cloned()).collect();

        let existing_hashes = self.analyze_and_remove_trailing_derive_sections(ctx, &state_suffixes, false);

        if existing_hashes.difference(&required_hashes).count() > 0 {
            debug!("Removing outdated derive sections");
            self.analyze_and_remove_trailing_derive_sections(ctx, &state_suffixes, true);
            modified = true;
        }

        for (state_name, state_map) in all_aggregated_states {
            if self.texture_override_redirection(ctx, state_map, &state_name) {
                modified = true;
            }
        }

        Ok(modified)
    }

    fn analyze_and_remove_trailing_derive_sections(
        &self,
        ctx: &mut FixerContext,
        state_suffixes: &[&str],
        should_remove: bool,
    ) -> HashSet<String> {
        let mut existing_hashes = HashSet::new();
        let mut sections_to_remove = HashSet::new();

        for (idx, section) in ctx.ini.sections.iter().enumerate().rev() {
            let sec_name_lower = section.name.to_lowercase();
            let is_derive_header = sec_name_lower.starts_with("textureoverride")
                && state_suffixes
                    .iter()
                    .any(|suffix| sec_name_lower.contains(&format!("_{}", suffix.to_lowercase())));

            if !is_derive_header {
                continue;
            }

            let has_match_priority = section
                .get_value("match_priority")
                .map_or(false, |val| val.trim() == "0");
            let section_hash = section.get_value("hash");

            if has_match_priority {
                sections_to_remove.insert(idx);
                if let Some(h) = section_hash {
                    existing_hashes.insert(h);
                }
                if should_remove {
                    info!("Removing outdated derive section: [{}]", section.name);
                }
            }
        }

        if should_remove && !sections_to_remove.is_empty() {
            let mut current_idx = 0;
            ctx.ini.sections.retain(|_| {
                let keep = !sections_to_remove.contains(&current_idx);
                current_idx += 1;
                keep
            });
            info!("Removed outdated derive sections from end of file");
        }

        existing_hashes
    }

    fn texture_override_redirection(
        &self,
        ctx: &mut FixerContext,
        tex_override_map: &HashMap<String, String>,
        header_suffix: &str,
    ) -> bool {
        let mut new_fix_sections = Vec::new();

        let mut existing_headers_lower: HashSet<String> =
            ctx.ini.sections.iter().map(|s| s.name.to_lowercase()).collect();

        let mut present_hashes_lower: HashSet<String> = HashSet::new();
        for sec in &ctx.ini.sections {
            if let Some(h) = sec.get_value("hash") {
                present_hashes_lower.insert(h.trim().to_lowercase());
            }
        }

        let mut grouped_map: HashMap<&String, Vec<&String>> = HashMap::new();
        for (changed_hash, original_hash) in tex_override_map {
            grouped_map.entry(original_hash).or_default().push(changed_hash);
        }

        for (original_hash, changed_hashes) in grouped_map {
            let mut needed_hashes: Vec<&String> = changed_hashes
                .iter()
                .filter(|&&h| !present_hashes_lower.contains(&h.trim().to_lowercase()))
                .cloned()
                .collect();
            needed_hashes.sort();

            if needed_hashes.is_empty() {
                continue;
            }

            if let Some((base_header, content_lines)) = self.get_texture_override_content(ctx, original_hash) {
                for changed_hash in needed_hashes {
                    let mut candidate_header = format!("{}_{}", base_header, header_suffix);
                    let mut counter = 0;

                    while existing_headers_lower.contains(&candidate_header.to_lowercase()) {
                        candidate_header = format!("{}_{}_{}", base_header, header_suffix, counter);
                        counter += 1;
                    }

                    existing_headers_lower.insert(candidate_header.to_lowercase());
                    present_hashes_lower.insert(changed_hash.trim().to_lowercase());

                    info!("Generating section: [{}] for hash {}", candidate_header, changed_hash);

                    let mut new_sec = IniSection::new(&candidate_header);
                    new_sec.lines.push(format!("hash = {}", changed_hash));
                    new_sec.lines.push("match_priority = 0".to_string());
                    new_sec.lines.extend(content_lines.clone());
                    new_fix_sections.push(new_sec);
                }
            }
        }

        if new_fix_sections.is_empty() {
            return false;
        }

        ctx.ini.sections.extend(new_fix_sections);
        true
    }

    fn get_texture_override_content(&self, ctx: &FixerContext, original_hash: &str) -> Option<(String, Vec<String>)> {
        for sec in &ctx.ini.sections {
            let sec_name_lower = sec.name.to_lowercase();
            if sec_name_lower.starts_with("textureoverride")
                && !sec_name_lower.starts_with("textureoverridecomponent")
                && !sec_name_lower.starts_with("textureoverrideshapekey")
            {
                if let Some(h) = sec.get_value("hash") {
                    if h.eq_ignore_ascii_case(original_hash) {
                        let mut filtered_lines = Vec::new();
                        for line in &sec.lines {
                            let (k, _, _) = parse_line(line);
                            if let Some(key_str) = k {
                                let key_lower = key_str.to_lowercase();
                                if key_lower == "hash" || key_lower == "match_priority" {
                                    continue;
                                }
                            }
                            if line.trim().starts_with(';') {
                                continue;
                            }
                            filtered_lines.push(line.clone());
                        }
                        return Some((sec.name.clone(), filtered_lines));
                    }
                }
            }
        }
        None
    }
}
