// src-core/src/fixers/materialmap.rs

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use log::{info, warn};

use crate::{
    config_loader::MaterialmapAdaptRule,
    domain::cst::{IniCstDocument, IniCstSection},
    errors::FixerError,
    fixers::traits::FixerContext,
    utils::dds_helper::MaterialmapMode,
};

pub struct MaterialmapFixer;

impl MaterialmapFixer {
    /// Resolve source Lightmap hash for the target component.
    fn resolve_source_lightmap(
        config: &crate::config_loader::CharacterConfig,
        rule: &MaterialmapAdaptRule,
    ) -> Option<String> {
        if let Some(h) = &rule.source_lightmap_hash {
            Some(h.clone())
        } else {
            config.textures.iter().find_map(|(h, node)| {
                node.meta.as_ref().and_then(|m| {
                    if m.type_ == "L" && m.id.iter().any(|id| *id == rule.component_id as u32) {
                        Some(h.clone())
                    } else {
                        None
                    }
                })
            })
        }
    }

    /// Check whether the mod or document already has an override for the target material hash.
    fn is_already_adapted(ini: &IniCstDocument, original_hashes: &HashSet<String>, target_mat_hash: &str) -> bool {
        let target_lower = target_mat_hash.to_lowercase();
        let target_ovr_name = format!("TextureOverride_Replace_{}", target_mat_hash).to_lowercase();

        // 1. If original mod already targeted this material hash, do not touch it
        if original_hashes.contains(&target_lower) {
            return true;
        }

        // 2. If modern replacement override section exists
        if ini.has_section(&target_ovr_name) {
            return true;
        }

        // 3. If any existing override section matches target material hash
        ini.iter_texture_overrides()
            .any(|sec| sec.name.to_lowercase() == target_ovr_name || sec.matches_texture_hash(target_mat_hash))
    }

    /// Export Discrete Partitioned Material Index Maps (L8 PNG) and generate corresponding CST Resource sections.
    fn export_materialmap_resources(
        base_dir: &Path,
        comp_id: u8,
        mode: MaterialmapMode,
        target_mat_hash: &str,
        referenced_resources: &[String],
        ini: &IniCstDocument,
        backed_up: &mut HashSet<std::path::PathBuf>,
        session_time: Option<&str>,
        lightmap_cache: &mut HashMap<std::path::PathBuf, std::sync::Arc<image::RgbaImage>>,
        generated_file_cache: &mut HashMap<(std::path::PathBuf, MaterialmapMode), std::path::PathBuf>,
    ) -> Result<(HashMap<String, String>, Vec<IniCstSection>, bool), FixerError> {
        // Phase 1: Collect export tasks (metadata only, no IO)
        struct ExportTask {
            old_res_name_lower: String,
            new_res_name: String,
            new_filename: String,
            input_path: std::path::PathBuf,
            output_path: std::path::PathBuf,
        }

        let _ = crate::utils::fs_utils::ensure_subdir(base_dir, "Textures")?;
        let mut tasks = Vec::new();

        for (idx, old_res_name) in referenced_resources.iter().enumerate() {
            let old_filename = match ini
                .get_section(old_res_name)
                .and_then(|s| s.get_unquoted_value("filename"))
            {
                Some(f) => f,
                None => continue,
            };

            let lower_fname = old_filename.to_lowercase();
            if lower_fname.ends_with("_r8.jpg") || lower_fname.ends_with("_r8.png") {
                continue;
            }

            let file_stem = Path::new(&old_filename)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(old_res_name);

            let last_token = file_stem.split_whitespace().last().unwrap_or(file_stem);
            let sub_id = last_token.strip_prefix("t=").unwrap_or(last_token);

            let clean_sub_id: String = sub_id
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || c == '_' || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();

            let new_res_name = if idx == 0 {
                format!("ResourceTexture_Replace_{}", target_mat_hash)
            } else {
                format!("ResourceTexture_Replace_{}_{}", target_mat_hash, clean_sub_id)
            };

            if let Some(input_path) = crate::utils::fs_utils::resolve_relative_path(base_dir, &old_filename) {
                if input_path.exists() {
                    let new_filename = format!("Textures/{}_c{}_r8.png", file_stem, comp_id);
                    let output_path = base_dir.join(&new_filename);

                    tasks.push(ExportTask {
                        old_res_name_lower: old_res_name.to_lowercase(),
                        new_res_name,
                        new_filename,
                        input_path,
                        output_path,
                    });
                } else {
                    warn!("Source Lightmap texture file does not exist: {}", input_path.display());
                }
            }
        }

        if tasks.is_empty() {
            return Ok((HashMap::new(), Vec::new(), false));
        }

        // Phase 2: Export with caching and deduplication
        let mut old_to_new_res = HashMap::new();
        let mut new_res_sections = Vec::new();
        let mut any_file_created = false;

        let do_backup = |out_path: &Path, backed_up: &mut HashSet<PathBuf>| -> Result<(), FixerError> {
            if let Some(st) = session_time {
                crate::utils::fs_utils::create_new_file_backup_with_time(out_path, backed_up, st)
            } else {
                crate::utils::fs_utils::create_new_file_backup(out_path, backed_up)
            }
        };

        for task in &tasks {
            if let Some(existing_output) = generated_file_cache.get(&(task.input_path.clone(), mode)) {
                if existing_output.exists() && existing_output != &task.output_path {
                    do_backup(&task.output_path, backed_up)?;
                    if let Err(e) = std::fs::copy(existing_output, &task.output_path) {
                        warn!("Failed to copy cached materialmap: {:?}", e);
                    } else {
                        info!(
                            "Reused identical Component {} Materialmap: {} -> {}",
                            comp_id,
                            existing_output.display(),
                            task.output_path.display()
                        );
                        any_file_created = true;
                    }
                }
            } else {
                let t_read = std::time::Instant::now();
                let decoded_img = if let Some(cached_img) = lightmap_cache.get(&task.input_path) {
                    cached_img.clone()
                } else {
                    match crate::utils::dds_helper::read_dds_rgba(&task.input_path) {
                        Ok(img) => {
                            let arc_img = std::sync::Arc::new(img);
                            lightmap_cache.insert(task.input_path.clone(), arc_img.clone());
                            arc_img
                        }
                        Err(e) => {
                            warn!("Failed to read source DDS ({}): {:?}", task.input_path.display(), e);
                            continue;
                        }
                    }
                };
                crate::domain::pipeline::record_prof("materialmap::read_dds", t_read.elapsed().as_micros() as u64);

                let t_bak = std::time::Instant::now();
                do_backup(&task.output_path, backed_up)?;
                crate::domain::pipeline::record_prof("materialmap::backup", t_bak.elapsed().as_micros() as u64);

                let t_export = std::time::Instant::now();
                info!(
                    "Exporting Component {} Materialmap (PNG): {} -> {}",
                    comp_id,
                    task.input_path.display(),
                    task.output_path.display()
                );
                match crate::utils::dds_helper::export_materialmap_from_img(&decoded_img, &task.output_path, mode) {
                    Ok(_bytes) => {
                        any_file_created = true;
                    }
                    Err(e) => {
                        warn!(
                            "Failed to export Component {} Materialmap ({}): {:?}",
                            comp_id,
                            task.input_path.display(),
                            e
                        );
                        continue;
                    }
                }
                crate::domain::pipeline::record_prof("materialmap::export_png", t_export.elapsed().as_micros() as u64);
                generated_file_cache.insert((task.input_path.clone(), mode), task.output_path.clone());
            }

            let mut new_res_sec = IniCstSection::new(&task.new_res_name);
            new_res_sec.as_resource_view_mut().set_filename(&task.new_filename);
            new_res_sections.push(new_res_sec);

            old_to_new_res.insert(task.old_res_name_lower.clone(), task.new_res_name.clone());
        }

        Ok((old_to_new_res, new_res_sections, any_file_created))
    }
}

impl crate::domain::pipeline::PipelineFixer for MaterialmapFixer {
    fn name(&self) -> &'static str {
        "MaterialmapFixer"
    }

    fn stage(&self) -> crate::domain::pipeline::PipelineStage {
        crate::domain::pipeline::PipelineStage::FeatureAdapt
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let adapt_rules = match &ctx.config.materialmap_adapt {
            Some(rules) if !rules.is_empty() => rules,
            _ => return Ok(false),
        };

        let mut ini_modified = false;
        let mut any_work_done = false;
        let base_dir = ctx.file_path().parent().unwrap_or_else(|| Path::new(".")).to_path_buf();

        let mut lightmap_cache: HashMap<std::path::PathBuf, std::sync::Arc<image::RgbaImage>> = HashMap::new();
        let mut generated_file_cache: HashMap<(std::path::PathBuf, MaterialmapMode), std::path::PathBuf> =
            HashMap::new();

        for rule in adapt_rules {
            let target_mat_hash = &rule.material_hash;
            let target_comp_id = rule.component_id;

            let source_lightmap_hash = match Self::resolve_source_lightmap(ctx.config, rule) {
                Some(h) => h,
                None => continue,
            };

            let mat_node = ctx.config.textures.get(target_mat_hash);
            let mut all_mat_hashes = HashSet::new();
            all_mat_hashes.insert(target_mat_hash.to_lowercase());
            if let Some(node) = mat_node {
                for rep in &node.replace {
                    all_mat_hashes.insert(rep.to_lowercase());
                }
                for derive_hashes in node.derive.values() {
                    for h in derive_hashes {
                        all_mat_hashes.insert(h.to_lowercase());
                    }
                }
            }

            let light_node = ctx.config.textures.get(&source_lightmap_hash);
            let mut all_light_hashes = HashSet::new();
            all_light_hashes.insert(source_lightmap_hash.to_lowercase());
            if let Some(node) = light_node {
                for rep in &node.replace {
                    all_light_hashes.insert(rep.to_lowercase());
                }
                for derive_hashes in node.derive.values() {
                    for h in derive_hashes {
                        all_light_hashes.insert(h.to_lowercase());
                    }
                }
            }

            let involves_mat = all_mat_hashes.iter().any(|h| ctx.original_hashes().contains(h));
            let involves_light = all_light_hashes.iter().any(|h| ctx.original_hashes().contains(h));

            if !involves_mat && !involves_light {
                continue;
            }

            // If already adapted or if mod already includes target material override, skip
            if Self::is_already_adapted(ctx.ini(), ctx.original_hashes(), target_mat_hash) {
                continue;
            }

            let src_light_sec = match ctx
                .ini()
                .iter_texture_overrides()
                .find(|sec| sec.matches_any_texture_hash(&all_light_hashes))
            {
                Some(s) => s.clone(),
                None => continue,
            };

            let mask_mode = match (rule.skin_value, rule.clothing_value) {
                (Some(skin_val), Some(clothing_val)) => MaterialmapMode::DiscretePartition {
                    skin_value: skin_val,
                    clothing_value: clothing_val,
                },
                (Some(skin_val), None) => MaterialmapMode::SkinOverrideWithG { skin_value: skin_val },
                (None, _) => MaterialmapMode::PassThroughG,
            };

            let referenced_resources = src_light_sec.collect_referenced_resources();
            if referenced_resources.is_empty() {
                continue;
            }

            let session_time = ctx.session_time().map(|s| s.to_string());
            let (ini, backed_up) = (&ctx.mod_ctx.ini, &mut ctx.mod_ctx.backed_up);

            let (old_to_new_res, new_res_sections, file_created) = Self::export_materialmap_resources(
                &base_dir,
                target_comp_id,
                mask_mode,
                target_mat_hash,
                &referenced_resources,
                ini,
                backed_up,
                session_time.as_deref(),
                &mut lightmap_cache,
                &mut generated_file_cache,
            )?;

            if file_created {
                any_work_done = true;
            }

            if old_to_new_res.is_empty() {
                continue;
            }

            let matching_mat_indices = ctx
                .ini()
                .find_section_indices(|sec| sec.matches_any_texture_hash(&all_mat_hashes));

            if !matching_mat_indices.is_empty() {
                let mut any_sec_changed = false;
                for &mat_idx in &matching_mat_indices {
                    let sec = &mut ctx.ini_mut().sections[mat_idx];
                    let old_lines = sec.lines.clone();
                    sec.rewrite_resource_bindings(|key, val| {
                        if key.eq_ignore_ascii_case("this") {
                            let clean = val.trim().trim_matches('"');
                            let (has_ref, res_name) = if let Some(stripped) = clean.strip_prefix("ref ") {
                                (true, stripped.trim())
                            } else {
                                (false, clean)
                            };
                            let target_res = if let Some(target_res) = old_to_new_res.get(&res_name.to_lowercase()) {
                                target_res.as_str()
                            } else if let Some(single_res) = (old_to_new_res.len() == 1)
                                .then(|| old_to_new_res.values().next())
                                .flatten()
                            {
                                single_res.as_str()
                            } else {
                                return None;
                            };
                            if has_ref {
                                Some(format!("ref {}", target_res))
                            } else {
                                Some(target_res.to_string())
                            }
                        } else {
                            None
                        }
                    });
                    if sec.lines != old_lines {
                        any_sec_changed = true;
                    }
                }

                let inserted = ctx
                    .ini_mut()
                    .insert_sections_if_missing(matching_mat_indices[0], new_res_sections);
                if any_sec_changed || inserted {
                    info!(
                        "Updated existing materialmap override and LODs for Component {}",
                        target_comp_id
                    );
                    ini_modified = true;
                    any_work_done = true;
                }
            } else {
                let target_ovr_name = format!("TextureOverride_Replace_{}", target_mat_hash);
                if ctx.ini().has_section(&target_ovr_name) {
                    continue;
                }

                let mut cf = src_light_sec.to_control_flow();
                cf.retain_resource_bindings_only();
                cf.transform_resource_bindings(|key, val| {
                    if key.eq_ignore_ascii_case("this") {
                        let clean = val.trim().trim_matches('"');
                        let (has_ref, res_name) = if let Some(stripped) = clean.strip_prefix("ref ") {
                            (true, stripped.trim())
                        } else {
                            (false, clean)
                        };
                        let target_res = if let Some(target_res) = old_to_new_res.get(&res_name.to_lowercase()) {
                            target_res.as_str()
                        } else if let Some(single_res) = (old_to_new_res.len() == 1)
                            .then(|| old_to_new_res.values().next())
                            .flatten()
                        {
                            single_res.as_str()
                        } else {
                            return None;
                        };
                        if has_ref {
                            Some(format!("ref {}", target_res))
                        } else {
                            Some(target_res.to_string())
                        }
                    } else {
                        None
                    }
                });

                let mut new_ovr_sec = IniCstSection::new(&target_ovr_name);
                {
                    let mut ovr_view = new_ovr_sec.as_texture_override_view_mut();
                    ovr_view.set_hash(target_mat_hash);
                    ovr_view.set_match_priority("0");
                }
                new_ovr_sec.lines.extend(cf.to_lines());

                let mut combined_secs = new_res_sections;
                combined_secs.push(new_ovr_sec);

                let src_name = src_light_sec.name.clone();
                let inserted = if !ctx.ini_mut().insert_sections_after(&src_name, combined_secs.clone()) {
                    ctx.ini_mut().push_sections_if_missing(combined_secs)
                } else {
                    true
                };

                if inserted {
                    info!(
                        "Generated adjacent materialmap override section {} for Component {}",
                        target_ovr_name, target_comp_id
                    );
                    ini_modified = true;
                    any_work_done = true;
                }
            }
        }

        if ini_modified {
            ctx.mark_ini_modified();
        }

        Ok(any_work_done)
    }
}
