// src-core/src/fixers/hair_fix.rs

use std::{collections::HashSet, path::Path};

use log::{info, warn};

use crate::{
    config_loader::{CharacterConfig, HairFixConfig},
    domain::cst::IniCstSection,
    errors::FixerError,
    fixers::traits::FixerContext,
    utils::{dds_helper::make_bc7_opaque, ini_parser::parse_line, regex_patterns::*},
};

pub struct HairFixer;

struct HairFallbackConfig {
    char_name: &'static str,
    texture_filename: &'static str,
    texture_data: &'static [u8],
    resource_name: &'static str,
    override_name: &'static str,
    base_hash: &'static str,
}

const ROVER_MALE_FALLBACK: HairFallbackConfig = HairFallbackConfig {
    char_name: "RoverMale",
    texture_filename: "RoverMaleHair_D.dds",
    texture_data: include_bytes!("../resources/MRoverHair_C6D.dds"),
    resource_name: "ResourceTextureRoverMaleHair",
    override_name: "TextureOverrideTextureRoverMaleHair",
    base_hash: "e8349ade",
};

impl HairFixer {
    /// Collects all hair diffuse hashes from character configuration.
    fn collect_hair_diffuse_hashes(&self, config: &CharacterConfig) -> HashSet<String> {
        let mut hashes = HashSet::new();
        for (base_hash, node) in &config.textures {
            if let Some(meta) = &node.meta {
                if meta.id.contains(&0) && meta.type_ == "D" {
                    hashes.insert(base_hash.to_lowercase());
                    for old_h in &node.replace {
                        hashes.insert(old_h.to_lowercase());
                    }
                    for derive_hashes in node.derive.values() {
                        for h in derive_hashes {
                            hashes.insert(h.to_lowercase());
                        }
                    }
                }
            }
        }
        hashes
    }

    /// Extracts referenced hair texture filenames from the INI structure.
    fn collect_hair_texture_files(&self, ctx: &FixerContext, hair_diffuse_hashes: &HashSet<String>) -> Vec<String> {
        let sanitize_res_name = |raw: &str| -> String {
            let clean = raw.trim().trim_matches('"');
            clean.strip_prefix("ref ").unwrap_or(clean).trim().to_lowercase()
        };

        let mut hair_resource_names = HashSet::new();

        // Check Component0 for this, ps-t1, or RabbitFX diffuse resource references.
        if let Some(sec) = ctx.ini().get_section("TextureOverrideComponent0") {
            for line in &sec.lines {
                let (k, v, _) = parse_line(line);
                if let (Some(key_str), Some(val_str)) = (k, v) {
                    let key_lower = key_str.trim().to_lowercase();
                    if key_lower == "this" || key_lower == "ps-t1" {
                        let res_name = sanitize_res_name(&val_str);
                        if res_name.starts_with("resource") {
                            hair_resource_names.insert(res_name);
                        }
                    }
                }
                if let Some(cap) = RE_RABBIT_FX_REF_DIFFUSE.captures(line) {
                    hair_resource_names.insert(cap[1].to_lowercase());
                }
            }
        }

        // Collect ResourceTexture from matching hair diffuse overrides.
        for sec in ctx.ini().iter_texture_overrides() {
            let sec_hash = sec.get_value("hash").map(|h| h.trim().to_lowercase());
            let matches_hash = sec_hash.as_ref().map_or(false, |h| hair_diffuse_hashes.contains(h));
            let matches_name = {
                let lower = sec.name.to_lowercase();
                lower.contains("hairdiffuse")
                    || (lower.contains("hair") && !lower.contains("hm") && !lower.contains("lightmap"))
            };

            if matches_hash || matches_name {
                for line in &sec.lines {
                    let (k, v, _) = parse_line(line);
                    if let (Some(key_str), Some(val_str)) = (k, v) {
                        let key_lower = key_str.trim().to_lowercase();
                        if key_lower == "this" || key_lower == "ps-t1" || key_lower.starts_with("resource") {
                            let res_name = sanitize_res_name(&val_str);
                            if res_name.starts_with("resource") {
                                hair_resource_names.insert(res_name);
                            }
                        }
                    }
                    if let Some(cap) = RE_RABBIT_FX_REF_DIFFUSE.captures(line) {
                        hair_resource_names.insert(cap[1].to_lowercase());
                    }
                }
            }
        }

        // Map resource sections to physical filenames on disk.
        let mut files_to_fix = Vec::new();
        for sec in &ctx.ini().sections {
            if hair_resource_names.contains(&sec.name.to_lowercase()) {
                if let Some(fname) = sec.get_unquoted_value("filename") {
                    if !files_to_fix.contains(&fname) {
                        files_to_fix.push(fname);
                    }
                }
            }
        }

        files_to_fix
    }

    /// Sets hair diffuse textures to opaque via `make_bc7_opaque`.
    fn fix_hair_textures_opaque(&self, ctx: &mut FixerContext, files: &[String]) -> Result<bool, FixerError> {
        if files.is_empty() {
            return Ok(false);
        }

        let backed_up_mutex = std::sync::Mutex::new(std::mem::take(ctx.backed_up()));
        let base_dir = ctx.file_path().parent().unwrap_or_else(|| Path::new("."));
        let mut modified_count = 0usize;

        for rel_path in files {
            if let Some(full_tex_path) = crate::utils::fs_utils::resolve_relative_path(base_dir, rel_path) {
                if full_tex_path.exists() {
                    info!(
                        "Setting hair texture Alpha channel to opaque (255): {}",
                        full_tex_path.display()
                    );
                    match make_bc7_opaque(&full_tex_path, &full_tex_path, &backed_up_mutex, ctx.session_time()) {
                        Ok(true) => {
                            modified_count += 1;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            warn!(
                                "Failed to make hair texture opaque ({}): {:?}",
                                full_tex_path.display(),
                                e
                            );
                        }
                    }
                } else {
                    warn!("Texture file does not exist: {}", full_tex_path.display());
                }
            }
        }

        *ctx.backed_up() = backed_up_mutex.into_inner().unwrap_or_else(|e| e.into_inner());
        Ok(modified_count > 0)
    }

    /// Applies fallback hair texture when no custom texture is found.
    fn apply_fallback_hair(
        &self,
        ctx: &mut FixerContext,
        cfg: &HairFallbackConfig,
    ) -> Result<(bool, bool), FixerError> {
        let base_dir = ctx.file_path().parent().unwrap_or_else(|| Path::new("."));
        let _ = crate::utils::fs_utils::ensure_subdir(base_dir, "Textures")?;
        let rel_path = format!("Textures/{}", cfg.texture_filename);
        let full_path = base_dir.join(&rel_path);

        let mut file_created = false;
        if !full_path.exists() {
            ctx.backup_new_file(&full_path)?;
            info!(
                "Writing fallback default hair texture for {}: {}",
                cfg.char_name,
                full_path.display()
            );
            std::fs::write(&full_path, cfg.texture_data).map_err(FixerError::IoError)?;
            file_created = true;
        }

        let normalized_path = rel_path.replace('\\', "/");
        let mut ini_changed = false;

        let mut res_view = ctx.ini_mut().ensure_resource(cfg.resource_name);
        if res_view.filename().as_deref() != Some(&normalized_path) {
            res_view.set_filename(&normalized_path);
            ini_changed = true;
        }

        let mut ovr_view = ctx.ini_mut().ensure_texture_override(cfg.override_name);
        if ovr_view.hash().is_none() {
            ovr_view.set_hash(cfg.base_hash);
            ovr_view.set_match_priority("0");
            ovr_view.set_this(cfg.resource_name);
            ini_changed = true;
        }

        Ok((ini_changed, file_created))
    }

    /// Splits hair component geometry into a dedicated component (e.g. Component6 for RoverMale).
    fn split_hair_component(
        &self,
        ctx: &mut FixerContext,
        hair_fix_cfg: &HairFixConfig,
        hair_hashes: &HashSet<String>,
        hair_files: &[String],
    ) -> Result<bool, FixerError> {
        let comp0_sec = match ctx.ini().get_section("TextureOverrideComponent0") {
            Some(sec) => sec.clone(),
            None => return Ok(false),
        };

        let target_comp_name = "TextureOverrideComponent6";
        if ctx.ini().has_section(target_comp_name) {
            return Ok(false);
        }

        let match_first = hair_fix_cfg.match_first_index.as_str();
        let match_count = hair_fix_cfg.match_index_count.as_str();
        let vg_off = hair_fix_cfg.vg_offset;
        let vg_cnt = hair_fix_cfg.vg_count;

        let uses_merge_status_id_0 = comp0_sec.lines.iter().any(|l| l.contains("$merge_status_id_0"));

        let mut comp6_sec = IniCstSection::new(target_comp_name);
        comp6_sec.lines = if uses_merge_status_id_0 {
            comp0_sec
                .lines
                .iter()
                .map(|l| l.replace("$merge_status_id_0", "$merge_status_id_6"))
                .collect()
        } else {
            comp0_sec.lines.clone()
        };

        {
            let mut comp6_view = comp6_sec.as_component_view_mut();
            comp6_view.set_match_first_index(match_first);
            comp6_view.set_match_index_count(match_count);
            comp6_view.set_vg_offset_and_count(vg_off, vg_cnt);
        }

        let has_rabbit_fx = comp0_sec
            .lines
            .iter()
            .any(|l| l.contains("Resource\\RabbitFX\\Diffuse"));

        let insert_idx = comp6_sec
            .lines
            .iter()
            .position(|l| RE_HANDLING_SKIP.is_match(l))
            .map(|idx| idx + 1)
            .unwrap_or(comp6_sec.lines.len());

        let base_indent = if insert_idx > 0 && insert_idx <= comp6_sec.lines.len() {
            let ref_line = &comp6_sec.lines[insert_idx - 1];
            ref_line
                .chars()
                .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                .collect::<String>()
        } else {
            "        ".to_string()
        };

        if !has_rabbit_fx {
            let source_hair_sec = hair_hashes
                .iter()
                .find_map(|h| ctx.ini().find_texture_override_by_hash(h).cloned())
                .or_else(|| {
                    ctx.ini()
                        .iter_texture_overrides()
                        .find(|sec| {
                            let l = sec.name.to_lowercase();
                            l.contains("hairdiffuse")
                                || (l.contains("hair") && !l.contains("hm") && !l.contains("lightmap"))
                        })
                        .cloned()
                });

            if let Some(src_sec) = source_hair_sec {
                let mut cf = src_sec.to_control_flow();
                cf.retain_resource_bindings_only();
                cf.strip_outer_object_detected();
                cf.transform_resource_bindings(|key, val| {
                    if key.eq_ignore_ascii_case("this") || key.eq_ignore_ascii_case("ps-t1") {
                        let clean = val.trim().trim_matches('"');
                        let res_name = clean.strip_prefix("ref ").unwrap_or(clean).trim();
                        Some(res_name.to_string())
                    } else {
                        None
                    }
                });
                cf.rename_key("this", "ps-t1");

                let formatted_lines = cf.to_lines_with_base_indent(&base_indent);
                for (offset, line) in formatted_lines.into_iter().enumerate() {
                    comp6_sec.lines.insert(insert_idx + offset, line);
                }
            } else if hair_files.is_empty() && ctx.char_name == "RoverMale" {
                info!("No custom hair texture found for RoverMale, applying fallback hair texture.");
                let _ = self.apply_fallback_hair(ctx, &ROVER_MALE_FALLBACK)?;
                comp6_sec.lines.insert(
                    insert_idx,
                    format!("{}ps-t1 = {}", base_indent, ROVER_MALE_FALLBACK.resource_name),
                );
            }
        }

        let mut last_comp_idx = None;
        let mut max_comp_id = 0;
        for (i, sec) in ctx.ini().sections.iter().enumerate() {
            if let Some(comp_id) = sec.component_id() {
                if comp_id >= max_comp_id {
                    max_comp_id = comp_id;
                    last_comp_idx = Some(i);
                }
            }
        }

        if let Some(idx) = last_comp_idx {
            info!(
                "Inserting new Component6 section after the last component section (Component{})",
                max_comp_id
            );
            ctx.ini_mut().sections.insert(idx + 1, comp6_sec);
        } else {
            info!("Appending new Component6 section to the end of the INI");
            ctx.ini_mut().sections.push(comp6_sec);
        }

        if uses_merge_status_id_0 {
            let mut consts = ctx.ini_mut().ensure_constants();
            if !consts.has_global("$merge_status_id_6") {
                consts.set_global("$merge_status_id_6", "0");
            }

            if let Some(skeleton_sec) = ctx.ini_mut().get_section_mut("CommandListUpdateMergedSkeleton") {
                if !skeleton_sec.has_key("$merge_status_id_6") {
                    skeleton_sec.prepend_key_value("$merge_status_id_6", "0", "    ");
                }
            }
        }

        ctx.mark_ini_modified();
        Ok(true)
    }

    /// Checks whether the mod references hair diffuse trigger hashes.
    /// Strictly requires matching trigger_hash (diffuse texture hashes) and excludes body main_hashes.
    fn should_fix_hair_textures(&self, ctx: &FixerContext, hair_fix_cfg: &HairFixConfig) -> bool {
        if hair_fix_cfg.trigger_hash.is_empty() {
            return false;
        }

        let trigger_hashes: HashSet<String> = hair_fix_cfg
            .trigger_hash
            .iter()
            .map(|h| h.trim().to_lowercase())
            .collect();

        ctx.original_hashes()
            .iter()
            .any(|h| trigger_hashes.contains(&h.to_lowercase()))
            || ctx.ini().iter_texture_overrides().any(|sec| {
                sec.get_value("hash")
                    .map_or(false, |h| trigger_hashes.contains(&h.trim().to_lowercase()))
            })
    }

    /// Checks whether the mod requires hair component splitting (e.g. RoverMale Component6).
    /// Triggers when component splitting is configured and the mod is an older mesh needing topology split.
    fn should_split_component(&self, ctx: &FixerContext, hair_fix_cfg: &HairFixConfig) -> bool {
        let needs_split = !hair_fix_cfg.match_first_index.is_empty() && !hair_fix_cfg.match_index_count.is_empty();
        if !needs_split {
            return false;
        }

        let has_comp0 = ctx.ini().has_section("TextureOverrideComponent0");
        let has_comp6 = ctx.ini().has_section("TextureOverrideComponent6");
        if !has_comp0 || has_comp6 {
            return false;
        }

        let mut target_hashes: HashSet<String> = hair_fix_cfg
            .trigger_hash
            .iter()
            .map(|h| h.trim().to_lowercase())
            .collect();
        for rep in &ctx.config.main_hashes {
            for old_h in &rep.old {
                target_hashes.insert(old_h.to_lowercase());
            }
        }

        ctx.original_hashes()
            .iter()
            .any(|h| target_hashes.contains(&h.to_lowercase()))
            || ctx.ini().iter_texture_overrides().any(|sec| {
                sec.get_value("hash")
                    .map_or(false, |h| target_hashes.contains(&h.trim().to_lowercase()))
            })
            || ctx.ini().get_section("TextureOverrideComponent0").map_or(false, |sec| {
                sec.get_value("hash")
                    .map_or(false, |h| target_hashes.contains(&h.trim().to_lowercase()))
            })
    }
}

impl crate::domain::pipeline::PipelineFixer for HairFixer {
    fn name(&self) -> &'static str {
        "HairFixer"
    }

    fn stage(&self) -> crate::domain::pipeline::PipelineStage {
        crate::domain::pipeline::PipelineStage::MeshGated
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let hair_fix_cfg = match &ctx.config.hair_fix {
            Some(cfg) => cfg,
            None => return Ok(false),
        };

        let fix_textures = self.should_fix_hair_textures(ctx, hair_fix_cfg);
        let split_component = self.should_split_component(ctx, hair_fix_cfg);

        if !fix_textures && !split_component {
            return Ok(false);
        }

        let mut any_work_done = false;

        let hair_hashes = self.collect_hair_diffuse_hashes(ctx.config);
        let hair_files = self.collect_hair_texture_files(ctx, &hair_hashes);

        // 1. Universal hair diffuse alpha channel fix (only when mod references target hair trigger hashes)
        if fix_textures && self.fix_hair_textures_opaque(ctx, &hair_files)? {
            any_work_done = true;
        }

        // 2. Component split (when match_first_index & match_index_count are configured, e.g. RoverMale)
        if split_component && self.split_hair_component(ctx, hair_fix_cfg, &hair_hashes, &hair_files)? {
            any_work_done = true;
        }

        Ok(any_work_done)
    }
}
