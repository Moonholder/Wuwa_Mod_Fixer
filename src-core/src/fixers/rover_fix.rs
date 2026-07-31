// src-core/src/fixers/rover_fix.rs

use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use crate::utils::dds_helper::{export_shading_mask, make_bc7_opaque};
use crate::utils::ini_parser::{IniDocument, IniSection, parse_line};
use crate::utils::regex_patterns::*;
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub struct RoverFixer;

const ROVER_MALE_HAIR_DDS: &[u8] = include_bytes!("../resources/MRoverHair_C6D.dds");
const ROVER_FEMALE_HAIR_DDS: &[u8] = include_bytes!("../resources/FRoverHair_C0D.dds");

impl RoverFixer {
    /// Helper: Extract leading whitespace characters as indentation
    fn get_indent(&self, line: &str) -> String {
        line.chars().take_while(|c| c.is_whitespace()).collect()
    }

    /// Helper: Handles writing fallback textures, folder creation, and backups
    fn write_fallback_texture(
        &self,
        ctx: &mut FixerContext,
        filename: &str,
        data: &[u8],
    ) -> Result<String, FixerError> {
        let base_dir = ctx.file_path.parent().unwrap();
        let _ = crate::utils::fs_utils::ensure_subdir(base_dir, "Textures")?;
        let rel_path = format!("Textures/{}", filename);
        let full_path = base_dir.join(&rel_path);

        if !full_path.exists() {
            crate::utils::fs_utils::create_new_file_backup(&full_path, ctx.backed_up)?;
            info!("Writing fallback default texture: {}", full_path.display());
            if let Err(e) = std::fs::write(&full_path, data) {
                warn!(
                    "Failed to write default fallback texture ({}): {:?}",
                    full_path.display(),
                    e
                );
            }
        }
        Ok(rel_path)
    }

    /// Find a safe insertion index: immediately after the last standard texture override section
    fn find_safe_insert_index(&self, ini: &IniDocument) -> usize {
        let mut last_override_idx = None;
        for (i, sec) in ini.sections.iter().enumerate() {
            let sec_name_lower = sec.name.to_lowercase();
            // Filter out advanced, component, shapekey, and redirection sections
            if sec_name_lower.starts_with("textureoverride")
                && !sec_name_lower.contains("_lod")
                && !sec_name_lower.contains("_derive")
                && !sec_name_lower.contains("shapekey")
                && !sec_name_lower.contains("component")
            {
                last_override_idx = Some(i);
            }
        }

        if let Some(idx) = last_override_idx {
            idx + 1
        } else {
            if !ini.sections.is_empty() { 1 } else { 0 }
        }
    }

    /// Targeted extraction of specified Component Lightmaps to generate new Materialmaps
    fn adapt_rover_materialmaps(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let mut modified = false;

        let is_rover_male = ctx.char_name == "RoverMale";
        let is_rover_female = ctx.char_name == "RoverFemale";

        // Map targeted Component IDs directly to their respective new Materialmap hashes
        let id_to_materialmap: HashMap<&str, &str> = if is_rover_female {
            [
                ("3", "f813702e"), // C3 (Component ID 3)
                ("4", "e40b43c4"), // C4 (Component ID 4)
            ]
            .iter()
            .cloned()
            .collect()
        } else if is_rover_male {
            [
                ("2", "faf5e483"), // C2 (Component ID 2)
            ]
            .iter()
            .cloned()
            .collect()
        } else {
            HashMap::new()
        };

        let mut hash_to_ovr_map = HashMap::new();
        for (idx, sec) in ctx.ini.sections.iter().enumerate() {
            let sec_name_lower = sec.name.to_lowercase();
            if sec_name_lower.starts_with("textureoverride") {
                if let Some(h) = sec.get_value("hash") {
                    if let Some(res_name) = sec.get_value("this") {
                        hash_to_ovr_map.insert(h.trim().to_lowercase(), (idx, res_name));
                    }
                }
            }
        }

        let base_dir = ctx.file_path.parent().unwrap();

        for (&target_id, &new_materialmap) in &id_to_materialmap {
            // Find the Lightmap texture node in config that matches the specific targeted Component ID
            let mut matched_lightmap = None;
            for (new_hash, node) in &ctx.config.textures {
                if let Some(meta) = &node.meta {
                    if meta.id.iter().any(|id| id.to_string() == target_id) && meta.type_ == "L" {
                        matched_lightmap = Some((new_hash.clone(), node));
                        break;
                    }
                }
            }

            let (new_lightmap_hash, lightmap_node) = match matched_lightmap {
                Some(val) => val,
                None => continue,
            };

            debug!("Processing lightmap: {}", new_lightmap_hash);

            // Verify if any of the old lightmap hashes for this component were originally present
            let has_old_hash = lightmap_node
                .replace
                .iter()
                .any(|oh| ctx.original_hashes.contains(&oh.to_lowercase()));

            if !has_old_hash {
                continue;
            }

            // Guard: If the target Materialmap override already exists, skip processing to avoid duplicates
            let target_ovr_name = format!("TextureOverride_Replace_{}", new_materialmap);
            if ctx.ini.has_section(&target_ovr_name) {
                continue;
            }

            // Since HashReplaceFixer ran first, the old hash was updated to the new_lightmap_hash inside the ini.
            // We search for the TextureOverride section that now contains hash = new_lightmap_hash.
            let (matched_sec_idx, old_resource_name) = match hash_to_ovr_map.get(&new_lightmap_hash.to_lowercase()) {
                Some(&(idx, ref res_name)) => (Some(idx), Some(res_name.clone())),
                None => (None, None),
            };

            if let Some(res_name) = old_resource_name {
                let filename_opt = ctx
                    .ini
                    .get_section(&res_name)
                    .and_then(|res_sec| res_sec.get_unquoted_value("filename"));

                if let Some(old_filename) = filename_opt {
                    if old_filename.to_lowercase().ends_with("_r8.dds")
                        || old_filename.to_lowercase().ends_with("_r8.jpg")
                    {
                        continue;
                    }

                    let input_path = base_dir.join(&old_filename);
                    if input_path.exists() {
                        let file_stem = Path::new(&old_filename)
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("shading_mask");

                        let new_filename = format!("Textures/{}_r8.jpg", file_stem);
                        let output_path = base_dir.join(&new_filename);

                        let _ = crate::utils::fs_utils::ensure_subdir(base_dir, "Textures")?;

                        // Create backup before generating the converted DDS
                        crate::utils::fs_utils::create_new_file_backup(&output_path, ctx.backed_up)?;
                        info!(
                            "Exporting R8 Shading Mask: {} -> {}",
                            input_path.display(),
                            output_path.display()
                        );

                        let bg_gray_value = if is_rover_male { 2 } else { 0 };
                        if let Err(e) = export_shading_mask(&input_path, &output_path, bg_gray_value) {
                            warn!("Failed to export R8 Shading Mask ({}): {:?}", input_path.display(), e);
                            continue;
                        }

                        // Build the new ResourceTexture section with the converted Materialmap hash
                        let new_res_name = format!("ResourceTexture_Replace_{}", new_materialmap);
                        let mut new_res_sec = IniSection::new(&new_res_name);
                        let normalized_path = new_filename.replace("\\", "/");
                        new_res_sec.set_key_value("filename", &normalized_path, "");

                        // Build the new TextureOverride section with the converted Materialmap hash
                        let new_ovr_name = format!("TextureOverride_Replace_{}", new_materialmap);
                        let mut new_ovr_sec = IniSection::new(&new_ovr_name);
                        new_ovr_sec.set_key_value("hash", new_materialmap, "");
                        new_ovr_sec.set_key_value("match_priority", "0", "");
                        new_ovr_sec.set_key_value("this", &new_res_name, "");

                        let target_idx = matched_sec_idx
                            .map(|idx| idx + 1)
                            .unwrap_or_else(|| self.find_safe_insert_index(ctx.ini));

                        ctx.ini.sections.insert(target_idx, new_ovr_sec);
                        ctx.ini.sections.insert(target_idx, new_res_sec);

                        info!(
                            "Successfully generated override section {} and resource section {} adjacent to the original section",
                            new_ovr_name, new_res_name
                        );
                        modified = true;
                    } else {
                        warn!("Source Lightmap texture file does not exist: {}", input_path.display());
                    }
                }
            }
        }

        Ok(modified)
    }

    /// writes and registers default hair textures
    fn apply_fallback_hair_texture(
        &self,
        ctx: &mut FixerContext,
        filename: &str,
        data: &[u8],
        resource_name: &str,
        override_name: &str,
        base_hash: &str,
    ) -> Result<bool, FixerError> {
        let mut ini_modified = false;
        let fallback_rel_path = self.write_fallback_texture(ctx, filename, data)?;

        let mut res_sec = ctx.ini.get_section_mut(resource_name).cloned();
        let mut is_new_res = false;
        if res_sec.is_none() {
            res_sec = Some(IniSection::new(resource_name));
            is_new_res = true;
        }
        let res_sec = res_sec.as_mut().unwrap();

        let normalized_fallback_path = fallback_rel_path.replace("\\", "/");
        let old_filename = res_sec.get_value("filename");
        if old_filename.as_deref() != Some(&normalized_fallback_path) {
            res_sec.set_key_value("filename", &normalized_fallback_path, "");
            ini_modified = true;
        }

        let mut ovr_sec = ctx.ini.get_section_mut(override_name).cloned();
        let mut is_new_ovr = false;
        if ovr_sec.is_none() {
            let mut new_sec = IniSection::new(override_name);
            new_sec.set_key_value("hash", base_hash, "");
            new_sec.set_key_value("match_priority", "0", "");
            new_sec.set_key_value("this", resource_name, "");
            ovr_sec = Some(new_sec);
            is_new_ovr = true;
            ini_modified = true;
        }

        if is_new_res || is_new_ovr {
            let target_idx = self.find_safe_insert_index(ctx.ini);
            if is_new_ovr {
                ctx.ini.sections.insert(target_idx, ovr_sec.unwrap());
            }
            if is_new_res {
                ctx.ini.sections.insert(target_idx, res_sec.clone());
            }
        } else {
            if let Some(sec) = ctx.ini.get_section_mut(resource_name) {
                *sec = res_sec.clone();
            }
        }

        Ok(ini_modified)
    }

    /// Helper: extracts hair texture filenames from ini segments
    fn collect_hair_textures(&self, ctx: &FixerContext) -> (Option<String>, Vec<String>) {
        let sanitize_res_name = |raw: &str| -> String {
            let clean = raw.trim().replace('"', "");
            clean.strip_prefix("ref ").unwrap_or(&clean).trim().to_lowercase()
        };

        let mut hair_diffuse_hashes = HashSet::new();
        for (base_hash, node) in &ctx.config.textures {
            if let Some(meta) = &node.meta {
                if meta.id.contains(&0) && meta.type_ == "D" {
                    hair_diffuse_hashes.insert(base_hash.to_lowercase());
                    for old_h in &node.replace {
                        hair_diffuse_hashes.insert(old_h.to_lowercase());
                    }
                    for derive_hashes in node.derive.values() {
                        for h in derive_hashes {
                            hair_diffuse_hashes.insert(h.to_lowercase());
                        }
                    }
                }
            }
        }

        let mut hair_resource_names = HashSet::new();

        // 1. If Component0 exists, extract ONLY Diffusemap referenced resources (ps-t0, this, RabbitFX Diffuse)
        if let Some(sec) = ctx.ini.get_section("TextureOverrideComponent0") {
            for line in &sec.lines {
                let (k, v, _) = parse_line(line);
                if let (Some(key_str), Some(val_str)) = (k, v) {
                    let key_lower = key_str.trim().to_lowercase();
                    if key_lower == "ps-t0" || key_lower == "this" {
                        let res_name = sanitize_res_name(&val_str);
                        if res_name.starts_with("resourcetexture") {
                            hair_resource_names.insert(res_name);
                        }
                    }
                }
                if let Some(cap) = RE_RABBIT_FX_REF_DIFFUSE.captures(line) {
                    hair_resource_names.insert(cap[1].to_lowercase());
                }
            }
        }

        // 2. Single-pass INI traversal: collect TextureOverride "this" references and ResourceTexture filenames
        let mut resource_filenames = HashMap::new();
        for sec in &ctx.ini.sections {
            let sec_name_lower = sec.name.to_lowercase();

            if sec_name_lower.starts_with("textureoverride")
                && !sec_name_lower.starts_with("textureoverridecomponent")
                && !sec_name_lower.starts_with("textureoverrideshapekey")
            {
                if let Some(hash_val) = sec.get_value("hash") {
                    if hair_diffuse_hashes.contains(&hash_val.trim().to_lowercase()) {
                        for this_val in sec.get_all_values("this") {
                            hair_resource_names.insert(sanitize_res_name(&this_val));
                        }
                    }
                }
            } else if sec_name_lower.starts_with("resourcetexture") {
                if let Some(val) = sec.get_unquoted_value("filename") {
                    resource_filenames.insert(sec.name.clone(), val);
                }
            }
        }

        let mut hair_resource_name = None;
        let mut hair_texture_files_to_fix = Vec::new();

        for (sec_name, filename) in &resource_filenames {
            let sec_name_lower = sec_name.to_lowercase();

            if hair_resource_names.contains(&sec_name_lower) {
                if hair_resource_name.is_none() {
                    hair_resource_name = Some(sec_name.clone());
                }
                if !hair_texture_files_to_fix.contains(filename) {
                    hair_texture_files_to_fix.push(filename.clone());
                }
            }
        }

        // Fallback detection: checks for default fallback resource names
        let fallback_res_name = if ctx.char_name == "RoverMale" {
            "ResourceTextureRoverMaleHair"
        } else {
            "ResourceTextureRoverFemaleHair"
        };
        if hair_resource_name.is_none() {
            if let Some(sec) = ctx.ini.get_section(fallback_res_name) {
                if let Some(val) = sec.get_unquoted_value("filename") {
                    hair_resource_name = Some(fallback_res_name.to_string());
                    if !hair_texture_files_to_fix.contains(&val) {
                        hair_texture_files_to_fix.push(val);
                    }
                }
            }
        }

        (hair_resource_name, hair_texture_files_to_fix)
    }

    /// Helper: sets completely opaque to solid for target DDS filenames
    fn fix_hair_textures_alpha(
        &self,
        ctx: &mut FixerContext,
        files: &[String],
        should_fix: bool,
    ) -> Result<bool, FixerError> {
        if !should_fix || files.is_empty() {
            return Ok(false);
        }

        let backed_up_mutex = std::sync::Mutex::new(std::mem::take(ctx.backed_up));
        std::thread::scope(|s| {
            for rel_path in files {
                let full_tex_path = ctx.file_path.parent().unwrap().join(rel_path);
                if full_tex_path.exists() {
                    let backed_up_ref = &backed_up_mutex;
                    s.spawn(move || {
                        info!(
                            "Modifying hair texture Alpha channel to 255: {}",
                            full_tex_path.display()
                        );
                        if let Err(e) = make_bc7_opaque(&full_tex_path, &full_tex_path, backed_up_ref) {
                            warn!(
                                "Failed to modify texture Alpha channel ({}): {:?}",
                                full_tex_path.display(),
                                e
                            );
                        }
                    });
                } else {
                    warn!("Texture file does not exist: {}", full_tex_path.display());
                }
            }
        });
        *ctx.backed_up = backed_up_mutex.into_inner().unwrap();
        Ok(true)
    }

    fn ensure_hair_fallback_texture(&self, ctx: &mut FixerContext, is_rover_male: bool) -> Result<bool, FixerError> {
        let (filename, data, res_name, ovr_name, hash) = if is_rover_male {
            (
                "RoverMaleHair_D.dds",
                ROVER_MALE_HAIR_DDS,
                "ResourceTextureRoverMaleHair",
                "TextureOverrideTextureRoverMaleHair",
                "e8349ade",
            )
        } else {
            (
                "FRoverHair_C0D.dds",
                ROVER_FEMALE_HAIR_DDS,
                "ResourceTextureRoverFemaleHair",
                "TextureOverrideTextureRoverFemaleHair",
                "c7953bd5",
            )
        };

        info!(
            "No custom hair texture found, entering {} fallback hair texture logic.",
            if is_rover_male { "RoverMale" } else { "RoverFemale" }
        );
        self.apply_fallback_hair_texture(ctx, filename, data, res_name, ovr_name, hash)
    }

    /// Helper: extracts raw lines from Component0
    fn get_component0_lines(&self, ctx: &FixerContext) -> Option<Vec<String>> {
        ctx.ini
            .get_section("TextureOverrideComponent0")
            .map(|sec| sec.lines.clone())
    }

    /// Female Rover specific fix steps
    fn fix_rover_female(&self, ctx: &mut FixerContext, should_fix_hair_alpha: bool) -> Result<bool, FixerError> {
        let mut ini_modified = false;

        if self.adapt_rover_materialmaps(ctx)? {
            ini_modified = true;
        }

        let (_, hair_texture_files_to_fix) = self.collect_hair_textures(ctx);
        let hair_textures_modified =
            self.fix_hair_textures_alpha(ctx, &hair_texture_files_to_fix, should_fix_hair_alpha)?;

        let comp0_lines_opt = self.get_component0_lines(ctx);
        let has_rabbit_fx = comp0_lines_opt.as_ref().map_or(false, |lines| {
            lines.iter().any(|l| l.contains("Resource\\RabbitFX\\Diffuse"))
        });

        if !has_rabbit_fx && hair_texture_files_to_fix.is_empty() {
            if self.ensure_hair_fallback_texture(ctx, false)? {
                ini_modified = true;
            }
        }

        Ok(ini_modified || hair_textures_modified)
    }

    /// Male Rover specific fix steps
    fn fix_rover_male(&self, ctx: &mut FixerContext, should_fix_hair_alpha: bool) -> Result<bool, FixerError> {
        let mut ini_modified = false;

        if self.adapt_rover_materialmaps(ctx)? {
            ini_modified = true;
        }

        let (_, hair_texture_files_to_fix) = self.collect_hair_textures(ctx);

        let hair_textures_modified =
            self.fix_hair_textures_alpha(ctx, &hair_texture_files_to_fix, should_fix_hair_alpha)?;

        let comp0_lines_opt = self.get_component0_lines(ctx);
        if comp0_lines_opt.is_none() {
            // If Component0 is missing, only handle fallback overrides and skip Component6 division
            let has_rabbit_fx = false;
            if !has_rabbit_fx && hair_texture_files_to_fix.is_empty() {
                if self.ensure_hair_fallback_texture(ctx, true)? {
                    ini_modified = true;
                }
            }
            return Ok(ini_modified || hair_textures_modified);
        }

        if ctx.ini.has_section("TextureOverrideComponent6") {
            return Ok(ini_modified || hair_textures_modified);
        }

        let mc_config_match_first_index = "144738";
        let mc_config_match_index_count = "32112";
        let mc_config_vg_offset = 139;
        let mc_config_vg_count = 24;

        debug!(
            "Detected hair split config (Component6): match_first_index={}, match_index_count={}",
            mc_config_match_first_index, mc_config_match_index_count
        );

        let comp0_lines = comp0_lines_opt.unwrap();
        let mut comp6_sec = IniSection::new("TextureOverrideComponent6");

        for line in &comp0_lines {
            let mut current = line.replace("$merge_status_id_0", "$merge_status_id_6");
            if RE_MATCH_FIRST_LINE.is_match(line) {
                let indent = self.get_indent(line);
                current = format!("{}match_first_index = {}", indent, mc_config_match_first_index);
            } else if RE_MATCH_COUNT_LINE.is_match(line) {
                let indent = self.get_indent(line);
                current = format!("{}match_index_count = {}", indent, mc_config_match_index_count);
            } else if RE_VG_OFFSET.is_match(line) {
                let indent = self.get_indent(line);
                current = format!("{}$\\WWMIv1\\vg_offset = {}", indent, mc_config_vg_offset);
            } else if RE_VG_COUNT.is_match(line) {
                let indent = self.get_indent(line);
                current = format!("{}$\\WWMIv1\\vg_count = {}", indent, mc_config_vg_count);
            }
            comp6_sec.lines.push(current);
        }

        let has_rabbit_fx = comp0_lines.iter().any(|l| l.contains("Resource\\RabbitFX\\Diffuse"));

        if !has_rabbit_fx && hair_texture_files_to_fix.is_empty() {
            self.ensure_hair_fallback_texture(ctx, true)?;
        }

        if !has_rabbit_fx {
            // Find the source override section that has hash = "e8349ade"
            let mut source_override_sec = None;
            for sec in &ctx.ini.sections {
                let sec_name_lower = sec.name.to_lowercase();
                if sec_name_lower.starts_with("textureoverride")
                    && !sec_name_lower.contains("component")
                    && !sec_name_lower.contains("shapekey")
                {
                    if let Some(h) = sec.get_value("hash") {
                        if h.trim().eq_ignore_ascii_case("e8349ade") {
                            source_override_sec = Some(sec);
                            break;
                        }
                    }
                }
            }

            if let Some(src_sec) = source_override_sec {
                let ps_t1_lines = src_sec.extract_control_flow_and_resources(|indent, key, val| {
                    if key.eq_ignore_ascii_case("this") {
                        Some(format!("{}ps-t1 = {}", indent, val))
                    } else {
                        None
                    }
                });

                if !ps_t1_lines.is_empty() {
                    let insert_idx = comp6_sec
                        .lines
                        .iter()
                        .position(|l| RE_HANDLING_SKIP.is_match(l))
                        .map(|idx| idx + 1)
                        .unwrap_or(comp6_sec.lines.len());

                    for (offset, line) in ps_t1_lines.into_iter().enumerate() {
                        comp6_sec.lines.insert(insert_idx + offset, line);
                    }
                }
            }
        }

        let mut last_comp_idx = None;
        let mut max_comp_id = -1;
        for (i, sec) in ctx.ini.sections.iter().enumerate() {
            if let Some(suffix) = sec.name.strip_prefix("TextureOverrideComponent") {
                if let Ok(comp_id) = suffix.parse::<i32>() {
                    if comp_id > max_comp_id {
                        max_comp_id = comp_id;
                        last_comp_idx = Some(i);
                    }
                }
            }
        }

        if let Some(idx) = last_comp_idx {
            info!(
                "Inserting new Component6 section after the last component section (Component{})",
                max_comp_id
            );
            ctx.ini.sections.insert(idx + 1, comp6_sec);
        } else {
            info!("No component section found, appending new Component6 section to the end of the file");
            ctx.ini.sections.push(comp6_sec);
        }

        let constants_sec = ctx.ini.add_section("Constants");
        if !constants_sec.has_key("global $merge_status_id_6") {
            constants_sec.set_key_value("global $merge_status_id_6", "0", "");
        }

        if let Some(skeleton_sec) = ctx.ini.get_section_mut("CommandListUpdateMergedSkeleton") {
            if !skeleton_sec.has_key("$merge_status_id_6") {
                skeleton_sec.prepend_key_value("$merge_status_id_6", "0", "    ");
            }
        }

        ini_modified = true;
        Ok(ini_modified || hair_textures_modified)
    }
}

impl Fixer for RoverFixer {
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let is_rover_male = ctx.char_name == "RoverMale";
        let is_rover_female = ctx.char_name == "RoverFemale";

        if !is_rover_male && !is_rover_female {
            return Ok(false);
        }

        // Define component filters precisely as requested
        let target_ids: HashSet<&str> = if is_rover_female {
            ["3", "4"].iter().cloned().collect()
        } else {
            ["2"].iter().cloned().collect()
        };

        // collect old hair hashes (id == 0, type == "D") AND old lightmap hashes ONLY for target IDs
        let mut hair_old_hashes = Vec::new();
        let mut old_lightmap_hashes = HashSet::new();

        for (_, node) in &ctx.config.textures {
            if let Some(meta) = &node.meta {
                if meta.id.contains(&0) && meta.type_ == "D" {
                    for old_h in &node.replace {
                        hair_old_hashes.push(old_h.to_lowercase());
                    }
                }
                let matches_target = meta.id.iter().any(|id| target_ids.contains(id.to_string().as_str()));
                if matches_target && meta.type_ == "L" {
                    for old_h in &node.replace {
                        old_lightmap_hashes.insert(old_h.to_lowercase());
                    }
                }
            }
        }

        let has_old_hair_hash = hair_old_hashes.iter().any(|oh| ctx.original_hashes.contains(oh));
        let has_old_lightmap_hash = old_lightmap_hashes.iter().any(|lh| ctx.original_hashes.contains(lh));

        let should_fix = has_old_hair_hash || has_old_lightmap_hash;

        // Skip execution if no triggers match and the fixer has already completed previously
        if !should_fix {
            let fallback_override_name = if is_rover_male {
                "TextureOverrideTextureRoverMaleHair"
            } else {
                "TextureOverrideTextureRoverFemaleHair"
            };
            if is_rover_male && ctx.ini.has_section("TextureOverrideComponent6") {
                return Ok(false);
            }
            if ctx.ini.has_section(fallback_override_name) {
                return Ok(false);
            }

            // collect expected Materialmap hashes (type == "M") to verify if they already exist
            let mut expected_materialmaps = Vec::new();
            for (base_hash, node) in &ctx.config.textures {
                if let Some(meta) = &node.meta {
                    if meta.type_ == "M" {
                        expected_materialmaps.push(base_hash.to_lowercase());
                    }
                }
            }

            let mut all_materialmaps_exist = true;
            for h in expected_materialmaps {
                let section_name = format!("TextureOverride_Replace_{}", h);
                if !ctx.ini.has_section(&section_name) {
                    all_materialmaps_exist = false;
                    break;
                }
            }
            if all_materialmaps_exist {
                return Ok(false);
            }
        }

        if is_rover_female {
            self.fix_rover_female(ctx, has_old_hair_hash)
        } else {
            self.fix_rover_male(ctx, has_old_hair_hash)
        }
    }
}
