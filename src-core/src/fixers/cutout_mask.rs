// src-core/src/fixers/cutout_mask.rs

use std::{collections::HashSet, path::Path};

use log::info;

use crate::{
    domain::cst::{IniCstDocument, IniCstSection},
    errors::FixerError,
    fixers::traits::FixerContext,
};

const WHITE_PNG_BYTES: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0xF3, 0xFF, 0x61, 0x00, 0x00, 0x00, 0x1D, 0x49,
    0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0xFC, 0xFF, 0xFF, 0xFF, 0x7F, 0x06, 0x0A, 0x00, 0x13, 0x25, 0x9A, 0x47, 0x0D,
    0x18, 0x35, 0x60, 0xD4, 0x80, 0xC1, 0x64, 0x00, 0x00, 0x6B, 0xCA, 0x04, 0x1C, 0xCB, 0xBA, 0x67, 0x49, 0x00, 0x00,
    0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
];

pub struct CutoutMaskFixer;

impl CutoutMaskFixer {
    /// Ensures fallback mask texture asset and corresponding [Resource] section exist.
    /// Returns (resource_name, ini_modified, file_created).
    fn ensure_white_mask_resource(
        &self,
        ctx: &mut FixerContext,
        res_name: &str,
        filename: &str,
    ) -> Result<(String, bool, bool), FixerError> {
        let mod_dir = ctx.file_path().parent().unwrap_or_else(|| Path::new("."));
        let file_path = crate::utils::fs_utils::resolve_relative_path(mod_dir, filename)
            .unwrap_or_else(|| mod_dir.join("Textures/White.png"));

        let mut file_created = false;
        if let Some(parent) = file_path.parent() {
            if !parent.exists() {
                let _ = std::fs::create_dir_all(parent);
            }
        }

        if !file_path.exists() {
            ctx.backup_new_file(&file_path)?;
            std::fs::write(&file_path, WHITE_PNG_BYTES).map_err(FixerError::IoError)?;
            file_created = true;
        }

        let clean_filename = filename
            .trim()
            .trim_matches('"')
            .trim_start_matches(|c| c == '/' || c == '\\');
        let mut res_view = ctx.ini_mut().ensure_resource(res_name);
        let mut ini_changed = false;
        if res_view.filename().as_deref() != Some(clean_filename) {
            res_view.set_filename(clean_filename);
            ini_changed = true;
        }

        Ok((res_name.to_string(), ini_changed, file_created))
    }

    /// Collects all resource names backed by existing files on disk.
    fn collect_valid_resources(ini: &IniCstDocument, base_dir: &Path) -> HashSet<String> {
        let mut valid = HashSet::new();
        for sec in &ini.sections {
            if let Some(fname) = sec.get_unquoted_value("filename") {
                if let Some(path) = crate::utils::fs_utils::resolve_relative_path(base_dir, &fname) {
                    if path.exists() {
                        valid.insert(sec.name.to_lowercase());
                    }
                }
            }
        }
        valid
    }

    /// Validates whether a resource reference points to an existing file.
    #[inline]
    fn is_resource_reference_valid(res_ref: &str, valid_resources: &HashSet<String>) -> bool {
        let clean = res_ref.trim().trim_matches('"');
        let clean = clean.strip_prefix("ref ").unwrap_or(clean).trim().trim_matches('"');
        let lower = clean.to_lowercase();
        if lower.is_empty() || lower == "null" || lower == "none" || lower == "0" {
            return false;
        }
        valid_resources.contains(&lower)
    }
}

impl crate::domain::pipeline::PipelineFixer for CutoutMaskFixer {
    fn name(&self) -> &'static str {
        "CutoutMaskFixer"
    }

    fn stage(&self) -> crate::domain::pipeline::PipelineStage {
        crate::domain::pipeline::PipelineStage::MeshGated
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let mask_rules = match &ctx.config.fallback_masks {
            Some(rules) if !rules.is_empty() => rules,
            _ => return Ok(false),
        };

        let base_dir = ctx.file_path().parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
        let mut valid_resources = Self::collect_valid_resources(ctx.ini(), &base_dir);
        let mut ini_modified = false;
        let mut any_work_done = false;

        for rule in mask_rules {
            let hash_key = &rule.hash;
            let node = ctx.config.textures.get(hash_key);
            let mut all_mask_hashes = HashSet::new();
            all_mask_hashes.insert(hash_key.to_lowercase());

            if let Some(n) = node {
                for rep in &n.replace {
                    all_mask_hashes.insert(rep.to_lowercase());
                }
                for derive_hashes in n.derive.values() {
                    for h in derive_hashes {
                        all_mask_hashes.insert(h.to_lowercase());
                    }
                }
            }

            // Find sections matching target mask hash or derived variants.
            let matching_indices = ctx
                .ini()
                .find_section_indices(|sec| sec.matches_any_texture_hash(&all_mask_hashes));

            if matching_indices.is_empty() {
                // Inject fallback mask override when section is missing.
                let (white_res, res_ini_changed, file_created) =
                    self.ensure_white_mask_resource(ctx, &rule.resource_name, &rule.filename)?;
                if res_ini_changed {
                    ini_modified = true;
                }
                if file_created || res_ini_changed {
                    any_work_done = true;
                }
                valid_resources.insert(white_res.to_lowercase());

                let target_sec_name = format!("TextureOverride_Replace_{}", hash_key);
                if !ctx.ini().has_section(&target_sec_name) {
                    let mut new_sec = IniCstSection::new(&target_sec_name);
                    let mut ovr_view = new_sec.as_texture_override_view_mut();
                    ovr_view.set_hash(hash_key);
                    ovr_view.set_match_priority("0");
                    ovr_view.set_object_detected_this(&white_res);

                    let anchor_name = ctx.ini().iter_texture_overrides().last().map(|s| s.name.clone());
                    let inserted = if let Some(anchor) = anchor_name {
                        ctx.ini_mut().insert_section_after(&anchor, new_sec.clone())
                    } else {
                        false
                    };

                    if !inserted {
                        ctx.ini_mut().sections.push(new_sec);
                    }

                    ini_modified = true;
                    any_work_done = true;
                    info!("Auto-injected adjacent fallback mask override for hash {}", hash_key);
                }
            } else {
                // Validate and fix invalid texture references in existing sections.
                for &sec_idx in &matching_indices {
                    let all_this = ctx.ini().sections[sec_idx].get_all_values("this");
                    let has_invalid_this = all_this.is_empty()
                        || all_this
                            .iter()
                            .any(|v| !Self::is_resource_reference_valid(v, &valid_resources));

                    if has_invalid_this {
                        let (white_res, _, _) =
                            self.ensure_white_mask_resource(ctx, &rule.resource_name, &rule.filename)?;
                        valid_resources.insert(white_res.to_lowercase());

                        let sec_mut: &mut IniCstSection = &mut ctx.ini_mut().sections[sec_idx];
                        let mut cf = sec_mut.to_control_flow();
                        let mut replaced_any = false;

                        cf.transform_resource_bindings(|key, val| {
                            if key.eq_ignore_ascii_case("this")
                                && !Self::is_resource_reference_valid(val, &valid_resources)
                            {
                                replaced_any = true;
                                Some(white_res.clone())
                            } else {
                                None
                            }
                        });

                        if !replaced_any && all_this.is_empty() {
                            let mut ovr_view = sec_mut.as_texture_override_view_mut();
                            ovr_view.set_object_detected_this(&white_res);
                        } else {
                            sec_mut.apply_control_flow(&cf);
                        }
                        ini_modified = true;
                        any_work_done = true;

                        info!(
                            "Corrected invalid cutout mask in section [{}]",
                            ctx.ini().sections[sec_idx].name
                        );
                    }
                }
            }
        }

        if ini_modified {
            ctx.mark_ini_modified();
        }

        Ok(any_work_done)
    }
}
