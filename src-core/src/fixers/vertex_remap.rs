use crate::config_loader::VertexRemapConfig;
use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use crate::t;
use log::info;
use std::collections::HashSet;

pub struct VertexRemapFixer;

impl Fixer for VertexRemapFixer {
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        if ctx.char_name == "AemeathMecha" && !ctx.enable_fix_aemeath_mech {
            return Ok(false);
        }

        let vg_remaps = match &ctx.config.vg_remaps {
            Some(v) => v,
            None => return Ok(false),
        };

        let blend_matches = crate::collector::parse_resouce_buffer_path(
            ctx.original_content,
            crate::collector::BufferType::Blend,
            ctx.file_path,
        );
        if blend_matches.is_empty() {
            return Ok(false);
        }

        let use_merged = ctx.ini.has_section("ResourceMergedSkeleton");

        let multiple = blend_matches.len() > 1;
        let mut start_idx = None;
        for (i, vg) in vg_remaps.iter().enumerate() {
            if vg
                .trigger_hash
                .iter()
                .any(|h| ctx.original_hashes.contains(&h.to_lowercase()))
            {
                start_idx = Some(i);
                break;
            }
        }
        let start_idx = match start_idx {
            Some(idx) => idx,
            None => return Ok(false),
        };

        use crate::config_loader::RemapProvider;

        let temp_config = VertexRemapConfig::build_composite_remap(vg_remaps[start_idx..].iter());
        let has_vg = temp_config.vertex_groups.is_some();
        let has_comp = temp_config.component_remap.is_some();
        if !has_vg && !has_comp {
            return Ok(false);
        }

        let mut seen = HashSet::new();

        for (b_path, stride) in blend_matches {
            let canon = b_path.canonicalize().unwrap_or_else(|_| b_path.clone());
            if !seen.insert(canon) || !b_path.exists() {
                continue;
            }

            let fwd_path =
                crate::collector::combile_buf_path(&b_path, &crate::collector::BufferType::BlendRemapForward);
            let has_remap = fwd_path.exists();

            let mut b_data = std::fs::read(&b_path)?;
            let res = if use_merged {
                if ctx.char_name == "RoverMale" {
                    if let Some(vg) = &temp_config.vertex_groups {
                        let len = b_data.len();
                        let changed = temp_config.remapping_vertex_groups(&mut b_data, vg, 0, len, stride);
                        Ok(changed)
                    } else {
                        Ok(false)
                    }
                } else {
                    temp_config.apply_remap_merged(&mut b_data, ctx.original_content, stride)
                }
            } else {
                temp_config.apply_remap_component(&mut b_data, &b_path, ctx.original_content, multiple, stride)
            };

            if let Ok(true) = res {
                crate::utils::fs_utils::create_backup_once(&b_path, ctx.backed_up)?;
                std::fs::write(&b_path, &b_data)?;
                info!("{}", t!(remapped_successfully));
            }

            if has_remap {
                if let Some(vg_map) = &temp_config.vertex_groups {
                    let mut fwd = std::fs::read(&fwd_path)?;

                    VertexRemapConfig::remap_blend_remap_forward(&mut fwd, vg_map);

                    crate::utils::fs_utils::create_backup_once(&fwd_path, ctx.backed_up)?;
                    std::fs::write(&fwd_path, &fwd)?;

                    info!("WWMI BlendRemapForward chained-remapped successfully");
                }
            }
        }

        Ok(false)
    }
}
