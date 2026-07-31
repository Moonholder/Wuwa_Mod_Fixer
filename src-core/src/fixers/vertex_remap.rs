use crate::config_loader::VertexRemapConfig;
use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use crate::t;
use crate::utils::vertex_remap::remap_vertex_groups;
use crate::{collector, collector::BufferType};
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

        let blend_matches =
            collector::parse_resource_buffer_path(ctx.original_content, BufferType::Blend, ctx.file_path);
        if blend_matches.is_empty() {
            return Ok(false);
        }

        let start_idx = vg_remaps.iter().position(|vg| {
            vg.trigger_hash
                .iter()
                .any(|h| ctx.original_hashes.contains(&h.to_lowercase()))
        });
        let start_idx = match start_idx {
            Some(idx) => idx,
            None => return Ok(false),
        };

        let composite = VertexRemapConfig::build_composite_remap(vg_remaps[start_idx..].iter(), ctx.original_content);
        if composite.vertex_groups.is_none() && composite.component_remap.is_none() {
            return Ok(false);
        }

        let use_merged = ctx.ini.has_section("ResourceMergedSkeleton");
        let multiple = blend_matches.len() > 1;

        let fwd_remap_matches =
            collector::parse_resource_buffer_path(ctx.original_content, BufferType::BlendRemapForward, ctx.file_path);

        let global_vg_map = composite.vertex_groups.as_ref();

        let mut seen = HashSet::new();

        for (b_path, stride) in blend_matches {
            let stride = match stride {
                Some(s) => s,
                None => continue,
            };
            let canon = b_path.canonicalize().unwrap_or_else(|_| b_path.clone());
            if !seen.insert(canon) || !b_path.exists() {
                continue;
            }

            let b_index = collector::get_buf_path_index(&b_path);
            let fwd_entry = fwd_remap_matches
                .iter()
                .find(|(p, _)| collector::get_buf_path_index(p) == b_index);
            let has_fwd = fwd_entry.is_some_and(|(p, _)| p.exists());

            if has_fwd {
                if let Some(vg_map) = &global_vg_map {
                    let (fwd_path, _) = fwd_entry.unwrap();
                    let mut fwd_data = std::fs::read(fwd_path)?;

                    VertexRemapConfig::remap_blend_remap_forward(&mut fwd_data, vg_map);

                    crate::utils::fs_utils::create_backup_once(fwd_path, ctx.backed_up)?;
                    std::fs::write(fwd_path, &fwd_data)?;
                    info!(
                        "[BlendRemapForward] {}: {}",
                        t!(remapped_successfully),
                        fwd_path.display()
                    );
                }
            }

            if use_merged {
                if let Some(vg_map) = &global_vg_map {
                    let mut b_data = std::fs::read(&b_path)?;
                    let len = b_data.len();
                    let changed = remap_vertex_groups(&mut b_data, vg_map, 0, len, stride);
                    if changed {
                        crate::utils::fs_utils::create_backup_once(&b_path, ctx.backed_up)?;
                        std::fs::write(&b_path, &b_data)?;
                        info!("[MergedRemap] {}: {}", t!(remapped_successfully), b_path.display());
                    }
                }
            } else {
                if let Some(regions) = &composite.component_remap {
                    let index_path = collector::combine_buf_path(&b_path, &BufferType::Index);
                    let buf_index_opt = collector::get_buf_path_index(&b_path);
                    let mut comp_indices = if multiple || buf_index_opt.is_some() {
                        collector::parse_component_indices_with_multiple(
                            ctx.original_content,
                            buf_index_opt.unwrap_or("0"),
                        )
                    } else {
                        collector::parse_component_indices(ctx.original_content)
                    };
                    if comp_indices.is_empty() {
                        comp_indices = collector::parse_component_indices(ctx.original_content);
                    }

                    let index_data = std::fs::read(&index_path).map_err(|e| FixerError::IoError(e))?;
                    let mut b_data = std::fs::read(&b_path)?;
                    let mut applied = false;

                    for region in regions {
                        let ci = region.component_index;
                        if let Some(&(idx_count, idx_offset)) = comp_indices.get(&ci) {
                            let range = collector::get_byte_range_in_buffer(idx_count, idx_offset, &index_data, stride);
                            if let Ok((start, end)) = range {
                                if start < end && end <= b_data.len() {
                                    if remap_vertex_groups(&mut b_data, &region.indices, start, end, stride) {
                                        applied = true;
                                    }
                                }
                            }
                        } else {
                            log::warn!("Component {} not found in parsed indices", ci);
                        }
                    }

                    if applied {
                        crate::utils::fs_utils::create_backup_once(&b_path, ctx.backed_up)?;
                        std::fs::write(&b_path, &b_data)?;
                        info!("[ComponentRemap] {}: {}", t!(remapped_successfully), b_path.display());
                    }
                }
            }
        }

        Ok(false)
    }
}
