use std::collections::HashSet;

use log::info;

use crate::{
    collector,
    collector::BufferType,
    config_loader::VertexRemapConfig,
    domain::pipeline::{PipelineFixer, PipelineStage},
    errors::FixerError,
    fixers::traits::FixerContext,
    t,
    utils::vertex_remap::remap_vertex_groups,
};

pub struct VertexRemapFixer;

impl PipelineFixer for VertexRemapFixer {
    fn name(&self) -> &'static str {
        "VertexRemapFixer"
    }

    fn stage(&self) -> PipelineStage {
        PipelineStage::MeshGated
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        if ctx.char_name == "AemeathMecha" && !ctx.mod_ctx.enable_fix_aemeath_mech {
            return Ok(false);
        }

        let vg_remaps = match &ctx.config.vg_remaps {
            Some(v) => v,
            None => return Ok(false),
        };

        let blend_matches = ctx.collect_resource_buffers(BufferType::Blend);
        if blend_matches.is_empty() {
            return Ok(false);
        }

        let start_idx = vg_remaps.iter().position(|vg| {
            vg.trigger_hash
                .iter()
                .any(|h| ctx.original_hashes().contains(&h.to_lowercase()))
        });
        let start_idx = match start_idx {
            Some(idx) => idx,
            None => return Ok(false),
        };

        let content = ctx.original_content().to_string();
        let composite = VertexRemapConfig::build_composite_remap(vg_remaps[start_idx..].iter(), &content);
        if composite.vertex_groups.is_none() && composite.component_remap.is_none() {
            return Ok(false);
        }

        let use_merged = ctx.ini().has_section("ResourceMergedSkeleton");
        let multiple = blend_matches.len() > 1;

        let fwd_remap_matches = ctx.collect_resource_buffers(BufferType::BlendRemapForward);

        let global_vg_map = composite.vertex_groups.as_ref();

        let mut seen = HashSet::new();
        let mut any_modified = false;

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

            if let Some((fwd_path, _)) = fwd_entry {
                if fwd_path.exists() {
                    if let Some(vg_map) = &global_vg_map {
                        let fwd_path_clone = fwd_path.clone();
                        let mut fwd_data = ctx.read_buffer(&fwd_path_clone)?.to_vec();

                        let changed = VertexRemapConfig::remap_blend_remap_forward(&mut fwd_data, vg_map);
                        if changed {
                            ctx.write_buffer_bytes(&fwd_path_clone, fwd_data);
                            any_modified = true;
                            info!(
                                "[BlendRemapForward] {}: {}",
                                t!(remapped_successfully),
                                fwd_path_clone.display()
                            );
                        }
                    }
                }
            }

            if use_merged {
                if let Some(vg_map) = &global_vg_map {
                    let b_path_clone = b_path.clone();
                    let mut b_data = ctx.read_buffer(&b_path_clone)?.to_vec();
                    let len = b_data.len();
                    let changed = remap_vertex_groups(&mut b_data, vg_map, 0, len, stride);
                    if changed {
                        ctx.write_buffer_bytes(&b_path_clone, b_data);
                        any_modified = true;
                        info!(
                            "[MergedRemap] {}: {}",
                            t!(remapped_successfully),
                            b_path_clone.display()
                        );
                    }
                }
            } else {
                if let Some(regions) = &composite.component_remap {
                    let index_path = collector::combine_buf_path(&b_path, &BufferType::Index);
                    let buf_index_opt = collector::get_buf_path_index(&b_path);
                    let comp_indices = if multiple || buf_index_opt.is_some() {
                        let parsed =
                            collector::parse_component_indices_with_multiple(&content, buf_index_opt.unwrap_or("0"));
                        if parsed.is_empty() {
                            ctx.component_indices().clone()
                        } else {
                            parsed
                        }
                    } else {
                        ctx.component_indices().clone()
                    };

                    let index_data = ctx.read_buffer(&index_path)?.to_vec();
                    let b_path_clone = b_path.clone();
                    let mut b_data = ctx.read_buffer(&b_path_clone)?.to_vec();
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
                        ctx.write_buffer_bytes(&b_path_clone, b_data);
                        any_modified = true;
                        info!(
                            "[ComponentRemap] {}: {}",
                            t!(remapped_successfully),
                            b_path_clone.display()
                        );
                    }
                }
            }
        }

        Ok(any_modified)
    }
}
