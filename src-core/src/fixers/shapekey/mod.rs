//! Shapekey pipeline fixer and unified subsystem facade.
pub mod partition;
pub mod rebuilder;
pub mod surface;
pub mod transplant;

use log::info;
pub use partition::*;
pub use rebuilder::*;
pub use surface::*;
pub use transplant::*;

use crate::{
    collector,
    domain::pipeline::{PipelineFixer, PipelineStage},
    errors::FixerError,
    fixers::traits::FixerContext,
    utils::regex_patterns::*,
};

pub struct ShapeKeyFixer;

impl PipelineFixer for ShapeKeyFixer {
    fn name(&self) -> &'static str {
        "ShapeKeyFixer"
    }

    fn stage(&self) -> PipelineStage {
        PipelineStage::MeshGated
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let mut ini_modified = false;

        let config = match &ctx.config.shapekey_fix {
            Some(c) => c,
            None => return Ok(false),
        };

        let has_trigger = config
            .trigger_hash
            .iter()
            .any(|h| ctx.original_hashes().contains(&h.to_lowercase()));
        if !has_trigger {
            return Ok(false);
        }

        if let Some(rewrites) = &config.section_rewrites {
            for rw in rewrites {
                let mut rewritten = ctx.ini_mut().rewrite_section_content(&rw.old_section, &rw.new_content);
                if !rewritten {
                    let batch_alias = if rw.old_section.ends_with("Batch") {
                        rw.old_section.strip_suffix("Batch").unwrap().to_string()
                    } else {
                        format!("{}Batch", rw.old_section)
                    };
                    if ctx.ini_mut().rewrite_section_content(&batch_alias, &rw.new_content) {
                        rewritten = true;
                    }
                }
                if rewritten {
                    ini_modified = true;
                }
            }
        }

        if let Some(array_val) = config.custom_values_array {
            if let Some(sec) = ctx.ini_mut().get_section_mut("ResourceCustomShapeKeyValuesRW") {
                for line in &mut sec.lines {
                    if RE_ARRAY_VAL.is_match(line) {
                        let replaced = RE_ARRAY_VAL.replace(line, format!("${{1}}{}", array_val));
                        if replaced != *line {
                            *line = replaced.to_string();
                            ini_modified = true;
                        }
                    }
                }
            }
        }

        if ini_modified {
            // Ensure Constants block defines all multi-batch variables even for INI-only mods.
            let mut consts_view = ctx.ini_mut().ensure_constants();
            if !consts_view.has_global("$shapekey_vertex_offset_batch0") {
                consts_view.set_global("$shapekey_vertex_offset_batch0", "0");
            }
            if !consts_view.has_global("$shapekey_vertex_count_batch0") {
                let fallback = consts_view
                    .get_global("$shapekey_vertex_count")
                    .unwrap_or_else(|| "0".to_string());
                consts_view.set_global("$shapekey_vertex_count_batch0", &fallback);
            }
            if !consts_view.has_global("$shapekey_vertex_offset_batch1") {
                let b0_count = consts_view
                    .get_global("$shapekey_vertex_count_batch0")
                    .unwrap_or_else(|| "0".to_string());
                consts_view.set_global("$shapekey_vertex_offset_batch1", &b0_count);
            }
            if !consts_view.has_global("$shapekey_vertex_count_batch1") {
                consts_view.set_global("$shapekey_vertex_count_batch1", "0");
            }

            ctx.mark_ini_modified();
        }

        let offsets = ctx.collect_resource_buffers(collector::BufferType::ShapeKeyOffset);
        let vertex_ids = ctx.collect_resource_buffers(collector::BufferType::ShapeKeyVertexId);
        let vertex_offsets = ctx.collect_resource_buffers(collector::BufferType::ShapeKeyVertexOffset);

        if offsets.is_empty() || vertex_ids.is_empty() || vertex_offsets.is_empty() {
            return Ok(ini_modified);
        }

        let (offset_path, _) = &offsets[0];
        let (id_path, _) = &vertex_ids[0];
        let (val_path, _) = &vertex_offsets[0];

        if !offset_path.exists() || !id_path.exists() || !val_path.exists() {
            return Ok(ini_modified);
        }

        if let Some(mut fixer) = ShapeKeyRebuilder::new(config, ctx.char_name) {
            let custom_shapekeys = collector::parse_custom_shapekey_ids(&ctx.ini().to_string());
            fixer.set_custom_shapekeys(custom_shapekeys);
            let off_bytes = ctx.read_buffer(offset_path)?.to_vec();
            let id_bytes = ctx.read_buffer(id_path)?.to_vec();
            let val_bytes = ctx.read_buffer(val_path)?.to_vec();

            let layout = ShapeKeyLayout::detect(&off_bytes);
            if fixer.needs_fix(&off_bytes) {
                let positions = ctx.collect_resource_buffers(collector::BufferType::Position);
                let pos_path = positions.first().map(|(p, _)| p.clone()).or_else(|| {
                    offset_path
                        .parent()
                        .map(|p| p.join("Position.buf"))
                        .filter(|p| p.exists())
                });
                let pos_bytes = match &pos_path {
                    Some(p) if p.exists() => ctx.read_buffer(p).ok().map(|s| s.to_vec()),
                    _ => None,
                };

                let index_buffers = ctx.collect_resource_buffers(collector::BufferType::Index);
                let index_bytes = index_buffers
                    .first()
                    .and_then(|(p, _)| ctx.read_buffer(p).ok())
                    .map(|s| s.to_vec());

                let texcoord_buffers = ctx.collect_resource_buffers(collector::BufferType::TexCoord);
                let tc_bytes = texcoord_buffers
                    .first()
                    .and_then(|(p, _)| ctx.read_buffer(p).ok())
                    .map(|s| s.to_vec());

                let partition = partition::extract_component_partition(
                    ctx,
                    index_bytes.as_deref(),
                    tc_bytes.as_deref(),
                );

                let result = fixer
                    .rebuild_buffers_partitioned(
                        &off_bytes,
                        &id_bytes,
                        &val_bytes,
                        pos_bytes.as_deref(),
                        partition.as_ref(),
                    )
                    .map_err(|e| FixerError::AnyhowError(anyhow::anyhow!(e)))?;

                if let (Some(part), Some(pos), Some(path), Some(ib), Some(reference)) =
                    (&partition, &pos_bytes, &pos_path, &index_bytes, &config.reference_asset)
                {
                    let face = match ctx.char_name {
                        "RoverFemale" | "FRoverSkin1" => Some((2, 5)),
                        "RoverMale" | "MRoverSkin1" => Some((1, 4)),
                        _ => None,
                    };
                    if let (Some((face, eyes)), Ok(asset)) = (face, transplant::load_asset(reference)) {
                        // The rebuilt AA field carries the upper/lower identity,
                        // including when the input was historically converted.
                        let mut aligned = part.clone();
                        if result.offset_buf.len() >= 184 {
                            let start = u32::from_le_bytes(result.offset_buf[176..180].try_into().unwrap()) as usize;
                            let end = u32::from_le_bytes(result.offset_buf[180..184].try_into().unwrap()) as usize;
                            if let (Some(ids), Some(vals)) = (
                                result.vertex_id_buf.get(start * 4..end * 4),
                                result.vertex_offset_buf.get(start * 12..end * 12),
                            ) {
                                aligned = part.with_mouth_motion(ids, vals);
                            }
                        }

                        let mut corrected = pos.clone();
                        let mut head_shift = [0.0f32; 3];
                        let mut color_include_face = true;
                        if let Some(map) =
                            transplant::transfer_legacy_surface(&asset, pos, &aligned, face, eyes)
                        {
                            head_shift = map.head_shift;
                            color_include_face = !map.uv_untrusted || map.uv_coverage >= 0.50;
                            let (lips, teeth) = surface::repair_mouth_rest(
                                &asset,
                                &map,
                                &aligned,
                                ib,
                                &mut corrected,
                                face,
                            );
                            if corrected != *pos {
                                ctx.write_buffer_bytes(path, corrected.clone());
                                info!("Aligned Rover neutral mouth: {lips} lip vertices, {teeth} rigid tooth vertices");
                            }
                        }

                        // Restore official face and tooth vertex colors (outline suppression masks,
                        // oral cavity tone masks, and ambient cavity shading).
                        // Crucial for idempotency: pass &corrected so spatial distances match on the 1st run.
                        let color_buffers = ctx.collect_resource_buffers(collector::BufferType::Color);
                        if let Some((color_path, stride)) = color_buffers.first() {
                            if stride.is_none_or(|s| s == 4) && color_path.exists() {
                                let mut colors = ctx.read_buffer(color_path)?.to_vec();
                                let mut changed = 0;
                                if !asset.colors.is_empty() {
                                    let candidates: Vec<u32> = if color_include_face {
                                        part.face_candidates
                                            .iter()
                                            .chain(&part.teeth_candidates)
                                            .copied()
                                            .collect()
                                    } else {
                                        part.teeth_candidates.clone()
                                    };
                                    changed = surface::repair_face_color_aligned(
                                        &asset,
                                        &corrected,
                                        &part.texcoords,
                                        &candidates,
                                        face,
                                        head_shift,
                                        &mut colors,
                                    );
                                }
                                if changed == 0 && ctx.char_name == "MRoverSkin1" {
                                    changed = surface::repair_skin_tooth_red(
                                        &mut colors,
                                        &part.texcoords,
                                        &part.teeth_candidates,
                                    );
                                }
                                if changed > 0 {
                                    ctx.write_buffer_bytes(color_path, colors);
                                    info!("Restored official face color mask on {changed} vertices");
                                }
                            }
                        }

                        if ctx.char_name == "MRoverSkin1" {
                            let components = collector::parse_component_indices(&ctx.ini().to_string());
                            if let Some(&(count, start)) = components.get(&0) {
                                if let Some(raw) = ib.get(start * 4..(start + count) * 4) {
                                    let mut hair: Vec<u32> = raw
                                        .chunks_exact(4)
                                        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                                        .collect();
                                    hair.sort_unstable();
                                    hair.dedup();
                                    let buffers = ctx.collect_resource_buffers(collector::BufferType::Vector);
                                    if let Some((path, stride)) = buffers.first() {
                                        if stride.is_none_or(|s| s == 8) && path.exists() {
                                            let mut vectors = ctx.read_buffer(path)?.to_vec();
                                            let changed = surface::repair_hair_frame(
                                                &asset,
                                                &corrected,
                                                &part.texcoords,
                                                &hair,
                                                &mut vectors,
                                            );
                                            if changed > 0 {
                                                ctx.write_buffer_bytes(path, vectors);
                                                info!("Restored official hair tangent frame on {changed} vertices");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // A modern layout is authoritative: its own offset table describes
                // every channel, so the rebuild only ever *completes* channels that
                // are stubs in the mod. When nothing was completed the payload must
                // stay byte-identical and no file is touched.
                let payload_changed = result.offset_buf != off_bytes
                    || result.vertex_id_buf != id_bytes
                    || result.vertex_offset_buf != val_bytes;
                if layout.is_modern() && !payload_changed {
                    info!(
                        "Shapekey buffers of {} need no channel completion, left untouched",
                        ctx.char_name
                    );
                } else {
                    // Synchronize the mod-owned layout constants with the rebuilt buffers.
                    let mut consts_view = ctx.ini_mut().ensure_constants();
                    consts_view.set_global("$shapekey_vertex_offset_batch0", "0");
                    consts_view.set_global("$shapekey_vertex_count_batch0", &result.batch0_count.to_string());
                    consts_view.set_global("$shapekey_vertex_offset_batch1", &result.batch0_count.to_string());
                    consts_view.set_global("$shapekey_vertex_count_batch1", &result.batch1_count.to_string());

                    ctx.write_buffer_bytes(offset_path, result.offset_buf);
                    ctx.write_buffer_bytes(id_path, result.vertex_id_buf);
                    ctx.write_buffer_bytes(val_path, result.vertex_offset_buf);

                    info!("Rebuilt shapekey buffers for {}", ctx.char_name);
                    ini_modified = true;
                }
            }
        }

        if ini_modified {
            ctx.mark_ini_modified();
        }

        Ok(ini_modified)
    }
}
