use log::info;

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

        if let Some(fixer) = crate::shapekey_fixer::ShapeKeyFixer::new(config, ctx.char_name) {
            let off_bytes = ctx.read_buffer(offset_path)?.to_vec();
            if fixer.needs_fix(&off_bytes) {
                let id_bytes = ctx.read_buffer(id_path)?.to_vec();
                let val_bytes = ctx.read_buffer(val_path)?.to_vec();

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

                let result = fixer
                    .rebuild_buffers(&off_bytes, &id_bytes, &val_bytes, pos_bytes.as_deref())
                    .map_err(|e| FixerError::AnyhowError(anyhow::anyhow!(e)))?;

                // Synchronize Constants values with the reconstructed vertex buffer counts.
                let mut consts_view = ctx.ini_mut().ensure_constants();
                consts_view.set_global("$shapekey_vertex_offset_batch0", "0");
                consts_view.set_global("$shapekey_vertex_count_batch0", &result.batch0_count.to_string());
                consts_view.set_global("$shapekey_vertex_offset_batch1", &result.batch0_count.to_string());
                consts_view.set_global("$shapekey_vertex_count_batch1", &result.batch1_count.to_string());

                ctx.write_buffer_bytes(offset_path, result.offset_buf);
                ctx.write_buffer_bytes(id_path, result.vertex_id_buf);
                ctx.write_buffer_bytes(val_path, result.vertex_offset_buf);

                info!("Fixed batched shapekey buffers for {}", ctx.char_name);
                ini_modified = true;
            }
        }

        if ini_modified {
            ctx.mark_ini_modified();
        }

        Ok(ini_modified)
    }
}
