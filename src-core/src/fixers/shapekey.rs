use crate::collector;
use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use crate::utils::fs_utils;
use crate::utils::regex_patterns::*;
use log::info;

pub struct ShapeKeyFixer;

impl Fixer for ShapeKeyFixer {
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let mut ini_modified = false;

        let config = match &ctx.config.shapekey_fix {
            Some(c) => c,
            None => return Ok(false),
        };

        let has_trigger = config
            .trigger_hash
            .iter()
            .any(|h| ctx.original_hashes.contains(&h.to_lowercase()));
        if !has_trigger {
            return Ok(false);
        }

        if let Some(rewrites) = &config.section_rewrites {
            for rw in rewrites {
                if ctx.ini.has_section(&rw.old_section) {
                    let mut dummy_doc = crate::utils::ini_parser::IniDocument::parse(&format!(
                        "[{}]\n{}",
                        rw.old_section, rw.new_content
                    ));
                    if let Some(sec) = dummy_doc.sections.pop() {
                        if let Some(target) = ctx.ini.get_section_mut(&rw.old_section) {
                            *target = sec;
                            ini_modified = true;
                        }
                    }
                }
            }
        }

        if let Some(array_val) = config.custom_values_array {
            if let Some(sec) = ctx.ini.get_section_mut("ResourceCustomShapeKeyValuesRW") {
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

        let offsets = collector::parse_resouce_buffer_path(
            ctx.original_content,
            collector::BufferType::ShapeKeyOffset,
            ctx.file_path,
        );
        let vertex_ids = collector::parse_resouce_buffer_path(
            ctx.original_content,
            collector::BufferType::ShapeKeyVertexId,
            ctx.file_path,
        );
        let vertex_offsets = collector::parse_resouce_buffer_path(
            ctx.original_content,
            collector::BufferType::ShapeKeyVertexOffset,
            ctx.file_path,
        );

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
            let id_bytes = std::fs::read(id_path)?;
            if fixer.needs_fix(id_bytes.len()) {
                let off_bytes = std::fs::read(offset_path)?;
                let val_bytes = std::fs::read(val_path)?;

                let result = fixer
                    .rebuild_buffers(&off_bytes, &id_bytes, &val_bytes)
                    .map_err(|e| FixerError::AnyhowError(anyhow::anyhow!(e)))?;

                // Inject batch constants
                if let Some(sec) = ctx.ini.get_section_mut("Constants") {
                    if !sec.has_key("global $shapekey_vertex_offset_batch0") {
                        sec.lines.push("global $shapekey_vertex_offset_batch0 = 0".to_string());
                        sec.lines.push(format!(
                            "global $shapekey_vertex_count_batch0 = {}",
                            result.batch0_count
                        ));
                        sec.lines.push(format!(
                            "global $shapekey_vertex_offset_batch1 = {}",
                            result.batch0_count
                        ));
                        sec.lines.push(format!(
                            "global $shapekey_vertex_count_batch1 = {}",
                            result.batch1_count
                        ));
                        ini_modified = true;
                    }
                }

                fs_utils::create_backup_once(offset_path, ctx.backed_up)?;
                fs_utils::create_backup_once(id_path, ctx.backed_up)?;
                fs_utils::create_backup_once(val_path, ctx.backed_up)?;

                std::fs::write(offset_path, result.offset_buf)?;
                std::fs::write(id_path, result.vertex_id_buf)?;
                std::fs::write(val_path, result.vertex_offset_buf)?;

                info!("Fixed batched shapekey buffers for {}", ctx.char_name);
            }
        }

        Ok(ini_modified)
    }
}
