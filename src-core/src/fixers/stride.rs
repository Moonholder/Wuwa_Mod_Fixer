use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use crate::utils::regex_patterns::*;
use log::info;

pub struct StrideFixer;

impl Fixer for StrideFixer {
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let stride_fix = match &ctx.config.stride_fix {
            Some(sf) => sf,
            None => return Ok(false),
        };

        let has_trigger_hash = stride_fix
            .trigger_hash
            .iter()
            .any(|h| ctx.original_hashes.contains(&h.to_lowercase()));

        if !has_trigger_hash {
            return Ok(false);
        }

        let mut modified = false;

        let mut fix_list = Vec::new();

        for section in &mut ctx.ini.sections {
            if RE_BLEND.is_match(&format!("[{}]\n", section.name)) {
                let mut needs_fix = false;
                for line in &mut section.lines {
                    if RE_STRIDE_8.is_match(line) {
                        let replaced = RE_STRIDE_8.replace(line, "stride = 16");
                        if replaced != *line {
                            *line = replaced.to_string();
                            needs_fix = true;
                            modified = true;
                        }
                    }
                }

                if needs_fix {
                    if let Some(filename) = section.get_value("filename") {
                        let filepath = ctx.file_path.parent().unwrap().join(filename.trim_matches('"'));
                        fix_list.push(filepath);
                    }
                }
            }
        }

        for path in fix_list {
            if path.exists() {
                let data = std::fs::read(&path)?;
                if data.len() % 8 == 0 {
                    // Check if it is really 8-byte stride data
                    crate::utils::fs_utils::create_backup_once(&path, ctx.backed_up)?;
                    let new_data = expand_blend_stride_to_16(&data);
                    std::fs::write(&path, new_data)?;
                    info!("Expanded blend stride to 16 for {}", path.display());
                }
            }
        }

        Ok(modified)
    }
}

fn expand_blend_stride_to_16(blend_data: &[u8]) -> Vec<u8> {
    let mut buf_data: Vec<u8> = Vec::with_capacity(blend_data.len() * 2);
    for chunk in blend_data.chunks_exact(8) {
        let (indices, weights) = chunk.split_at(4);
        buf_data.extend_from_slice(indices);
        buf_data.extend_from_slice(&[0u8; 4]);
        buf_data.extend_from_slice(weights);
        buf_data.extend_from_slice(&[0u8; 4]);
    }
    buf_data
}
