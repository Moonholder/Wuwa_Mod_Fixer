// src-core/src/fixers/stride.rs

use std::path::PathBuf;

use log::info;

use crate::{
    domain::pipeline::{PipelineFixer, PipelineStage},
    errors::FixerError,
    fixers::traits::FixerContext,
};

pub struct StrideFixer;

impl PipelineFixer for StrideFixer {
    fn name(&self) -> &'static str {
        "StrideFixer"
    }

    fn stage(&self) -> PipelineStage {
        PipelineStage::MeshGated
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let stride_fix = match &ctx.config.stride_fix {
            Some(sf) => sf,
            None => return Ok(false),
        };

        let has_trigger_hash = stride_fix
            .trigger_hash
            .iter()
            .any(|h| ctx.original_hashes().contains(&h.to_lowercase()));

        if !has_trigger_hash {
            return Ok(false);
        }

        let base_dir = ctx
            .file_path()
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf();
        let mut fix_list: Vec<PathBuf> = Vec::new();
        let mut ini_modified = false;

        // Scan resource sections to update blend buffer stride from 8 to 16.
        for mut res_view in ctx.ini_mut().iter_resources_mut() {
            if res_view.is_blend_buffer() {
                if res_view.stride() == Some(8) {
                    if res_view.ensure_stride(16) {
                        ini_modified = true;
                    }
                    if let Some(path) = res_view.resolved_path(&base_dir) {
                        fix_list.push(path);
                    }
                }
            }
        }

        let mut modified = ini_modified;

        // Expand binary blend buffer payloads on disk.
        for path in fix_list {
            if path.exists() {
                let data = ctx.read_buffer(&path)?.to_vec();
                if data.len() % 8 == 0 {
                    let new_data = expand_blend_stride_to_16(&data);
                    ctx.write_buffer_bytes(&path, new_data);
                    info!("Expanded blend stride to 16 for {}", path.display());
                    modified = true;
                }
            }
        }

        if ini_modified {
            ctx.mark_ini_modified();
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
