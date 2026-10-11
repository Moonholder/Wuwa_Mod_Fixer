use log::{debug, info};

use crate::{
    collector,
    domain::pipeline::{PipelineFixer, PipelineStage},
    errors::FixerError,
    fixers::traits::FixerContext,
};

pub struct Rendering33Fixer;

impl PipelineFixer for Rendering33Fixer {
    fn name(&self) -> &'static str {
        "Rendering33Fixer"
    }

    fn stage(&self) -> PipelineStage {
        PipelineStage::MeshGated
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let texcoord_buffers = ctx.collect_resource_buffers(collector::BufferType::TexCoord);
        let index_buffers = ctx.collect_resource_buffers(collector::BufferType::Index);

        if texcoord_buffers.is_empty() || index_buffers.is_empty() {
            return Ok(false);
        }

        let (texcoord_path, tc_stride) = &texcoord_buffers[0];
        let (index_path, _) = &index_buffers[0];

        let tc_stride = match tc_stride {
            Some(s) => *s,
            None => return Ok(false),
        };

        if !texcoord_path.exists() || !index_path.exists() || tc_stride != 16 {
            return Ok(false);
        }

        let comp_indices = ctx.component_indices().clone();
        if comp_indices.is_empty() {
            return Ok(false);
        }

        let default_skip: Vec<u8> = vec![5];
        let skip_components = ctx.config.skip_components.clone().unwrap_or(default_skip);
        let enable_r33 = ctx.mod_ctx.enable_rendering33_fix;

        let index_data = ctx.read_buffer(index_path)?.to_vec();

        // Check for invalid COLOR1 vertex mask attributes.
        let read_tc = ctx.read_buffer(texcoord_path)?;
        let mut needs_fix = false;

        for (_conponent_no, &(count, offset)) in comp_indices
            .iter()
            .filter(|(comp_id, _)| !skip_components.contains(comp_id))
        {
            let (start_byte, end_byte) =
                match collector::get_byte_range_in_buffer(count, offset, &index_data, tc_stride) {
                    Ok(range) => range,
                    Err(_) => continue,
                };

            if end_byte > read_tc.len() {
                continue;
            }

            let slice = &read_tc[start_byte..end_byte];
            for chunk in slice.chunks_exact(tc_stride) {
                let b4 = chunk[4];
                let b5 = chunk[5];
                let b6 = chunk[6];
                let b7 = chunk[7];

                if enable_r33 {
                    if b4 != 0 || b6 != 0 {
                        needs_fix = true;
                        break;
                    }
                } else if b4 == 255 && b5 == 255 && b6 == 255 && b7 == 255 {
                    needs_fix = true;
                    break;
                }
            }
            if needs_fix {
                break;
            }
        }

        if !needs_fix {
            return Ok(false);
        }

        // Clear invalid mask bytes in place.
        let mut changed = false;
        let tc_path_clone = texcoord_path.clone();
        let texcoord_data = ctx.get_buffer_mut(&tc_path_clone)?;

        for (&conponent_no, &(count, offset)) in comp_indices
            .iter()
            .filter(|(comp_id, _)| !skip_components.contains(comp_id))
        {
            let (start_byte, end_byte) =
                match collector::get_byte_range_in_buffer(count, offset, &index_data, tc_stride) {
                    Ok(range) => range,
                    Err(_) => continue,
                };

            if end_byte > texcoord_data.len() {
                continue;
            }

            let mut comp_changed = false;
            let mut_slice = &mut texcoord_data[start_byte..end_byte];
            let mut unique_masks = std::collections::HashSet::new();
            for chunk in mut_slice.chunks_exact_mut(tc_stride) {
                let b4 = chunk[4];
                let b5 = chunk[5];
                let b6 = chunk[6];
                let b7 = chunk[7];

                if enable_r33 {
                    if b4 != 0 || b6 != 0 {
                        chunk[4] = 0;
                        chunk[5] = 0;
                        chunk[6] = 0;
                        chunk[7] = 0;
                        changed = true;
                        comp_changed = true;
                        if unique_masks.len() < 20 {
                            unique_masks.insert([b4, b5, b6, b7]);
                        }
                    }
                } else if b4 == 255 && b5 == 255 && b6 == 255 && b7 == 255 {
                    chunk[4] = 0;
                    chunk[5] = 0;
                    chunk[6] = 0;
                    chunk[7] = 0;
                    changed = true;
                }
            }
            if comp_changed {
                debug!("component: {}, mask: {:?}", conponent_no, unique_masks);
            }
        }

        if changed {
            info!(
                "Render Pipeline Fix: Wiped invalid COLOR1 vertex mask in {}",
                tc_path_clone.display()
            );
        }

        Ok(changed)
    }
}
