use crate::collector;
use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use crate::utils::fs_utils;
use log::{debug, info};

pub struct Rendering33Fixer;

impl Fixer for Rendering33Fixer {
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let texcoord_buffers =
            collector::parse_resource_buffer_path(ctx.original_content, collector::BufferType::TexCoord, ctx.file_path);
        let index_buffers =
            collector::parse_resource_buffer_path(ctx.original_content, collector::BufferType::Index, ctx.file_path);

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

        let mut texcoord_data = std::fs::read(texcoord_path)?;
        let index_data = std::fs::read(index_path)?;

        let comp_indices = collector::parse_component_indices(ctx.original_content);
        if comp_indices.is_empty() {
            return Ok(false);
        }

        let mut changed = false;

        let default_skip: Vec<u8> = vec![5];
        let skip_components = ctx.config.skip_components.as_ref().unwrap_or(&default_skip);

        for (conponent_no, (count, offset)) in comp_indices
            .into_iter()
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

                if ctx.enable_rendering33_fix {
                    if b4 == b5 && b6 == b7 {
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
                    }
                } else {
                    if b4 == 255 && b5 == 255 && b6 == 255 && b7 == 255 {
                        chunk[4] = 0;
                        chunk[5] = 0;
                        chunk[6] = 0;
                        chunk[7] = 0;
                        changed = true;
                    }
                }
            }
            if comp_changed {
                debug!("component: {}, mask: {:?}", conponent_no, unique_masks);
            }
        }

        if changed {
            fs_utils::create_backup_once(texcoord_path, ctx.backed_up)?;
            std::fs::write(texcoord_path, &texcoord_data)?;
            info!("Wuwa 3.3 Fix: Wiped garbage COLOR1 mask in {}", texcoord_path.display());
        }

        Ok(false)
    }
}
