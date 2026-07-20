use crate::collector;
use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use crate::utils::fs_utils;
use log::info;

pub struct Rendering33Fixer;

impl Fixer for Rendering33Fixer {
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let color_buf_matches =
            collector::parse_resouce_buffer_path(ctx.original_content, collector::BufferType::Color, ctx.file_path);

        for (buf_path, stride) in color_buf_matches {
            if !buf_path.exists() || stride != 4 {
                continue;
            }

            let mut data = std::fs::read(&buf_path)?;
            let mut changed = false;

            for chunk in data.chunks_exact_mut(4) {
                if chunk[0] == 255 && chunk[1] == 255 && chunk[2] == 255 && chunk[3] == 255 {
                    chunk[0] = 0xFF; // 255
                    chunk[1] = 0xBC; // 188
                    chunk[2] = 0xBC; // 188
                    chunk[3] = 0x33; // 51
                    changed = true;
                }
            }

            if changed {
                fs_utils::create_backup_once(&buf_path, ctx.backed_up)?;
                std::fs::write(&buf_path, &data)?;
                info!("Wuwa 3.3 Fix: Updated default Color values in {}", buf_path.display());
            }
        }

        let texcoord_buf_matches =
            collector::parse_resouce_buffer_path(ctx.original_content, collector::BufferType::TexCoord, ctx.file_path);

        for (buf_path, stride) in texcoord_buf_matches {
            if !buf_path.exists() || stride != 16 {
                continue;
            }

            let mut data = std::fs::read(&buf_path)?;
            let mut changed = false;

            for chunk in data.chunks_exact_mut(16) {
                if chunk[4] == 255 && chunk[5] == 255 && chunk[6] == 255 && chunk[7] == 255 {
                    chunk[4] = 0;
                    chunk[5] = 0;
                    chunk[6] = 0;
                    chunk[7] = 0;
                    changed = true;
                }
            }

            if changed {
                fs_utils::create_backup_once(&buf_path, ctx.backed_up)?;
                std::fs::write(&buf_path, &data)?;
                info!("Wuwa 3.3 Fix: Wiped garbage COLOR1 mask in {}", buf_path.display());
            }
        }

        Ok(false)
    }
}
