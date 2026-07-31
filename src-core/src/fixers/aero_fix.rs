use anyhow::anyhow;
use log::{debug, info, warn};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::collector;
use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use crate::t;
use crate::utils::{fs_utils, ini_parser};

pub struct AeroFixer;

impl Fixer for AeroFixer {
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let mut modified = false;

        let aero_mode: u8 = if ctx.char_name == "RoverFemale" {
            ctx.aero_fix_mode
        } else {
            0
        };

        if aero_mode == 1 {
            // TexCoord override
            let texcoord_mod =
                self.fix_aero_rover_female_eyes_with_texcoord(ctx.file_path, ctx.original_content, ctx.backed_up)?;

            if texcoord_mod {
                info!("{}", t!(aero_rover_female_eyes_fixed));
            } else {
                info!("TexCoord fix did not apply (component 5 not found)");
            }
        } else if aero_mode == 2 {
            // Texture mirror flip
            let texture_section_added = self.fix_aero_rover_female_eyes_with_texture(ctx.file_path, ctx)?;
            modified |= texture_section_added;
            info!("{}", t!(aero_rover_female_eyes_fixed));
        }

        Ok(modified)
    }
}

impl AeroFixer {
    fn fix_aero_rover_female_eyes_with_texcoord(
        &self,
        ini_path: &Path,
        content: &str,
        backed_up: &mut HashSet<PathBuf>,
    ) -> Result<bool, FixerError> {
        let component_indices = collector::parse_component_indices(content);
        if !component_indices.contains_key(&5) {
            return Ok(false);
        }

        let &(index_count, index_offset) = component_indices
            .get(&5)
            .ok_or_else(|| anyhow!("Failed to find component indices"))?;

        let texcoord_buf_matches =
            collector::parse_resource_buffer_path(content, collector::BufferType::TexCoord, ini_path);

        let mut ret = false;

        for (tex_coord_path, stride) in texcoord_buf_matches {
            let stride = match stride {
                Some(s) => s,
                None => continue,
            };
            if !tex_coord_path.exists() {
                continue;
            }

            let index_path = collector::combine_buf_path(&tex_coord_path, &collector::BufferType::Index);

            let index_data = std::fs::read(index_path)?;

            let (start, end) = collector::get_byte_range_in_buffer(index_count, index_offset, &index_data, stride)
                .map_err(|e| anyhow!("Failed to get byte range in buffer: {}", e))?;

            let fixed_data = include_bytes!("../resources/FRoverC5_TexCoord.buf");

            debug!(
                "start: {}, end: {}, range_len: {}, fixed_len: {}, stride: {}",
                start,
                end,
                end - start,
                fixed_data.len(),
                stride
            );

            let mut tex_coord_data = std::fs::read(&tex_coord_path)?;
            let range_len = end - start;
            if range_len % stride != 0 {
                warn!(
                    "texcoord range length {} is not divisible by stride {} - skip",
                    range_len, stride
                );
                continue;
            }

            let vertex_count = range_len / stride;
            if vertex_count == 0 {
                continue;
            }

            if fixed_data.len() % vertex_count != 0 {
                warn!(
                    "fixed data length {} is not divisible by vertex count {} - skip",
                    fixed_data.len(),
                    vertex_count
                );
                continue;
            }

            let src_stride = fixed_data.len() / vertex_count;
            let texcoord1_offset_in_src = 8usize;
            let texcoord1_size = 4usize;
            let dst_texcoord1_offset = 8usize;

            if dst_texcoord1_offset + texcoord1_size > stride {
                warn!(
                    "dst texcoord1 (offset {} + size {}) out of dst stride {} - skip",
                    dst_texcoord1_offset, texcoord1_size, stride
                );
                continue;
            }

            for i in 0..vertex_count {
                let src_start = i * src_stride + texcoord1_offset_in_src;
                let src_end = src_start + texcoord1_size;
                let dst_start = start + i * stride + dst_texcoord1_offset;
                let dst_end = dst_start + texcoord1_size;

                if src_end > fixed_data.len() || dst_end > tex_coord_data.len() {
                    warn!(
                        "index out of bounds while copying texcoord1 for vertex {} - skip remaining",
                        i
                    );
                    break;
                }

                tex_coord_data[dst_start..dst_end].copy_from_slice(&fixed_data[src_start..src_end]);
            }

            fs_utils::create_backup_once(&tex_coord_path, backed_up)?;
            std::fs::write(&tex_coord_path, &tex_coord_data)?;
            ret = true;
        }
        Ok(ret)
    }

    fn fix_aero_rover_female_eyes_with_texture(
        &self,
        ini_path: &Path,
        ctx: &mut FixerContext,
    ) -> Result<bool, FixerError> {
        let mut modified = false;
        let texture_path = ini_path.parent().unwrap().join("Textures");
        if !texture_path.exists() {
            std::fs::create_dir_all(&texture_path)?;
        }

        let eyes_dds = include_bytes!("../resources/FRoverAeroEyes.dds");
        let file_name = "FRoverAeroEyes.dds";
        let dds_file_path = texture_path.join(file_name);
        if !dds_file_path.exists() {
            fs_utils::create_new_file_backup(&dds_file_path, ctx.backed_up)?;
            std::fs::write(&dds_file_path, eyes_dds)?;
            ctx.backed_up.insert(dds_file_path);
        }

        // Inject global $object_detected = 0 into [Constants]
        if let Some(sec) = ctx.ini.get_section_mut("Constants") {
            if !sec.has_key("global $object_detected") {
                sec.prepend_key_value("global $object_detected", "0", "");
                info!("Injected global $object_detected = 0 into [Constants]");
                modified = true;
            }
        } else {
            let mut sec = ini_parser::IniSection::new("Constants");
            sec.set_key_value("global $object_detected", "0", "");
            ctx.ini.sections.insert(0, sec);
            info!("Created [Constants] section with global $object_detected = 0");
            modified = true;
        }

        // Inject $object_detected = 1 into [TextureOverrideComponent5]
        if let Some(sec) = ctx.ini.get_section_mut("TextureOverrideComponent5") {
            if !sec.has_key("$object_detected") {
                // Find where to insert, preferably after match_index_count
                let mut insert_idx = sec.lines.len();
                for (i, line) in sec.lines.iter().enumerate() {
                    if line.contains("match_index_count") {
                        insert_idx = i + 1;
                        break;
                    }
                }
                sec.lines.insert(insert_idx, "$object_detected = 1".to_string());
                info!("Injected $object_detected = 1 into [TextureOverrideComponent5]");
                modified = true;
            }
        }

        let res_sec_name = "ResourceTextureFRoverAeroEyes";
        if !ctx.ini.has_section(res_sec_name) {
            let mut sec = ini_parser::IniSection::new(res_sec_name);
            sec.set_key_value("filename", &format!("Textures/{}", file_name), "");
            ctx.ini.sections.push(sec);
            modified = true;
        }

        let tex_ovr_name = "TextureOverrideTextureFRoverAeroEyes";
        if !ctx.ini.has_section(tex_ovr_name) {
            let mut sec = ini_parser::IniSection::new(tex_ovr_name);
            sec.set_key_value("hash", "a856c4f2", "");
            sec.set_key_value("match_priority", "0", "");
            sec.lines.push("if $object_detected".to_string());
            sec.lines.push("this = ResourceTexture_AeroRoverFemaleEyes".to_string());
            sec.lines.push("endif".to_string());
            ctx.ini.sections.push(sec);
            modified = true;
        }

        Ok(modified)
    }
}
