// src-core/src/fixers/aero_fix.rs

use std::path::Path;

use anyhow::anyhow;
use log::{debug, info, warn};

use crate::{
    collector,
    domain::{
        cst::IniCstSection,
        pipeline::{PipelineFixer, PipelineStage},
    },
    errors::FixerError,
    fixers::traits::FixerContext,
    t,
};

const RESOURCE_NAME: &str = "ResourceTextureFRoverAeroEyes";
const OVERRIDE_NAME: &str = "TextureOverrideTextureFRoverAeroEyes";
const DDS_FILE_NAME: &str = "FRoverAeroEyes.dds";
const TARGET_EYES_HASH: &str = "a856c4f2";

const AERO_EYES_DDS_BYTES: &[u8] = include_bytes!("../resources/FRoverAeroEyes.dds");
const FIXED_TEXCOORD_BYTES: &[u8] = include_bytes!("../resources/FRoverC5_TexCoord.buf");

pub struct AeroFixer;

impl PipelineFixer for AeroFixer {
    fn name(&self) -> &'static str {
        "AeroFixer"
    }

    fn stage(&self) -> PipelineStage {
        PipelineStage::MeshGated
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        if ctx.char_name != "RoverFemale" {
            return Ok(false);
        }

        let aero_mode = ctx.mod_ctx.aero_fix_mode;

        match aero_mode {
            1 => {
                // TexCoord override (Buffer cache accelerated)
                let texcoord_mod = self.fix_aero_rover_female_eyes_with_texcoord(ctx)?;
                if texcoord_mod {
                    info!("{}", t!(aero_rover_female_eyes_fixed));
                }
                Ok(texcoord_mod)
            }
            2 => {
                // Texture mirror flip (Domain section views)
                let texture_mod = self.fix_aero_rover_female_eyes_with_texture(ctx)?;
                if texture_mod {
                    info!("{}", t!(aero_rover_female_eyes_fixed));
                }
                Ok(texture_mod)
            }
            _ => Ok(false),
        }
    }
}

impl AeroFixer {
    fn fix_aero_rover_female_eyes_with_texcoord(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let &(index_count, index_offset) = match ctx.component_indices().get(&5) {
            Some(indices) => indices,
            None => {
                debug!("Component 5 not found in component indices - skipping TexCoord aero fix");
                return Ok(false);
            }
        };

        let texcoord_buf_matches = ctx.collect_resource_buffers(collector::BufferType::TexCoord);
        if texcoord_buf_matches.is_empty() {
            debug!("No TexCoord buffers found - skipping TexCoord aero fix");
            return Ok(false);
        }

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
            if !index_path.exists() {
                warn!(
                    "Index buffer path {} does not exist for TexCoord buffer {}",
                    index_path.display(),
                    tex_coord_path.display()
                );
                continue;
            }

            let index_data = ctx.read_buffer(&index_path)?;
            let (start, end) = collector::get_byte_range_in_buffer(index_count, index_offset, index_data, stride)
                .map_err(|e| anyhow!("Failed to get byte range in buffer: {}", e))?;

            debug!(
                "start: {}, end: {}, range_len: {}, fixed_len: {}, stride: {}",
                start,
                end,
                end - start,
                FIXED_TEXCOORD_BYTES.len(),
                stride
            );

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

            if FIXED_TEXCOORD_BYTES.len() % vertex_count != 0 {
                warn!(
                    "fixed data length {} is not divisible by vertex count {} - skip",
                    FIXED_TEXCOORD_BYTES.len(),
                    vertex_count
                );
                continue;
            }

            let src_stride = FIXED_TEXCOORD_BYTES.len() / vertex_count;
            let texcoord1_offset_in_src = 8usize;
            let texcoord1_size = 4usize;
            let dst_texcoord1_offset = 8usize;

            if texcoord1_offset_in_src + texcoord1_size > src_stride {
                warn!(
                    "src texcoord1 (offset {} + size {}) out of src stride {} - skip",
                    texcoord1_offset_in_src, texcoord1_size, src_stride
                );
                continue;
            }

            if dst_texcoord1_offset + texcoord1_size > stride {
                warn!(
                    "dst texcoord1 (offset {} + size {}) out of dst stride {} - skip",
                    dst_texcoord1_offset, texcoord1_size, stride
                );
                continue;
            }

            let read_tc = ctx.read_buffer(&tex_coord_path)?;
            let mut needs_fix = false;

            for i in 0..vertex_count {
                let src_start = i * src_stride + texcoord1_offset_in_src;
                let src_end = src_start + texcoord1_size;
                let dst_start = start + i * stride + dst_texcoord1_offset;
                let dst_end = dst_start + texcoord1_size;

                if src_end > FIXED_TEXCOORD_BYTES.len() || dst_end > read_tc.len() {
                    break;
                }

                if read_tc[dst_start..dst_end] != FIXED_TEXCOORD_BYTES[src_start..src_end] {
                    needs_fix = true;
                    break;
                }
            }

            if !needs_fix {
                continue;
            }

            let tex_coord_data = ctx.get_buffer_mut(&tex_coord_path)?;
            for i in 0..vertex_count {
                let src_start = i * src_stride + texcoord1_offset_in_src;
                let src_end = src_start + texcoord1_size;
                let dst_start = start + i * stride + dst_texcoord1_offset;
                let dst_end = dst_start + texcoord1_size;

                if src_end > FIXED_TEXCOORD_BYTES.len() || dst_end > tex_coord_data.len() {
                    warn!(
                        "index out of bounds while copying texcoord1 for vertex {} - skip remaining",
                        i
                    );
                    break;
                }

                tex_coord_data[dst_start..dst_end].copy_from_slice(&FIXED_TEXCOORD_BYTES[src_start..src_end]);
            }

            ret = true;
        }

        Ok(ret)
    }

    fn fix_aero_rover_female_eyes_with_texture(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let has_comp5_section = ctx.ini().has_section("TextureOverrideComponent5");
        let has_comp5_index = ctx.component_indices().contains_key(&5);

        if !has_comp5_section && !has_comp5_index {
            debug!("Component 5 not detected in INI, skipping Aero texture injection to avoid dead code");
            return Ok(false);
        }

        let mut modified = false;
        let ini_path = ctx.file_path().to_path_buf();
        let base_dir = ini_path.parent().unwrap_or_else(|| Path::new("."));
        let texture_path = base_dir.join("Textures");

        if !texture_path.exists() {
            if let Err(e) = std::fs::create_dir_all(&texture_path) {
                warn!("Failed to create Textures directory: {:?}", e);
            }
        }

        let dds_file_path = texture_path.join(DDS_FILE_NAME);
        if !dds_file_path.exists() {
            ctx.backup_new_file(&dds_file_path)?;
            std::fs::write(&dds_file_path, AERO_EYES_DDS_BYTES)?;
            modified = true;
        }

        // Prepend global $object_detected = 0 to [Constants]
        let mut consts_view = ctx.ini_mut().ensure_constants();
        if !consts_view.has_global("$object_detected") {
            consts_view.prepend_global("$object_detected", "0");
            info!("Injected global $object_detected = 0 into [Constants]");
            modified = true;
        }

        // Inject $object_detected = 1 into target component
        if let Some(mut comp5) = ctx.ini_mut().as_component_mut(5) {
            if comp5.ensure_object_detected_flag() {
                info!("Injected $object_detected = 1 into [TextureOverrideComponent5]");
                modified = true;
            }
        }

        // Construct and insert eye resource and texture override sections
        let has_res_sec = ctx.ini().has_section(RESOURCE_NAME);
        let has_ovr_sec = ctx.ini().has_section(OVERRIDE_NAME);

        if !has_res_sec || !has_ovr_sec {
            let mut new_secs = Vec::new();

            if !has_res_sec {
                let mut res_sec = IniCstSection::new(RESOURCE_NAME);
                let mut res_view = res_sec.as_resource_view_mut();
                res_view.set_filename(&format!("Textures/{}", DDS_FILE_NAME));
                new_secs.push(res_sec);
            }

            if !has_ovr_sec {
                let mut ovr_sec = IniCstSection::new(OVERRIDE_NAME);
                let mut ovr_view = ovr_sec.as_texture_override_view_mut();
                ovr_view.set_hash(TARGET_EYES_HASH);
                ovr_view.set_match_priority("0");
                ovr_view.set_object_detected_this(RESOURCE_NAME);
                new_secs.push(ovr_sec);
            }

            // Insert adjacent to component section or fallback to last texture override
            let anchor_name = if ctx.ini().has_section("TextureOverrideComponent5") {
                Some("TextureOverrideComponent5".to_string())
            } else {
                ctx.ini().iter_texture_overrides().last().map(|s| s.name.clone())
            };

            let inserted = if let Some(anchor) = anchor_name {
                ctx.ini_mut().insert_sections_after(&anchor, new_secs.clone())
            } else {
                false
            };

            if !inserted {
                ctx.ini_mut().push_sections_if_missing(new_secs);
            }
            modified = true;
        } else {
            if let Some(mut res_view) = ctx.ini_mut().as_resource_mut(RESOURCE_NAME) {
                let expected_filename = format!("Textures/{}", DDS_FILE_NAME);
                if res_view.filename().as_deref() != Some(&expected_filename) {
                    res_view.set_filename(&expected_filename);
                    modified = true;
                }
            }
        }

        if modified {
            ctx.mark_ini_modified();
        }

        Ok(modified)
    }
}
