// src-core/src/utils/dds_helper.rs

use std::{
    collections::HashSet,
    fs::File,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::Result;
use ddsfile::Dds;
use image::{
    ColorType, ImageEncoder,
    codecs::png::{CompressionType, FilterType, PngEncoder},
};
use image_dds::image_from_dds;

/// Sets the alpha channel of a BC7 DDS texture to 255 (opaque).
pub fn make_bc7_opaque(
    input_path: &Path,
    output_path: &Path,
    backed_up_mutex: &Mutex<HashSet<PathBuf>>,
    session_time: Option<&str>,
) -> Result<bool> {
    let mut file = File::open(input_path)?;
    let mut dds = Dds::read(&mut file)?;
    drop(file);

    let mut any_changed = false;
    for chunk in dds.data.chunks_exact_mut(16) {
        let Ok(arr) = chunk.try_into() else {
            continue;
        };
        let original = u128::from_le_bytes(arr);
        let mut bits = original;
        let mode = bits.trailing_zeros();
        match mode {
            4 => {
                let rot = (bits >> 5) & 0x03;
                let mask: u128 = match rot {
                    0 => 0xFFF << 38,
                    1 => 0x3FF << 8,
                    2 => 0x3FF << 18,
                    3 => 0x3FF << 28,
                    _ => 0,
                };
                bits |= mask;
            }
            5 => {
                let rot = (bits >> 6) & 0x03;
                let mask: u128 = match rot {
                    0 => 0xFFFF << 50,
                    1 => 0x3FFF << 8,
                    2 => 0x3FFF << 22,
                    3 => 0x3FFF << 36,
                    _ => 0,
                };
                bits |= mask;
            }
            6 => {
                bits |= 0x3FFF << 49;
            }
            7 => {
                bits |= 0xFFFFF << 74;
            }
            _ => {} // Modes 0-3 have no alpha channel (decode to 255 by GPU hardware)
        }
        if bits != original {
            chunk.copy_from_slice(&bits.to_le_bytes());
            any_changed = true;
        }
    }

    if !any_changed {
        return Ok(false);
    }

    {
        let mut guard = backed_up_mutex
            .lock()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {e}"))?;
        if let Some(st) = session_time {
            crate::utils::fs_utils::create_backup_once_with_time(input_path, &mut *guard, st)?;
        } else {
            crate::utils::fs_utils::create_backup_once(input_path, &mut *guard)?;
        }
    }

    let mut out_file = File::create(output_path)?;
    dds.write(&mut out_file)?;
    Ok(true)
}

/// Reads DDS texture file as RgbaImage.
pub fn read_dds_rgba<P: AsRef<Path>>(path: P) -> Result<image::RgbaImage, Box<dyn std::error::Error>> {
    let mut file = std::io::BufReader::new(File::open(path.as_ref())?);
    let dds = Dds::read(&mut file)?;

    let img_res = image_from_dds(&dds, 0);

    match img_res {
        Ok(img) => Ok(img),
        Err(e) => {
            if let Some(ddsfile::D3DFormat::A8B8G8R8) = dds.get_d3d_format() {
                let width = dds.get_width();
                let height = dds.get_height();
                // A8B8G8R8 memory layout is already RGBA sequential bytes — zero-copy construction
                let img = image::RgbaImage::from_raw(width, height, dds.data)
                    .ok_or_else(|| anyhow::anyhow!("Failed to construct RgbaImage from raw A8B8G8R8 data"))?;
                Ok(img)
            } else {
                Err(e.into())
            }
        }
    }
}

/// Evaluates whether a Lightmap pixel falls within the character skin mask range.
/// Skin mask regions feature full material mask (R >= 225), subsurface scattering ratio (G/R in [0.26, 0.43]),
/// strict blue suppression (B <= 35) to exclude cool/neutral reflections, and warm tone separation (R >= B + 30).
#[inline(always)]
pub fn is_lightmap_skin(lr: u8, lg: u8, lb: u8) -> bool {
    let lru = lr as u32;
    let lgu = lg as u32;
    let lbu = lb as u32;

    lru >= 225 && lgu * 100 >= lru * 26 && lgu * 100 <= lru * 43 && lbu <= 35 && lru >= lbu + 30
}

/// Heuristic fallback skin mask evaluator for non-standard mod textures (Phase 2).
/// Used only when no standard Lightmap skin pixels are detected in the entire texture.
/// Targets flesh/peach diffuse or ambient tones mistakenly placed into Lightmap slots:
/// - Prominent brightness: R >= 220
/// - Warm tint balance: G >= 80, B >= 40, and G >= B (excludes purple/magenta highlights)
/// - Strong warm tone separation: R >= B + 50 and R >= G + 25 (excludes white/neutral grays)
/// - Hue constraint: R + B >= 2 * G (ensures Hue <= 30°, strictly red-to-orange flesh tone, rejecting bright yellows)
#[inline(always)]
pub fn is_fallback_skin(r: u8, g: u8, b: u8) -> bool {
    let ru = r as u32;
    let gu = g as u32;
    let bu = b as u32;

    ru >= 220 && gu >= 80 && bu >= 40 && gu >= bu && ru >= bu + 50 && ru >= gu + 25 && ru + bu >= 2 * gu
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MaterialmapMode {
    /// Discrete partition mode: assigns `skin_value` for skin regions,
    /// `clothing_value` for non-skin foreground, and 0 for background.
    DiscretePartition { skin_value: u8, clothing_value: u8 },

    /// Direct pass-through of the original Lightmap green channel.
    PassThroughG,

    /// Skin override mode: assigns `skin_value` to skin regions while preserving the original green channel elsewhere.
    SkinOverrideWithG { skin_value: u8 },
}

pub type ShadingMaskMode = MaterialmapMode;

pub fn encode_materialmap_png_bytes(
    lightmap_img: &image::RgbaImage,
    mode: MaterialmapMode,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (width, height) = lightmap_img.dimensions();
    let raw_pixels = lightmap_img.as_raw();

    let mask_data: Vec<u8> = match mode {
        MaterialmapMode::PassThroughG => raw_pixels.chunks_exact(4).map(|chunk| chunk[1]).collect(),
        MaterialmapMode::SkinOverrideWithG { skin_value } => {
            let has_standard_skin = raw_pixels.chunks_exact(4).any(|c| is_lightmap_skin(c[0], c[1], c[2]));
            if has_standard_skin {
                raw_pixels
                    .chunks_exact(4)
                    .map(|chunk| {
                        if is_lightmap_skin(chunk[0], chunk[1], chunk[2]) {
                            skin_value
                        } else {
                            chunk[1]
                        }
                    })
                    .collect()
            } else {
                raw_pixels
                    .chunks_exact(4)
                    .map(|chunk| {
                        if is_fallback_skin(chunk[0], chunk[1], chunk[2]) {
                            skin_value
                        } else {
                            chunk[1]
                        }
                    })
                    .collect()
            }
        }
        MaterialmapMode::DiscretePartition {
            skin_value,
            clothing_value,
        } => {
            let has_standard_skin = raw_pixels.chunks_exact(4).any(|c| is_lightmap_skin(c[0], c[1], c[2]));
            if has_standard_skin {
                raw_pixels
                    .chunks_exact(4)
                    .map(|chunk| {
                        let (r, g, b) = (chunk[0], chunk[1], chunk[2]);
                        if is_lightmap_skin(r, g, b) {
                            skin_value
                        } else if r > 20 || g > 20 || b > 20 {
                            clothing_value
                        } else {
                            0u8
                        }
                    })
                    .collect()
            } else {
                raw_pixels
                    .chunks_exact(4)
                    .map(|chunk| {
                        let (r, g, b) = (chunk[0], chunk[1], chunk[2]);
                        if is_fallback_skin(r, g, b) {
                            skin_value
                        } else if r > 20 || g > 20 || b > 20 {
                            clothing_value
                        } else {
                            0u8
                        }
                    })
                    .collect()
            }
        }
    };

    let estimated_png_size = (width as usize * height as usize / 64 + 1024).clamp(32 * 1024, 512 * 1024);
    let mut png_buf = Vec::with_capacity(estimated_png_size);
    let encoder = PngEncoder::new_with_quality(&mut png_buf, CompressionType::Default, FilterType::NoFilter);
    encoder.write_image(&mask_data, width, height, ColorType::L8)?;

    Ok(png_buf)
}

#[inline]
pub fn encode_shading_mask_bytes(
    lightmap_img: &image::RgbaImage,
    mode: MaterialmapMode,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    encode_materialmap_png_bytes(lightmap_img, mode)
}

pub fn export_materialmap_from_img<P: AsRef<Path>>(
    lightmap_img: &image::RgbaImage,
    output_path: P,
    mode: MaterialmapMode,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = encode_materialmap_png_bytes(lightmap_img, mode)?;
    std::fs::write(output_path.as_ref(), &bytes)?;
    Ok(bytes)
}

#[inline]
pub fn export_shading_mask_from_img<P: AsRef<Path>>(
    lightmap_img: &image::RgbaImage,
    output_path: P,
    mode: MaterialmapMode,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    export_materialmap_from_img(lightmap_img, output_path, mode)
}

pub fn export_materialmap<P1: AsRef<Path>, P2: AsRef<Path>>(
    lightmap_path: P1,
    output_path: P2,
    mode: MaterialmapMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let lightmap_img = read_dds_rgba(lightmap_path)?;
    export_materialmap_from_img(&lightmap_img, output_path, mode)?;
    Ok(())
}

#[inline]
pub fn export_shading_mask<P1: AsRef<Path>, P2: AsRef<Path>>(
    lightmap_path: P1,
    output_path: P2,
    mode: MaterialmapMode,
) -> Result<(), Box<dyn std::error::Error>> {
    export_materialmap(lightmap_path, output_path, mode)
}

#[cfg(test)]
mod tests {
    use image_dds::{ImageFormat, Mipmaps, Quality, dds_from_image};

    use super::*;

    #[test]
    fn test_is_lightmap_skin() {
        // Standard skin calibration and warm tint profiles (R >= 225, G/R ~ 0.30)
        assert!(is_lightmap_skin(255, 77, 0)); // Reference skin baseline (G/R=0.302)
        assert!(is_lightmap_skin(255, 76, 0)); // Custom asset skin variant (G/R=0.298)
        assert!(is_lightmap_skin(240, 72, 0)); // Interpolated edge gradient (G/R=0.300)

        // Mod solid orange skin Lightmaps (#FF6600, G/R in [0.40, 0.42])
        assert!(is_lightmap_skin(255, 102, 0)); // Pure orange mod skin (G/R=0.400)
        assert!(is_lightmap_skin(255, 105, 0)); // RoverMod Components-4 t=372bd73a.dds variant (G/R=0.412)

        // Yellow clothing / golden fabric (G/R >= 0.50 rejected)
        assert!(!is_lightmap_skin(255, 150, 0));
        assert!(!is_lightmap_skin(255, 128, 0));

        // Dark red fabric / stockings (R=203, G/R=0.251 rejected as clothing)
        assert!(!is_lightmap_skin(203, 51, 0));
        assert!(!is_lightmap_skin(200, 48, 0));

        // Red clothing / cape (low G, G/R < 0.26 rejected)
        assert!(!is_lightmap_skin(255, 20, 0));
        assert!(!is_lightmap_skin(240, 15, 0));

        // Dark green fabric (low R, mid/high G)
        assert!(!is_lightmap_skin(5, 60, 5));
        assert!(!is_lightmap_skin(30, 80, 20));

        // Metallic / specular highlights (high B or cool tone)
        assert!(!is_lightmap_skin(120, 120, 110));
        assert!(!is_lightmap_skin(255, 100, 90)); // High B cool/neutral reflection rejected
        assert!(!is_lightmap_skin(255, 255, 255)); // Pure white background R=B=255 rejected

        // Pure black background
        assert!(!is_lightmap_skin(10, 10, 10));
    }

    #[test]
    fn test_is_fallback_skin() {
        // Non-standard mod Lightmaps (diffuse/ambient flesh tones)
        assert!(is_fallback_skin(247, 131, 81)); // 2_ec330 quadrant flesh skin
        assert!(is_fallback_skin(249, 180, 149)); // Diffuse bake flesh skin (_1.dds)
        assert!(is_fallback_skin(235, 120, 60)); // Warm flesh shadow

        // Non-skin elements rejected by fallback filters
        assert!(!is_fallback_skin(8, 124, 174)); // Cyan/blue background from 2_ec330
        assert!(!is_fallback_skin(255, 255, 255)); // Pure white fabric/highlight
        assert!(!is_fallback_skin(230, 225, 220)); // Off-white/gray cloth
        assert!(!is_fallback_skin(255, 200, 50)); // Bright yellow fabric (2G > R+B)
        assert!(!is_fallback_skin(240, 190, 80)); // Golden silk (2G > R+B)
        assert!(!is_fallback_skin(240, 30, 30)); // Red cloth (G < 80)
        assert!(!is_fallback_skin(240, 90, 120)); // Magenta/purple specular (B > G)
        assert!(!is_fallback_skin(30, 80, 20)); // Dark green fabric
        assert!(!is_fallback_skin(10, 10, 10)); // Black background
    }

    #[test]
    fn test_export_materialmap() {
        let temp_dir = std::env::temp_dir().join(format!(
            "test_shading_mask_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let lightmap_path = temp_dir.join("lightmap.dds");
        let output_path = temp_dir.join("mask.png");

        const ROVER_FEMALE_HAIR_DDS: &[u8] = include_bytes!("../resources/FRoverHair_C0D.dds");
        std::fs::write(&lightmap_path, ROVER_FEMALE_HAIR_DDS).unwrap();

        let res = export_materialmap(&lightmap_path, &output_path, MaterialmapMode::PassThroughG);
        assert!(res.is_ok());
        assert!(output_path.exists());

        let res_partition = export_materialmap(
            &lightmap_path,
            &output_path,
            MaterialmapMode::DiscretePartition {
                skin_value: 64,
                clothing_value: 0,
            },
        );
        assert!(res_partition.is_ok());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_materialmap_discrete_partition() {
        let mut img = image::RgbaImage::new(2, 2);
        img.put_pixel(0, 0, image::Rgba([255, 77, 0, 255]));
        img.put_pixel(1, 0, image::Rgba([5, 120, 5, 255]));
        img.put_pixel(0, 1, image::Rgba([0, 0, 0, 255]));
        img.put_pixel(1, 1, image::Rgba([30, 80, 20, 255]));

        let bytes_rf3 = encode_materialmap_png_bytes(
            &img,
            MaterialmapMode::DiscretePartition {
                skin_value: 64,
                clothing_value: 0,
            },
        )
        .unwrap();
        assert!(!bytes_rf3.is_empty());
        let decoded_rf3 = image::load_from_memory(&bytes_rf3).unwrap().to_luma8();
        assert_eq!(decoded_rf3.get_pixel(0, 0)[0], 64);
        assert_eq!(decoded_rf3.get_pixel(1, 0)[0], 0);

        // Solid orange mod skin Lightmap test (#FF6600, G/R = 0.400)
        let mut img_orange = image::RgbaImage::new(2, 2);
        img_orange.put_pixel(0, 0, image::Rgba([255, 102, 0, 255]));
        img_orange.put_pixel(1, 0, image::Rgba([255, 105, 0, 255]));
        img_orange.put_pixel(0, 1, image::Rgba([255, 102, 0, 255]));
        img_orange.put_pixel(1, 1, image::Rgba([255, 105, 0, 255]));

        let bytes_rf4 = encode_materialmap_png_bytes(
            &img_orange,
            MaterialmapMode::DiscretePartition {
                skin_value: 4,
                clothing_value: 0,
            },
        )
        .unwrap();
        assert!(!bytes_rf4.is_empty());
        let decoded_rf4 = image::load_from_memory(&bytes_rf4).unwrap().to_luma8();
        assert_eq!(decoded_rf4.get_pixel(0, 0)[0], 4);
        assert_eq!(decoded_rf4.get_pixel(1, 0)[0], 4);
        assert_eq!(decoded_rf4.get_pixel(0, 1)[0], 4);
        assert_eq!(decoded_rf4.get_pixel(1, 1)[0], 4);

        // Non-standard quadrant mod skin Lightmap test (Fallback to diffuse/ambient flesh tone)
        let mut img_fallback = image::RgbaImage::new(2, 2);
        img_fallback.put_pixel(0, 0, image::Rgba([247, 131, 81, 255])); // Flesh skin
        img_fallback.put_pixel(1, 0, image::Rgba([8, 124, 174, 255])); // Cyan background
        img_fallback.put_pixel(0, 1, image::Rgba([8, 124, 174, 255])); // Cyan background
        img_fallback.put_pixel(1, 1, image::Rgba([8, 124, 174, 255])); // Cyan background

        let bytes_fallback = encode_materialmap_png_bytes(
            &img_fallback,
            MaterialmapMode::DiscretePartition {
                skin_value: 4,
                clothing_value: 0,
            },
        )
        .unwrap();
        assert!(!bytes_fallback.is_empty());
        let decoded_fallback = image::load_from_memory(&bytes_fallback).unwrap().to_luma8();
        assert_eq!(decoded_fallback.get_pixel(0, 0)[0], 4);
        assert_eq!(decoded_fallback.get_pixel(1, 0)[0], 0);
        assert_eq!(decoded_fallback.get_pixel(0, 1)[0], 0);
        assert_eq!(decoded_fallback.get_pixel(1, 1)[0], 0);

        let bytes_passthrough = encode_materialmap_png_bytes(&img, MaterialmapMode::PassThroughG).unwrap();
        assert!(!bytes_passthrough.is_empty());
    }

    #[test]
    fn test_make_bc7_opaque() {
        let temp_dir = std::env::temp_dir().join(format!(
            "test_make_opaque_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let tex_path = temp_dir.join("hair_diffuse.dds");

        // 4x4 test texture: opaque (255), semi-transparent (128), transparent (0)
        let mut img = image::RgbaImage::new(4, 4);
        img.put_pixel(0, 0, image::Rgba([100, 100, 100, 255]));
        img.put_pixel(1, 0, image::Rgba([80, 80, 80, 128]));
        img.put_pixel(2, 0, image::Rgba([0, 0, 0, 0]));
        img.put_pixel(3, 0, image::Rgba([60, 60, 60, 255]));

        let dds = dds_from_image(&img, ImageFormat::BC7Srgb, Quality::Fast, Mipmaps::Disabled).unwrap();
        let mut f = File::create(&tex_path).unwrap();
        dds.write(&mut f).unwrap();
        drop(f);

        let backed_up = Mutex::new(HashSet::new());

        // First pass: mark opaque and verify modification
        let res = make_bc7_opaque(&tex_path, &tex_path, &backed_up, None).unwrap();
        assert!(res);

        // Verify decoded pixel alpha channels are 255
        let opaque_img = read_dds_rgba(&tex_path).unwrap();
        let p_solid = opaque_img.get_pixel(0, 0);
        assert_eq!(p_solid[3], 255, "Solid pixel alpha should be 255");
        let p_bangs = opaque_img.get_pixel(2, 0);
        assert_eq!(p_bangs[3], 255, "Bangs pixel alpha should be restored to 255");

        // Idempotence test: second pass detects no changes and short-circuits
        let res_idempotent = make_bc7_opaque(&tex_path, &tex_path, &backed_up, None).unwrap();
        assert!(!res_idempotent, "Idempotent check should skip disk write");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_builtin_fallback_resources_alpha() {
        let f_path = if Path::new("src/resources/FRoverHair_C0D.dds").exists() {
            PathBuf::from("src/resources/FRoverHair_C0D.dds")
        } else {
            PathBuf::from("src-core/src/resources/FRoverHair_C0D.dds")
        };
        if f_path.exists() {
            let img_f = read_dds_rgba(&f_path).unwrap();
            let p = img_f.get_pixel(0, 0);
            assert!(p[3] > 0, "Female fallback hair alpha should not be 0 (got {})", p[3]);
        }

        let m_path = if Path::new("src/resources/MRoverHair_C6D.dds").exists() {
            PathBuf::from("src/resources/MRoverHair_C6D.dds")
        } else {
            PathBuf::from("src-core/src/resources/MRoverHair_C6D.dds")
        };
        if m_path.exists() {
            let img_m = read_dds_rgba(&m_path).unwrap();
            let p = img_m.get_pixel(0, 0);
            assert!(p[3] > 0, "Male fallback hair alpha should not be 0 (got {})", p[3]);
        }
    }
}
