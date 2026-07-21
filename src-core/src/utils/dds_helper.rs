// src-core/src/utils/dds_helper.rs

use anyhow::Result;
use ddsfile::Dds;
use image_dds::image_from_dds;
use std::collections::HashSet;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// 将 BC7 格式 DDS 贴图的 Alpha 通道全部设为 255（完全不透明）。
pub fn make_bc7_opaque(input_path: &Path, output_path: &Path, backed_up_mutex: &Mutex<HashSet<PathBuf>>) -> Result<()> {
    {
        let mut guard = backed_up_mutex.lock().unwrap();
        crate::utils::fs_utils::create_backup_once(input_path, &mut *guard)?;
    }
    let mut file = File::open(input_path)?;
    let mut dds = Dds::read(&mut file)?;
    drop(file); // 释放文件句柄

    // BC7: 通过按位解析 Block Mode 和 Rotation 直接强行置满 Alpha 端点
    for chunk in dds.data.chunks_exact_mut(16) {
        let mut bits = u128::from_le_bytes(chunk.try_into().unwrap());
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
                bits |= 0xFFFF << 49;
            }
            7 => {
                bits |= 0xFFFFF << 68;
            }
            _ => {} // Mode 0,1,2,3 无 Alpha 通道，跳过
        }
        chunk.copy_from_slice(&bits.to_le_bytes());
    }

    let mut out_file = File::create(output_path)?;
    dds.write(&mut out_file)?;
    Ok(())
}

pub fn export_shading_mask<P1: AsRef<Path>, P2: AsRef<Path>>(
    input_path: P1,
    output_path: P2,
    bg_gray_value: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(input_path)?;
    let dds = Dds::read(&mut file)?;
    let img_res = image_from_dds(&dds, 0);

    let (width, height, gray_data) = match img_res {
        Ok(img) => {
            let (width, height) = img.dimensions();
            let data: Vec<u8> = img
                .pixels()
                .map(|p| if p[0] < 50 { bg_gray_value } else { p[1] })
                .collect();
            (width, height, data)
        }
        Err(e) => {
            if let Some(ddsfile::D3DFormat::A8B8G8R8) = dds.get_d3d_format() {
                let width = dds.get_width();
                let height = dds.get_height();
                let mut data = Vec::with_capacity((width * height) as usize);

                for chunk in dds.data.chunks_exact(4) {
                    let r = chunk[0];
                    let g = chunk[1];
                    data.push(if r < 50 { bg_gray_value } else { g });
                }
                (width, height, data)
            } else {
                return Err(e.into());
            }
        }
    };

    let gray_img = image::GrayImage::from_raw(width, height, gray_data).expect("gray image size mismatch");

    gray_img.save(output_path.as_ref())?;
    Ok(())
}
