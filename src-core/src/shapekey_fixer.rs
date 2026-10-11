use log::info;

use crate::config_loader::{ShapeKeyFixConfig, SymmetryFilter};

pub struct RebuildResult {
    pub offset_buf: Vec<u8>,
    pub vertex_id_buf: Vec<u8>,
    pub vertex_offset_buf: Vec<u8>,
    pub batch0_count: u32,
    pub batch1_count: u32,
}

/// Low-level geometry buffer rebuilder for multi-batch shape keys.
pub struct ShapeKeyRebuilder<'a> {
    config: &'a ShapeKeyFixConfig,
}

pub type ShapeKeyFixer<'a> = ShapeKeyRebuilder<'a>;

impl<'a> ShapeKeyRebuilder<'a> {
    pub fn new(config: &'a ShapeKeyFixConfig, _char_name: &str) -> Option<Self> {
        Some(Self { config })
    }

    pub fn needs_fix(&self, offset_buf: &[u8]) -> bool {
        // Check if buffer is already reorganized into multi-batch layout.
        if offset_buf.len() >= 1024 && offset_buf.len() % 512 == 0 {
            let b1_first = u32::from_le_bytes(offset_buf[512..516].try_into().unwrap_or([1; 4]));
            if b1_first == 0 {
                return false;
            }
        }
        true
    }

    pub fn rebuild_buffers(
        &self,
        old_offset: &[u8],
        old_vertex_id: &[u8],
        old_vertex_offset: &[u8],
        position_buf: Option<&[u8]>,
    ) -> Result<RebuildResult, String> {
        let stride = self.config.offset_stride.unwrap_or(12) as usize;

        let mut extracted_shapekeys = std::collections::HashMap::new();

        let is_batch_format = old_offset.len() % 512 == 0 && old_offset.len() > 0;

        if is_batch_format {
            let num_batches = old_offset.len() / 512;
            info!(
                "Detected old ShapeKeyOffset formatted in Batching structure. Total batches: {}",
                num_batches
            );

            let mut vertex_offset_base = 0;
            for b in 0..num_batches {
                let batch_base = b * 512;
                let batch_vertex_count = old_offset
                    .get(batch_base + 127 * 4..batch_base + 128 * 4)
                    .and_then(|s| s.try_into().ok())
                    .map(u32::from_le_bytes)
                    .unwrap_or(0) as usize;

                for k in 0..127 {
                    let start = old_offset
                        .get(batch_base + k * 4..batch_base + k * 4 + 4)
                        .and_then(|s| s.try_into().ok())
                        .map(u32::from_le_bytes)
                        .unwrap_or(0) as usize;
                    let end = old_offset
                        .get(batch_base + (k + 1) * 4..batch_base + (k + 1) * 4 + 4)
                        .and_then(|s| s.try_into().ok())
                        .map(u32::from_le_bytes)
                        .unwrap_or(0) as usize;
                    let count = end.saturating_sub(start);

                    if count > 0 {
                        let id_start = (vertex_offset_base + start) * 4;
                        let id_end = (vertex_offset_base + end) * 4;
                        let val_start = (vertex_offset_base + start) * stride;
                        let val_end = (vertex_offset_base + end) * stride;

                        if id_end <= old_vertex_id.len() && val_end <= old_vertex_offset.len() {
                            let id_slice = old_vertex_id[id_start..id_end].to_vec();
                            let val_slice = old_vertex_offset[val_start..val_end].to_vec();
                            extracted_shapekeys.insert(b * 127 + k, (count, id_slice, val_slice));
                        }
                    }
                }
                vertex_offset_base += batch_vertex_count;
            }
        } else {
            let mut is_stride_16 = false;
            if old_offset.len() % 16 == 0 {
                let num_8_blocks = old_offset.len() / 8;
                let mut all_odd_zeros = true;
                let mut has_odd_blocks = false;
                for i in (1..num_8_blocks).step_by(2) {
                    has_odd_blocks = true;
                    let start = old_offset
                        .get(i * 8..i * 8 + 4)
                        .and_then(|s| s.try_into().ok())
                        .map(u32::from_le_bytes)
                        .unwrap_or(0);
                    let end = old_offset
                        .get(i * 8 + 4..i * 8 + 8)
                        .and_then(|s| s.try_into().ok())
                        .map(u32::from_le_bytes)
                        .unwrap_or(0);
                    if start != 0 || end != 0 {
                        all_odd_zeros = false;
                        break;
                    }
                }
                if has_odd_blocks && all_odd_zeros {
                    is_stride_16 = true;
                }
            }

            let offset_unit_size = if is_stride_16 { 16 } else { 8 };
            let num_old_slots = old_offset.len() / offset_unit_size;
            info!(
                "Detected old ShapeKeyOffset flat format (stride {} bytes). Total old slots: {}",
                offset_unit_size, num_old_slots
            );

            for i in 0..num_old_slots {
                let base_idx = i * offset_unit_size;
                let start = old_offset
                    .get(base_idx..base_idx + 4)
                    .and_then(|s| s.try_into().ok())
                    .map(u32::from_le_bytes)
                    .unwrap_or(0) as usize;
                let end = old_offset
                    .get(base_idx + 4..base_idx + 8)
                    .and_then(|s| s.try_into().ok())
                    .map(u32::from_le_bytes)
                    .unwrap_or(0) as usize;
                let count = end.saturating_sub(start);

                if count > 0 {
                    let id_start = start * 4;
                    let id_end = (start + count) * 4;
                    let val_start = start * stride;
                    let val_end = (start + count) * stride;

                    if id_end <= old_vertex_id.len() && val_end <= old_vertex_offset.len() {
                        let id_slice = old_vertex_id[id_start..id_end].to_vec();
                        let val_slice = old_vertex_offset[val_start..val_end].to_vec();
                        extracted_shapekeys.insert(i, (count, id_slice, val_slice));
                    }
                }
            }
        }

        let max_mapped = self.config.expression_remap.as_ref().map_or(0, |r| {
            r.values()
                .flat_map(|v| v.iter().map(|t| t.target_channel))
                .max()
                .unwrap_or(0) as usize
        });

        let max_unmapped = extracted_shapekeys.keys().copied().max().unwrap_or(0) as usize;
        let max_channel = std::cmp::max(max_mapped, max_unmapped);

        let batch_count = (max_channel / 127) + 1;
        let target_entries = batch_count * 127;

        let mut new_shapekeys = vec![(0usize, Vec::<u8>::new(), Vec::<u8>::new()); target_entries];

        // Adaptive horizontal gaze orientation normalization:
        // By standard convention, slot 2 (look left) has negative X displacement (mean_x < 0),
        // and slot 3 (look right) has positive X displacement (mean_x > 0).
        // Swap slots if inverted displacement is detected to preserve physical orientation.
        if let (Some((c2, _, vals2)), Some((c3, _, vals3))) = (extracted_shapekeys.get(&2), extracted_shapekeys.get(&3))
        {
            let mean2 = calculate_mean_x(vals2, *c2, stride);
            let mean3 = calculate_mean_x(vals3, *c3, stride);

            if mean2 > 0.05 && mean3 < -0.05 {
                info!(
                    "Detected inverted eye gaze horizontal displacement (Slot 2: {mean2:.3}, Slot 3: {mean3:.3}). Normalizing gaze orientation."
                );
                if let (Some(data2), Some(data3)) = (extracted_shapekeys.remove(&2), extracted_shapekeys.remove(&3)) {
                    extracted_shapekeys.insert(2, data3);
                    extracted_shapekeys.insert(3, data2);
                }
            }
        }

        let mut sorted_keys: Vec<usize> = extracted_shapekeys.keys().copied().collect();
        sorted_keys.sort_unstable();

        for old_channel in sorted_keys {
            let Some((src_count, src_ids, src_vals)) = extracted_shapekeys.get(&old_channel).cloned() else {
                continue;
            };
            if let Some(remaps) = &self.config.expression_remap {
                if let Some(targets) = remaps.get(&(old_channel as u16)) {
                    for target in targets {
                        let t = target.target_channel as usize;
                        if t >= target_entries {
                            continue;
                        }
                        match target.filter {
                            SymmetryFilter::All => {
                                new_shapekeys[t] = (src_count, src_ids.clone(), src_vals.clone());
                            }
                            SymmetryFilter::Left | SymmetryFilter::Right => {
                                if let Some(pos) = position_buf {
                                    let mut filtered_ids = Vec::new();
                                    let mut filtered_vals = Vec::new();
                                    let is_left = target.filter == SymmetryFilter::Left;

                                    for i in 0..src_count {
                                        let vid_start = i * 4;
                                        if vid_start + 4 > src_ids.len() {
                                            break;
                                        }
                                        let vid =
                                            u32::from_le_bytes(src_ids[vid_start..vid_start + 4].try_into().unwrap())
                                                as usize;
                                        let pos_offset = vid * 12;

                                        let keep = if pos_offset + 4 <= pos.len() {
                                            let x =
                                                f32::from_le_bytes(pos[pos_offset..pos_offset + 4].try_into().unwrap());
                                            if is_left { x <= 0.0 } else { x >= 0.0 }
                                        } else {
                                            true
                                        };

                                        if keep {
                                            filtered_ids.extend_from_slice(&src_ids[vid_start..vid_start + 4]);
                                            let val_start = i * stride;
                                            let val_end = val_start + stride;
                                            if val_end <= src_vals.len() {
                                                filtered_vals.extend_from_slice(&src_vals[val_start..val_end]);
                                            }
                                        }
                                    }
                                    let count = filtered_ids.len() / 4;
                                    new_shapekeys[t] = (count, filtered_ids, filtered_vals);
                                } else {
                                    log::warn!(
                                        "Position buffer missing for symmetry split on channel {t}, fallback to All"
                                    );
                                    new_shapekeys[t] = (src_count, src_ids.clone(), src_vals.clone());
                                }
                            }
                        }
                    }
                }
            } else if old_channel < target_entries {
                new_shapekeys[old_channel] = (src_count, src_ids, src_vals);
            }
        }

        let mut new_offset_bytes = Vec::with_capacity(batch_count * 512);
        let mut new_id_bytes = Vec::new();
        let mut new_val_bytes = Vec::new();
        let mut batch_counts = vec![0u32; batch_count];

        for b in 0..batch_count {
            let mut batch_verts_count = 0u32;
            new_offset_bytes.extend_from_slice(&0u32.to_le_bytes());

            for k in 0..127 {
                let (count, id_slice, val_slice) = &new_shapekeys[b * 127 + k];
                batch_verts_count += *count as u32;
                new_offset_bytes.extend_from_slice(&batch_verts_count.to_le_bytes());

                if *count > 0 {
                    new_id_bytes.extend_from_slice(id_slice);
                    new_val_bytes.extend_from_slice(val_slice);
                }
            }
            batch_counts[b] = batch_verts_count;
        }

        let c0 = batch_counts[0];
        let c1 = if batch_count > 1 { batch_counts[1] } else { 0 };

        info!(
            "Rebuilt ShapeKey buffers via batch redirect: total_batches={}, batch0_count={}, batch1_count={}",
            batch_count, c0, c1
        );

        Ok(RebuildResult {
            offset_buf: new_offset_bytes,
            vertex_id_buf: new_id_bytes,
            vertex_offset_buf: new_val_bytes,
            batch0_count: c0,
            batch1_count: c1,
        })
    }
}

/// Converts an IEEE 754 half-precision float (16-bit) to f32.
fn f16_to_f32(h: u16) -> f32 {
    let sign = ((h & 0x8000) as u32) << 16;
    let exp = (h & 0x7c00) >> 10;
    let mant = (h & 0x03ff) as u32;

    if exp == 0 {
        if mant == 0 {
            f32::from_bits(sign)
        } else {
            let mut m = mant << 13;
            let mut e = 127 - 14;
            while (m & 0x00800000) == 0 {
                m <<= 1;
                e -= 1;
            }
            m &= !0x00800000;
            f32::from_bits(sign | ((e as u32) << 23) | m)
        }
    } else if exp == 31 {
        f32::from_bits(sign | 0x7f800000 | (mant << 13))
    } else {
        let e = (exp as i32 - 15 + 127) as u32;
        let m = mant << 13;
        f32::from_bits(sign | (e << 23) | m)
    }
}

/// Computes mean X-axis displacement across shape key vertices.
fn calculate_mean_x(vals: &[u8], count: usize, stride: usize) -> f32 {
    if count == 0 || stride < 2 {
        return 0.0;
    }
    let mut sum = 0.0f32;
    let mut valid_verts = 0usize;
    for i in 0..count {
        let offset = i * stride;
        if offset + 2 <= vals.len() {
            let u = u16::from_le_bytes([vals[offset], vals[offset + 1]]);
            sum += f16_to_f32(u);
            valid_verts += 1;
        }
    }
    if valid_verts > 0 { sum / valid_verts as f32 } else { 0.0 }
}
