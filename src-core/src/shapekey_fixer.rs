use crate::config_loader::ShapeKeyFixConfig;
use log::info;

pub struct RebuildResult {
    pub offset_buf: Vec<u8>,
    pub vertex_id_buf: Vec<u8>,
    pub vertex_offset_buf: Vec<u8>,
    pub batch0_count: u32,
    pub batch1_count: u32,
}

pub struct ShapeKeyFixer<'a> {
    config: &'a ShapeKeyFixConfig,
}

impl<'a> ShapeKeyFixer<'a> {
    pub fn new(config: &'a ShapeKeyFixConfig, _char_name: &str) -> Option<Self> {
        Some(Self { config })
    }

    pub fn needs_fix(&self, vertex_id_buf_size: usize) -> bool {
        let expected = self.config.new_vertex_count.unwrap_or(0) as usize * 4;
        expected > 0 && vertex_id_buf_size != expected
    }

    pub fn rebuild_buffers(
        &self,
        old_offset: &[u8],
        old_vertex_id: &[u8],
        old_vertex_offset: &[u8],
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
                let batch_vertex_count = u32::from_le_bytes(
                    old_offset[batch_base + 127 * 4..batch_base + 128 * 4]
                        .try_into()
                        .unwrap(),
                ) as usize;

                for k in 0..127 {
                    let start = u32::from_le_bytes(
                        old_offset[batch_base + k * 4..batch_base + k * 4 + 4]
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    let end = u32::from_le_bytes(
                        old_offset[batch_base + (k + 1) * 4..batch_base + (k + 1) * 4 + 4]
                            .try_into()
                            .unwrap(),
                    ) as usize;
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
                    let start = u32::from_le_bytes(old_offset[i * 8..i * 8 + 4].try_into().unwrap());
                    let end = u32::from_le_bytes(old_offset[i * 8 + 4..i * 8 + 8].try_into().unwrap());
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
                let start = u32::from_le_bytes(old_offset[base_idx..base_idx + 4].try_into().unwrap()) as usize;
                let end = u32::from_le_bytes(old_offset[base_idx + 4..base_idx + 8].try_into().unwrap()) as usize;
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

        let max_mapped = self
            .config
            .expression_remap
            .as_ref()
            .map_or(0, |r| r.values().copied().max().unwrap_or(0) as usize);

        let max_unmapped = extracted_shapekeys.keys().copied().max().unwrap_or(0) as usize;
        let max_channel = std::cmp::max(max_mapped, max_unmapped);

        let batch_count = (max_channel / 127) + 1;
        let target_entries = batch_count * 127;

        let mut new_shapekeys = vec![(0usize, Vec::<u8>::new(), Vec::<u8>::new()); target_entries];

        let mut sorted_keys: Vec<usize> = extracted_shapekeys.keys().copied().collect();
        sorted_keys.sort_unstable();

        for old_channel in sorted_keys {
            let data = extracted_shapekeys.get(&old_channel).unwrap().clone();
            let new_channel = if let Some(remaps) = &self.config.expression_remap {
                remaps
                    .get(&(old_channel as u16))
                    .map(|&v| v as usize)
                    .unwrap_or(old_channel)
            } else {
                old_channel
            };

            if new_channel < target_entries {
                new_shapekeys[new_channel] = data;
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
