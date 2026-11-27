use log::info;

use crate::config_loader::{ShapeKeyFixConfig, SymmetryFilter};
use super::transplant;

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
    surface_components: Option<(u32, u32)>,
    custom_shapekey_ids: std::collections::HashSet<u32>,
}

pub type ShapeKeyFixer<'a> = ShapeKeyRebuilder<'a>;

/// Layout generation of a mod's `ShapeKeyOffset.buf`.
///
/// The buffer is a flat array of 128 `u32` slots per batch:
/// `offsets[0..=126]` are the per-channel start indices and `offsets[127]` is the
/// batch total (== base of the next batch).  A single dispatch handles at most
/// 127 channels. Batch count describes storage, not channel provenance:
///
/// * one batch  - legacy export, at most 127 used channels
/// * two batches - modern export, 127 + 34 channels
///
/// Historical converters also emitted two batches. Their populated expressions
/// need an independent semantic check before treating them as authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeKeyLayout {
    Legacy,
    Modern,
    Malformed,
}

impl ShapeKeyLayout {
    pub fn detect(offset_buf: &[u8]) -> Self {
        if offset_buf.is_empty() || offset_buf.len() % 512 != 0 {
            return Self::Malformed;
        }
        match offset_buf.len() / 512 {
            0 => Self::Malformed,
            1 => Self::Legacy,
            _ => Self::Modern,
        }
    }

    /// True when the buffer already has the multi-batch layout of the target game.
    pub fn is_modern(self) -> bool {
        matches!(self, Self::Modern)
    }
}

impl<'a> ShapeKeyRebuilder<'a> {
    pub fn new(config: &'a ShapeKeyFixConfig, char_name: &str) -> Option<Self> {
        let surface_components = match char_name {
            "RoverFemale" | "FRoverSkin1" => Some((2, 5)),
            "RoverMale" | "MRoverSkin1" => Some((1, 4)),
            _ => None,
        };
        Some(Self {
            config,
            surface_components,
            custom_shapekey_ids: std::collections::HashSet::new(),
        })
    }

    pub fn with_custom_shapekeys(mut self, ids: std::collections::HashSet<u32>) -> Self {
        self.custom_shapekey_ids = ids;
        self
    }

    pub fn set_custom_shapekeys(&mut self, ids: std::collections::HashSet<u32>) {
        self.custom_shapekey_ids = ids;
    }

    /// Decides whether the buffers have to be processed at all.
    ///
    /// * `Legacy`    - always: the layout itself has to be upgraded.
    /// * `Modern`    - configured completion or a Rover reference can require
    ///   inspection. Populated expressions change only when multiple independent
    ///   reference anchors expose a historically converted channel layout.
    /// * `Malformed` - always: best effort repair.
    pub fn needs_fix(&self, offset_buf: &[u8]) -> bool {
        match ShapeKeyLayout::detect(offset_buf) {
            ShapeKeyLayout::Legacy | ShapeKeyLayout::Malformed => true,
            ShapeKeyLayout::Modern => {
                self.config
                    .channel_substitutes
                    .as_ref()
                    .is_some_and(|table| !table.is_empty())
                    || !self.transplant_channels(false).is_empty()
                    || (self.surface_components.is_some() && self.config.reference_asset.is_some())
            }
        }
    }

    pub fn rebuild_buffers(
        &self,
        old_offset: &[u8],
        old_vertex_id: &[u8],
        old_vertex_offset: &[u8],
        position_buf: Option<&[u8]>,
    ) -> Result<RebuildResult, String> {
        self.rebuild_buffers_partitioned(old_offset, old_vertex_id, old_vertex_offset, position_buf, None)
    }

    pub fn rebuild_buffers_partitioned(
        &self,
        old_offset: &[u8],
        old_vertex_id: &[u8],
        old_vertex_offset: &[u8],
        position_buf: Option<&[u8]>,
        partition: Option<&transplant::ComponentPartition>,
    ) -> Result<RebuildResult, String> {
        let stride = self.config.offset_stride.unwrap_or(12) as usize;

        let is_legacy = if old_offset.len() < 1024 || old_offset.len() % 512 != 0 {
            true
        } else {
            let b1_first = u32::from_le_bytes(old_offset[512..516].try_into().unwrap_or([1; 4]));
            if b1_first != 0 {
                true
            } else {
                let b1_total = u32::from_le_bytes(old_offset[1020..1024].try_into().unwrap_or([0; 4]));
                let b0_s14 = u32::from_le_bytes(old_offset[14 * 4..15 * 4].try_into().unwrap_or([0; 4]));
                let b0_e14 = u32::from_le_bytes(old_offset[15 * 4..16 * 4].try_into().unwrap_or([0; 4]));
                b1_total == 0 && b0_e14 > b0_s14
            }
        };

        if !is_legacy {
            let num_batches = old_offset.len() / 512;
            let mut extracted_shapekeys = std::collections::HashMap::new();
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

            let surface_partition = partition.map(|part| {
                if stride == 12 {
                    if let Some((_, ids, values)) = extracted_shapekeys.get(&44) {
                        return part.with_mouth_motion(ids, values);
                    }
                }
                part.clone()
            });
            let partition = surface_partition.as_ref();

            // 1) Reference transplant: overwrite the listed channels with the
            //    target build's own data, moved onto the mod's vertices by
            //    nearest-position matching. This reproduces the original
            //    expression instead of approximating it.
            let mut transplanted: Vec<usize> = Vec::new();
            if let Some(asset_rel) = &self.config.reference_asset {
                if let Some(pos) = position_buf {
                    let channels: Vec<usize> = self
                        .transplant_channels(false)
                        .into_iter()
                        .filter(|(ch, _)| !self.custom_shapekey_ids.contains(&(*ch as u32)))
                        .filter(|(ch, _)| extracted_shapekeys.get(ch).map(|v| v.0 <= 2).unwrap_or(true))
                        .map(|(ch, _)| ch)
                        .collect();
                    let tolerance = self
                        .config
                        .transplant_tolerance
                        .as_deref()
                        .and_then(|s| s.trim().parse::<f32>().ok())
                        .unwrap_or(0.6);
                    let diffusion = self
                        .config
                        .transplant_diffusion
                        .as_deref()
                        .and_then(|s| s.trim().parse::<f32>().ok())
                        .unwrap_or(0.0);
                    match transplant::load_asset(asset_rel) {
                        Ok(asset) => {
                            // every mod vertex is a potential correspondence; the
                            // matcher narrows it down per channel by bounding box
                            let candidates: Vec<u32> = (0..(pos.len() / 12) as u32).collect();
                            for t in self.reference_channels(
                                &asset,
                                pos,
                                &candidates,
                                partition,
                                &channels,
                                tolerance,
                                diffusion,
                            ) {
                                let ratio = t.matched as f32 / t.reference_len.max(1) as f32;
                                if ratio < 0.5 {
                                    info!(
                                        "transplant ch{}: only {:.1}% of the reference vertices matched, kept substitute",
                                        t.channel,
                                        ratio * 100.0
                                    );
                                    continue;
                                }
                                let id_bytes: Vec<u8> = t.ids.iter().flat_map(|i| i.to_le_bytes()).collect();
                                let val_bytes: Vec<u8> = t.vals.iter().flat_map(|v| v.to_le_bytes()).collect();
                                extracted_shapekeys.insert(t.channel, (t.ids.len(), id_bytes, val_bytes));
                                transplanted.push(t.channel);
                                info!(
                                    "transplanted ch{}: {}/{} reference vertices matched ({:.1}%)",
                                    t.channel,
                                    t.matched,
                                    t.reference_len,
                                    ratio * 100.0
                                );
                            }
                        }
                        Err(e) => log::warn!("shapekey reference asset '{}' is unavailable: {}", asset_rel, e),
                    }
                }
            }

            // Complete channels that are only stubs in this mod but carry real
            // deformation in the target build (3.8 female: 111 = strong wink,
            // 113..=116 = visemes).  The substitute table is derived from the
            // target reference by vertex-set / mean-displacement similarity and
            // lives in config.yml, so it is regenerable per character/version.
            //
            // Everything else is preserved byte for byte: in a modern mod the
            // channel order and the per-channel payload are authoritative, and
            // re-deriving them is what silently corrupted mods before.
            let is_stub = |map: &std::collections::HashMap<usize, (usize, Vec<u8>, Vec<u8>)>, ch: usize| {
                map.get(&ch).map_or(true, |x| x.0 <= 2)
            };

            let mut completed: Vec<(usize, usize, usize)> = Vec::new();
            if let Some(raw_subs) = &self.config.channel_substitutes {
                let subs: std::collections::HashMap<String, String> = raw_subs
                    .iter()
                    .filter(|(k, _)| k.parse::<usize>().map(|c| !transplanted.contains(&c)).unwrap_or(false))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                let mut pairs: Vec<(usize, usize, f32)> = subs
                    .iter()
                    .filter_map(|(t, spec)| {
                        let (src, scale) = match spec.split_once(':') {
                            Some((src, scale)) => (src, scale.parse::<f32>().unwrap_or(1.0)),
                            None => (spec.as_str(), 1.0),
                        };
                        Some((t.parse::<usize>().ok()?, src.parse::<usize>().ok()?, scale))
                    })
                    .collect();
                pairs.sort_unstable_by_key(|x| x.0);
                for (target, source, scale) in pairs {
                    if !is_stub(&extracted_shapekeys, target) {
                        continue;
                    }
                    if let Some(mut src) = extracted_shapekeys.get(&source).cloned() {
                        scale_payload(&mut src.2, stride, scale);
                        completed.push((target, source, src.0));
                        extracted_shapekeys.insert(target, src);
                    }
                }
            }
            if !completed.is_empty() {
                info!(
                    "Completed {} stub shapekey channel(s) (target, source, vertices): {:?}",
                    completed.len(),
                    completed
                );
            }

            let batch_count = num_batches.max(1);
            let target_entries = batch_count * 127;
            let mut new_shapekeys = vec![(0usize, Vec::<u8>::new(), Vec::<u8>::new()); target_entries];
            for (ch, data) in extracted_shapekeys {
                if ch < target_entries {
                    new_shapekeys[ch] = data;
                }
            }

            self.repair_surface(&mut new_shapekeys, position_buf, stride, partition, true);

            return Self::build_reconstructed_buffers(&new_shapekeys, batch_count);
        }

        let mut extracted_shapekeys = std::collections::HashMap::new();

        let is_batch_format = old_offset.len() % 512 == 0 && !old_offset.is_empty();

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

        // Adaptive version-cascading normalization for legacy models missing symmetric expressions:
        // In WWMI 1.0~1.1, meshes had only 86 shapekey channels (0..85).
        // Channels 72..=85 were 14 chest physics deformation channels (Z ~ 108..110),
        // and symmetric facial expressions (86 smile, 87 frown, 89/90 smirks) did not exist yet.
        // In WWMI 1.2~3.7, chest channels were relocated to 91..=104, and channels 86..=90 were added.
        if !extracted_shapekeys.contains_key(&86) {
            let has_ch72 = extracted_shapekeys.contains_key(&72);
            let is_chest = if has_ch72 {
                let max_k = extracted_shapekeys.keys().copied().max().unwrap_or(0);
                if max_k <= 85 {
                    true
                } else if let Some(pos) = position_buf {
                    let (c72, ids72, _) = &extracted_shapekeys[&72];
                    if *c72 > 0 {
                        let mut sum_z = 0.0f32;
                        let mut count_z = 0usize;
                        for i in 0..*c72 {
                            let vid_start = i * 4;
                            if vid_start + 4 <= ids72.len() {
                                let vid =
                                    u32::from_le_bytes(ids72[vid_start..vid_start + 4].try_into().unwrap()) as usize;
                                let z_off = vid * 12 + 8;
                                if z_off + 4 <= pos.len() {
                                    let z = f32::from_le_bytes(pos[z_off..z_off + 4].try_into().unwrap());
                                    sum_z += z;
                                    count_z += 1;
                                }
                            }
                        }
                        count_z > 0 && (sum_z / count_z as f32) < 125.0
                    } else {
                        false
                    }
                } else {
                    max_k <= 86
                }
            } else {
                false
            };

            if is_chest {
                info!("Relocating legacy chest channels 72..=85 to standard 91..=104");
                for i in 0..14 {
                    let old_chest_ch = 72 + i;
                    let target_chest_ch = 91 + i;
                    if let Some(chest_data) = extracted_shapekeys.remove(&old_chest_ch) {
                        extracted_shapekeys.insert(target_chest_ch, chest_data);
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
        let max_transplant = self
            .transplant_channels(true)
            .into_iter()
            .map(|(c, _)| c)
            .max()
            .unwrap_or(0);
        let max_channel = max_mapped.max(max_unmapped).max(max_transplant);

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
            if self.custom_shapekey_ids.contains(&(old_channel as u32)) {
                if old_channel < target_entries {
                    new_shapekeys[old_channel] = (src_count, src_ids, src_vals);
                }
                continue;
            }
            if let Some(remaps) = &self.config.expression_remap {
                if let Some(targets) = remaps.get(&(old_channel as u16)) {
                    for target in targets {
                        let t = target.target_channel as usize;
                        if t >= target_entries || self.custom_shapekey_ids.contains(&(t as u32)) {
                            continue;
                        }
                        match target.filter {
                            SymmetryFilter::All => {
                                if src_count > 2 || new_shapekeys[t].0 <= 2 {
                                    new_shapekeys[t] = (src_count, src_ids.clone(), src_vals.clone());
                                }
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
                                    if count > 2 || new_shapekeys[t].0 <= 2 {
                                        new_shapekeys[t] = (count, filtered_ids, filtered_vals);
                                    }
                                } else {
                                    log::warn!(
                                        "Position buffer missing for symmetry split on channel {t}, fallback to All"
                                    );
                                    if src_count > 2 || new_shapekeys[t].0 <= 2 {
                                        new_shapekeys[t] = (src_count, src_ids.clone(), src_vals.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            } else if old_channel < target_entries {
                new_shapekeys[old_channel] = (src_count, src_ids, src_vals);
            }
        }

        let mut surface_partition = partition.cloned();
        let has_aa_remap = self
            .config
            .expression_remap
            .as_ref()
            .and_then(|remap| remap.get(&22))
            .is_some_and(|targets| targets.iter().any(|t| t.target_channel == 44));
        if stride == 12 && has_aa_remap {
            let aa_source = extracted_shapekeys
                .get(&22)
                .or_else(|| extracted_shapekeys.contains_key(&86).then(|| extracted_shapekeys.get(&44)).flatten());
            if let (Some(part), Some((_, ids, vals))) = (partition, aa_source) {
                surface_partition = Some(part.with_mouth_motion(ids, vals));
            }
        }
        // A complete surface field already supplies every face/eye channel,
        // including static zeros. Running per-channel substitutes first would
        // be redundant and could discard authored vertices outside that field.
        if !self.repair_surface(
            &mut new_shapekeys,
            position_buf,
            stride,
            surface_partition.as_ref(),
            false,
        ) {
            // Transplant official reference channels onto missing/stub slots (and forced channels)
            let _transplanted = self.transplant_into(&mut new_shapekeys, position_buf, stride, partition);

            // Complete missing/stub channels using configured substitutes
            if let Some(raw_subs) = &self.config.channel_substitutes {
                let mut pairs: Vec<(usize, usize, f32)> = raw_subs
                    .iter()
                    .filter_map(|(t, spec)| {
                        let (src, scale) = match spec.split_once(':') {
                            Some((src, scale)) => (src, scale.parse::<f32>().ok()?),
                            None => (spec.as_str(), 1.0),
                        };
                        Some((t.parse::<usize>().ok()?, src.parse::<usize>().ok()?, scale))
                    })
                    .collect();
                pairs.sort_unstable_by_key(|x| x.0);
                for (target, source, scale) in pairs {
                    if target < new_shapekeys.len()
                        && new_shapekeys[target].0 <= 2
                        && source < new_shapekeys.len()
                        && new_shapekeys[source].0 > 2
                    {
                        let (count, ids, mut vals) = new_shapekeys[source].clone();
                        scale_payload(&mut vals, stride, scale);
                        new_shapekeys[target] = (count, ids, vals);
                    }
                }
            }
        }
        Self::build_reconstructed_buffers(&new_shapekeys, batch_count)
    }

    fn repair_surface(
        &self,
        slots: &mut [(usize, Vec<u8>, Vec<u8>)],
        positions: Option<&[u8]>,
        stride: usize,
        partition: Option<&transplant::ComponentPartition>,
        heal_only: bool,
    ) -> bool {
        if stride != 12 {
            return false;
        }
        let (Some(pos), Some(part), Some((face, eyes)), Some(path)) = (
            positions,
            partition,
            self.surface_components,
            self.config.reference_asset.as_deref(),
        ) else {
            return false;
        };
        let asset = match transplant::load_asset(path) {
            Ok(asset) => asset,
            Err(e) => {
                log::warn!("Surface transfer unavailable: {e}");
                return false;
            }
        };
        let Some(surface) = transplant::transfer_legacy_surface(&asset, pos, part, face, eyes) else {
            return false;
        };
        // Fully custom-UV heads (non-official head swaps) carry bespoke visemes
        // that must not be replaced; hybrid heads with official face/teeth UVs (>= 50%)
        // still heal missing and divergent official-UV channels.
        if heal_only && surface.uv_untrusted && surface.uv_coverage < 0.50 {
            return false;
        }
        let mut missing_stubs = Vec::new();
        let mut incompatible = Vec::new();
        const MOUTH_ANCHORS: &[usize] = &[44, 45, 48, 63, 75, 103, 104, 105, 106, 131, 132];
        const SECONDARY_MORPHS: &[usize] = &[
            22, 23, 87, 88, 103, 104, 105, 106, 110, 111, 113, 114, 115, 116, 126, 131, 132, 146,
        ];
        if heal_only {
            // Check official channels against reference model. Exclude custom shapekeys.
            for channel in &surface.channels {
                let ch = channel.channel;
                if self.custom_shapekey_ids.contains(&(ch as u32)) {
                    continue;
                }
                let Some(slot) = slots.get(ch) else {
                    continue;
                };
                if slot.0 == 0 {
                    if !channel.ids.is_empty() && (SECONDARY_MORPHS.contains(&ch) || !MOUTH_ANCHORS.contains(&ch)) {
                        missing_stubs.push(ch);
                    }
                    continue;
                }
                let actual: std::collections::HashMap<u32, [f32; 3]> = slot
                    .1
                    .chunks_exact(4)
                    .zip(slot.2.chunks_exact(12))
                    .map(|(id, v)| {
                        (
                            u32::from_le_bytes(id.try_into().unwrap()),
                            std::array::from_fn(|i| {
                                f16_to_f32(u16::from_le_bytes(v[i * 2..i * 2 + 2].try_into().unwrap()))
                            }),
                        )
                    })
                    .collect();
                if !actual.values().any(|v| v.iter().any(|&x| x.abs() > 0.01)) {
                    continue;
                }
                let wanted: std::collections::HashMap<u32, [f32; 3]> = channel
                    .ids
                    .iter()
                    .zip(channel.vals.chunks_exact(6))
                    .map(|(&id, v)| (id, std::array::from_fn(|i| f16_to_f32(v[i]))))
                    .collect();
                let mut active = 0;
                let mut bad = 0;
                let check_ids: Box<dyn Iterator<Item = &u32>> = if surface.uv_untrusted && !surface.uv_matched.is_empty() {
                    Box::new(surface.vertices.iter().filter(|id| surface.uv_matched.contains(id)))
                } else {
                    Box::new(surface.vertices.iter())
                };
                for id in check_ids {
                    let a = actual.get(id).copied().unwrap_or([0.; 3]);
                    let b = wanted.get(id).copied().unwrap_or([0.; 3]);
                    let amplitude: f32 = a.iter().chain(&b).map(|x| x * x).sum();
                    let error: f32 = (0..3).map(|i| (a[i] - b[i]).powi(2)).sum();
                    if amplitude > 0.01f32.powi(2) {
                        active += 1;
                        if error > 0.05f32.powi(2) && error > 0.04 * amplitude {
                            bad += 1;
                        }
                    }
                }
                if active > 0 && bad as f32 / active as f32 > 0.15 {
                    incompatible.push(ch);
                }
            }
            if incompatible.is_empty() && missing_stubs.is_empty() {
                return false;
            }
            if !missing_stubs.is_empty() {
                info!(
                    "Self-healing converted shapekey batches: completing {} missing facial channels",
                    missing_stubs.len()
                );
            }
            if !incompatible.is_empty() {
                info!(
                    "Self-healing converted shapekey batches: refreshing {} divergent facial channels",
                    incompatible.len()
                );
            }
        }
        let mapped: std::collections::HashSet<u32> = surface.vertices.into_iter().collect();
        for channel in surface.channels {
            let Some(slot) = slots.get_mut(channel.channel) else {
                continue;
            };
            // Never overwrite custom shapekey sliders registered in the INI.
            if self.custom_shapekey_ids.contains(&(channel.channel as u32)) {
                continue;
            }
            // If healing modern batches and existing anchors were fully compatible, only complete missing stubs.
            // When any anchor is incompatible, all official facial channels are refreshed.
            if heal_only && incompatible.is_empty() && !missing_stubs.contains(&channel.channel) {
                continue;
            }
            let mut ids = Vec::new();
            let mut values = Vec::new();
            for (id, value) in slot.1.chunks_exact(4).zip(slot.2.chunks_exact(12)) {
                if !mapped.contains(&u32::from_le_bytes(id.try_into().unwrap())) {
                    ids.extend_from_slice(id);
                    values.extend_from_slice(value);
                }
            }
            ids.extend(channel.ids.iter().flat_map(|id| id.to_le_bytes()));
            values.extend(channel.vals.iter().flat_map(|v| v.to_le_bytes()));
            *slot = (ids.len() / 4, ids, values);
        }
        true
    }

    /// `(channel, force)` pairs from the config lists.
    ///
    /// Each list accepts single channels and inclusive ranges, e.g.
    /// `"111,113-116,127-160"`. When `legacy` is set the legacy force list is
    /// used instead of the normal one, because a 105 channel mod's slot
    /// numbering does not correspond to the target build's.
    #[allow(dead_code)]
    fn transplant_channels(&self, legacy: bool) -> Vec<(usize, bool)> {
        fn parse(list: &str, force: bool, out: &mut Vec<(usize, bool)>) {
            for item in list.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                match item.split_once('-') {
                    Some((a, b)) => {
                        if let (Ok(a), Ok(b)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>()) {
                            for ch in a..=b {
                                out.push((ch, force));
                            }
                        }
                    }
                    None => {
                        if let Ok(ch) = item.parse::<usize>() {
                            out.push((ch, force));
                        }
                    }
                }
            }
        }
        let mut out = Vec::new();
        if let Some(list) = &self.config.channel_transplant {
            parse(list, false, &mut out);
        }
        // an empty string means "not configured"; fall back to the normal force list
        let non_empty = |o: &Option<String>| o.as_ref().filter(|l| !l.trim().is_empty()).map(|s| s.to_string());
        let force_owned = if legacy {
            match &self.config.channel_transplant_force_legacy {
                Some(s) if s.trim().eq_ignore_ascii_case("none") => None,
                Some(s) if !s.trim().is_empty() => Some(s.clone()),
                _ => non_empty(&self.config.channel_transplant_force),
            }
        } else {
            non_empty(&self.config.channel_transplant_force)
        };
        let force_list = force_owned.as_deref();
        if let Some(list) = force_list {
            parse(list, true, &mut out);
        }
        out.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        out.dedup_by_key(|c| c.0);
        out
    }

    /// UV-aware references use the same correspondence for stub completion and
    /// whole-surface repair. Positional per-channel matching is only a fallback
    /// for older assets, rather than a competing Rover transfer algorithm.
    fn reference_channels(
        &self,
        asset: &transplant::ReferenceAsset,
        positions: &[u8],
        candidates: &[u32],
        partition: Option<&transplant::ComponentPartition>,
        channels: &[usize],
        tolerance: f32,
        diffusion: f32,
    ) -> Vec<transplant::Transplanted> {
        if let (Some(part), Some((face, eyes))) = (partition, self.surface_components) {
            if let Some(surface) =
                transplant::transfer_legacy_surface(asset, positions, part, face, eyes)
            {
                let remaining: Vec<_> = channels
                    .iter()
                    .copied()
                    .filter(|ch| !surface.channels.iter().any(|c| c.channel == *ch))
                    .collect();
                let mut result: Vec<_> = surface
                    .channels
                    .into_iter()
                    .filter(|c| channels.contains(&c.channel))
                    .collect();
                if !remaining.is_empty() {
                    result.extend(transplant::transplant_partitioned(
                        asset, positions, candidates, partition, &remaining, tolerance, diffusion,
                    ));
                }
                return result;
            }
        }
        transplant::transplant_partitioned(
            asset, positions, candidates, partition, channels, tolerance, diffusion,
        )
    }

    /// Overwrites the configured channels of `slots` with the target build's own
    /// data, matched onto the mod's vertices by position. Used by both the legacy
    /// and the modern path so a 105 channel mod gets the official 3.8 channels too.
    fn transplant_into(
        &self,
        slots: &mut [(usize, Vec<u8>, Vec<u8>)],
        position_buf: Option<&[u8]>,
        stride: usize,
        partition: Option<&transplant::ComponentPartition>,
    ) -> Vec<usize> {
        let mut transplanted = Vec::new();
        let Some(asset_rel) = &self.config.reference_asset else {
            return transplanted;
        };
        let Some(pos) = position_buf else {
            return transplanted;
        };
        let wanted = self.transplant_channels(true);
        if wanted.is_empty() {
            return transplanted;
        }
        // only fill channels that are still empty, unless explicitly forced
        // every listed channel is a candidate; forced ones are always replaced,
        // the others only when their vertex set disagrees with the reference
        let channels: Vec<usize> = wanted
            .iter()
            .map(|(ch, _)| *ch)
            .filter(|ch| !self.custom_shapekey_ids.contains(&(*ch as u32)))
            .collect();
        let forced: std::collections::HashSet<usize> = wanted.iter().filter(|(_, f)| *f).map(|(ch, _)| *ch).collect();
        if channels.is_empty() {
            return transplanted;
        }
        let tolerance = self
            .config
            .transplant_tolerance
            .as_deref()
            .and_then(|s| s.trim().parse::<f32>().ok())
            .unwrap_or(0.5);
        let diffusion = self
            .config
            .transplant_diffusion
            .as_deref()
            .and_then(|s| s.trim().parse::<f32>().ok())
            .unwrap_or(0.0);

        let asset = match transplant::load_asset(asset_rel) {
            Ok(a) => a,
            Err(e) => {
                log::warn!("shapekey reference asset '{}' is unavailable: {}", asset_rel, e);
                return transplanted;
            }
        };
        let candidates: Vec<u32> = (0..(pos.len() / 12) as u32).collect();
        for t in self.reference_channels(&asset, pos, &candidates, partition, &channels, tolerance, diffusion) {
            let ratio = t.matched as f32 / t.reference_len.max(1) as f32;
            // a forced channel is taken regardless of coverage: a mod whose mesh only
            // covers part of the face still needs the official data on the part it has
            let is_forced = forced.contains(&t.channel);
            if t.matched == 0 || (!is_forced && ratio < 0.5) || t.channel >= slots.len() || stride != 12 {
                continue;
            }
            if is_forced && ratio < 0.5 {
                info!(
                    "forced transplant of ch{} with only {:.1}% coverage",
                    t.channel,
                    ratio * 100.0
                );
            }
            // keep existing author data when it drives the same vertices as the
            // reference channel does; replace it when it drives a different set
            let existing = &slots[t.channel];
            if existing.0 > 2 && !is_forced {
                let ej: std::collections::HashSet<u32> = existing
                    .1
                    .chunks_exact(4)
                    .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect();
                let tj: std::collections::HashSet<u32> = t.ids.iter().copied().collect();
                let inter = ej.intersection(&tj).count();
                let union = ej.union(&tj).count().max(1);
                let jaccard = inter as f32 / union as f32;
                if jaccard >= 0.30 {
                    info!(
                        "kept author data for ch{} (vertex overlap with the reference {:.2})",
                        t.channel, jaccard
                    );
                    continue;
                }
                info!(
                    "replacing mis-mapped ch{} (vertex overlap with the reference only {:.2})",
                    t.channel, jaccard
                );
            }
            let id_bytes: Vec<u8> = t.ids.iter().flat_map(|i| i.to_le_bytes()).collect();
            let val_bytes: Vec<u8> = t.vals.iter().flat_map(|v| v.to_le_bytes()).collect();
            slots[t.channel] = (t.ids.len(), id_bytes, val_bytes);
            transplanted.push(t.channel);
            info!(
                "transplanted ch{}: {}/{} reference vertices matched ({:.1}%)",
                t.channel,
                t.matched,
                t.reference_len,
                ratio * 100.0
            );
        }
        transplanted
    }

    fn build_reconstructed_buffers(
        new_shapekeys: &[(usize, Vec<u8>, Vec<u8>)],
        batch_count: usize,
    ) -> Result<RebuildResult, String> {
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

/// Converts an f32 into an IEEE 754 half float (round to nearest even).
pub(crate) fn f32_to_f16(v: f32) -> u16 {
    let bits = v.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let exp = ((bits >> 23) & 0xff) as i32 - 127 + 15;
    let mant = bits & 0x007f_ffff;

    if exp >= 0x1f {
        return sign | 0x7c00; // inf / nan
    }
    if exp <= 0 {
        if exp < -10 {
            return sign; // underflow to zero
        }
        let m = ((mant | 0x0080_0000) >> (1 - exp)) as u32;
        let m = (m + 0x1000) >> 13;
        return sign | (m as u16 & 0x03ff);
    }
    let half = sign | ((exp as u16) << 10) | ((mant >> 13) as u16);
    let rem = mant & 0x1fff;
    if rem > 0x1000 || (rem == 0x1000 && (half & 1) == 1) {
        half.wrapping_add(1)
    } else {
        half
    }
}

/// Scales every f16 component of a stride wide payload in place.
fn scale_payload(payload: &mut [u8], stride: usize, factor: f32) {
    if (factor - 1.0).abs() < 1e-6 {
        return;
    }
    for chunk in payload.chunks_exact_mut(stride) {
        for c in 0..stride / 2 {
            let u = u16::from_le_bytes([chunk[c * 2], chunk[c * 2 + 1]]);
            let scaled = f16_to_f32(u) * factor;
            chunk[c * 2..c * 2 + 2].copy_from_slice(&f32_to_f16(scaled).to_le_bytes());
        }
    }
}

/// Converts an IEEE 754 half-precision float (16-bit) to f32.
pub(crate) fn f16_to_f32(h: u16) -> f32 {
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

#[cfg(test)]
mod layout_tests {
    use super::*;

    fn config() -> ShapeKeyFixConfig {
        ShapeKeyFixConfig {
            trigger_hash: Vec::new(),
            section_rewrites: None,
            custom_values_array: None,
            expression_remap: None,
            offset_stride: Some(12),
            channel_substitutes: None,
            reference_asset: None,
            channel_transplant: None,
            channel_transplant_force: None,
            channel_transplant_force_legacy: None,
            transplant_tolerance: None,
            transplant_diffusion: None,
        }
    }

    /// 128 u32 slots per batch: `counts` are per-channel vertex counts.
    fn batch_slots(counts: &[u32; 127]) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        let mut total = 0u32;
        out.extend_from_slice(&0u32.to_le_bytes());
        for c in counts {
            total += *c;
            out.extend_from_slice(&total.to_le_bytes());
        }
        out
    }

    struct TempSkref(std::path::PathBuf);

    impl Drop for TempSkref {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0.join("reference.skref"));
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    fn write_temp_skref(
        tag: &str,
        pos: &[[f32; 3]],
        uvs: &[[f32; 2]],
        channels: &[(u32, &[u32], [u16; 6])],
    ) -> (TempSkref, String, Vec<u8>) {
        let dir = std::env::temp_dir().join(format!("{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("reference.skref");
        let pos_bytes: Vec<u8> = pos.iter().flatten().flat_map(|x| x.to_le_bytes()).collect();
        let mut asset = b"SKREF1\0\0".to_vec();
        asset.extend((pos.len() as u32).to_le_bytes());
        asset.extend((channels.len() as u32).to_le_bytes());
        asset.extend_from_slice(&pos_bytes);
        for &(ch, vids, val) in channels {
            asset.extend(ch.to_le_bytes());
            asset.extend((vids.len() as u32).to_le_bytes());
            for &id in vids {
                asset.extend(id.to_le_bytes());
            }
            for _ in 0..vids.len() {
                for v in val {
                    asset.extend(v.to_le_bytes());
                }
            }
        }
        asset.extend_from_slice(b"SKUV1\0\0\0");
        for uv in uvs {
            asset.extend_from_slice(&uv[0].to_le_bytes());
            asset.extend_from_slice(&uv[1].to_le_bytes());
            asset.extend(2u32.to_le_bytes());
        }
        std::fs::write(&path, asset).unwrap();
        let ref_str = path.to_string_lossy().into_owned();
        (TempSkref(dir), ref_str, pos_bytes)
    }

    #[test]
    fn legacy_rebuild_replaces_author_motion_including_reference_zeroes() {
        let (_guard, ref_path, positions) = write_temp_skref(
            "surface_rebuild",
            &[[0., 0., 0.], [1., 0., 0.]],
            &[[0., 0.], [0., 0.]],
            &[(7, &[0], [0x3c00, 0, 0, 0, 0, 0])],
        );
        let mut cfg = config();
        cfg.reference_asset = Some(ref_path);
        cfg.channel_transplant_force_legacy = Some("7".into());
        let fixer = ShapeKeyRebuilder::new(&cfg, "RoverFemale").unwrap();
        let mut counts = [0; 127];
        counts[7] = 3;
        let ids: Vec<u8> = [0u32, 1, 2].iter().flat_map(|x| x.to_le_bytes()).collect();
        let values = [0x4000u16, 0, 0, 0, 0, 0]
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect::<Vec<_>>()
            .repeat(3);
        let part = transplant::ComponentPartition {
            face_candidates: vec![0, 1],
            texcoords: vec![0; 32],
            ..Default::default()
        };
        let result = fixer
            .rebuild_buffers_partitioned(&batch_slots(&counts), &ids, &values, Some(&positions), Some(&part))
            .unwrap();
        assert_eq!(
            result.vertex_id_buf,
            [2u32, 0].iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<_>>(),
            "unmatched author vertex must survive forced channel completion"
        );
        assert_eq!(
            result.vertex_offset_buf,
            [0x4000u16, 0, 0, 0, 0, 0, 0x3c00, 0, 0, 0, 0, 0]
                .iter()
                .flat_map(|x| x.to_le_bytes())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn converted_two_batch_expressions_self_heal_and_then_stay_identical() {
        let (_guard, ref_path, positions) = write_temp_skref(
            "surface_heal",
            &[[0., 0., 0.], [1., 0., 0.]],
            &[[0., 0.], [0., 0.]],
            &[
                (44, &[0], [0x3c00, 0, 0, 0, 0, 0]),
                (48, &[0], [0x3c00, 0, 0, 0, 0, 0]),
            ],
        );
        let mut cfg = config();
        cfg.reference_asset = Some(ref_path);
        let fixer = ShapeKeyRebuilder::new(&cfg, "RoverFemale").unwrap();
        let mut counts = [0; 127];
        counts[44] = 2;
        counts[48] = 2;
        let off = [batch_slots(&counts), batch_slots(&[0; 127])].concat();
        let ids: Vec<u8> = [0u32, 1, 0, 1].iter().flat_map(|x| x.to_le_bytes()).collect();
        let vals = [0x4000u16, 0, 0, 0, 0, 0]
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect::<Vec<_>>()
            .repeat(4);
        let part = transplant::ComponentPartition {
            face_candidates: vec![0, 1],
            texcoords: vec![0; 32],
            ..Default::default()
        };
        let fixed = fixer
            .rebuild_buffers_partitioned(&off, &ids, &vals, Some(&positions), Some(&part))
            .unwrap();
        assert_ne!(
            fixed.vertex_offset_buf, vals,
            "a converted layout must not hide incorrect populated channels"
        );
        assert_eq!(
            fixed.vertex_id_buf,
            [0u32, 0].iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<_>>()
        );
        let again = fixer
            .rebuild_buffers_partitioned(
                &fixed.offset_buf,
                &fixed.vertex_id_buf,
                &fixed.vertex_offset_buf,
                Some(&positions),
                Some(&part),
            )
            .unwrap();
        assert_eq!(fixed.offset_buf, again.offset_buf);
        assert_eq!(fixed.vertex_id_buf, again.vertex_id_buf);
        assert_eq!(fixed.vertex_offset_buf, again.vertex_offset_buf);
    }

    #[test]
    fn converted_two_batch_with_unpopulated_mouth_anchors_preserves_authored_channels() {
        let (_guard, ref_path, positions) = write_temp_skref(
            "surface_unpop",
            &[[0., 0., 0.], [1., 0., 0.]],
            &[[0., 0.], [0., 0.]],
            &[
                (44, &[0], [0x3c00, 0, 0, 0, 0, 0]),
                (75, &[0], [0x3c00, 0, 0, 0, 0, 0]),
            ],
        );
        let mut cfg = config();
        cfg.reference_asset = Some(ref_path);
        let fixer = ShapeKeyRebuilder::new(&cfg, "RoverFemale").unwrap();
        let mut counts = [0; 127];
        counts[44] = 1;
        // ch 75 is unpopulated (0 count) in the mod
        let off = [batch_slots(&counts), batch_slots(&[0; 127])].concat();
        let ids: Vec<u8> = 0u32.to_le_bytes().to_vec();
        let vals: Vec<u8> = [0x3c00u16, 0, 0, 0, 0, 0]
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect();
        let part = transplant::ComponentPartition {
            face_candidates: vec![0, 1],
            texcoords: vec![0; 32],
            ..Default::default()
        };
        let fixed = fixer
            .rebuild_buffers_partitioned(&off, &ids, &vals, Some(&positions), Some(&part))
            .unwrap();
        // Channel 75 must not be populated by self-healing since ch 44 agreed and ch 75 was unpopulated.
        let ch75_start = u32::from_le_bytes(fixed.offset_buf[75 * 4..76 * 4].try_into().unwrap());
        let ch75_end = u32::from_le_bytes(fixed.offset_buf[76 * 4..77 * 4].try_into().unwrap());
        assert_eq!(
            ch75_start, ch75_end,
            "unpopulated anchor channel must not trigger self-healing"
        );
        assert_eq!(fixed.vertex_offset_buf, vals);
    }

    #[test]
    fn custom_shapekeys_registered_in_ini_are_protected_and_unregistered_105_is_populated() {
        let (_guard, ref_path, positions) = write_temp_skref(
            "custom_sk",
            &[[0., 0., 0.], [1., 0., 0.]],
            &[[0., 0.], [0., 0.]],
            &[
                (105, &[0], [0x3c00, 0, 0, 0, 0, 0]),
                (108, &[0], [0x3c00, 0, 0, 0, 0, 0]),
            ],
        );

        let mut cfg = config();
        cfg.reference_asset = Some(ref_path);
        let mut custom_ids = std::collections::HashSet::new();
        custom_ids.insert(108); // Mod author uses channel 108 as custom body slider!

        let fixer = ShapeKeyRebuilder::new(&cfg, "RoverFemale")
            .unwrap()
            .with_custom_shapekeys(custom_ids);

        let mut counts = [0; 127];
        counts[108] = 1; // Channel 108 has custom author displacement
        let off = [batch_slots(&counts), batch_slots(&[0; 127])].concat();
        let ids: Vec<u8> = 1u32.to_le_bytes().to_vec(); // Vertex 1 (body/custom)
        let vals: Vec<u8> = [0x4200u16, 0, 0, 0, 0, 0]
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect();

        let part = transplant::ComponentPartition {
            face_candidates: vec![0],
            texcoords: vec![0; 32],
            ..Default::default()
        };

        let fixed = fixer
            .rebuild_buffers_partitioned(&off, &ids, &vals, Some(&positions), Some(&part))
            .unwrap();

        // 1. Channel 108 must be 100% protected: must keep author's original displacement
        let ch108_start = u32::from_le_bytes(fixed.offset_buf[108 * 4..109 * 4].try_into().unwrap()) as usize;
        let ch108_end = u32::from_le_bytes(fixed.offset_buf[109 * 4..110 * 4].try_into().unwrap()) as usize;
        assert_eq!(ch108_end - ch108_start, 1, "custom channel 108 must retain author vertex");
        let val108 = &fixed.vertex_offset_buf[ch108_start * 12..ch108_end * 12];
        assert_eq!(val108, &vals, "custom channel 108 must not be overwritten by reference asset");

        // 2. Channel 105 (not registered as custom) must be populated with official facial data
        let ch105_start = u32::from_le_bytes(fixed.offset_buf[105 * 4..106 * 4].try_into().unwrap()) as usize;
        let ch105_end = u32::from_le_bytes(fixed.offset_buf[106 * 4..107 * 4].try_into().unwrap()) as usize;
        assert_eq!(ch105_end - ch105_start, 1, "unregistered channel 105 must be populated with official viseme");
    }

    /// Regression: a modern mod whose trailing channels 117..=126 are populated
    /// (they are 2-vertex stubs in the real game data) used to be considered
    /// broken and got rebuilt, silently dropping those channels and re-packing
    /// every slice. It must now be left alone.
    #[test]
    fn modern_buffers_with_populated_trailing_channels_are_left_alone() {
        let mut counts = [0u32; 127];
        for c in counts.iter_mut() {
            *c = 3;
        }
        let mut buf = Vec::new();
        buf.extend_from_slice(&batch_slots(&counts));
        buf.extend_from_slice(&batch_slots(&counts));
        assert_eq!(ShapeKeyLayout::detect(&buf), ShapeKeyLayout::Modern);
        let cfg = config();
        let fixer = ShapeKeyRebuilder::new(&cfg, "RoverFemale").unwrap();
        assert!(!fixer.needs_fix(&buf));
    }

    /// A modern mod whose viseme / strong-wink channels are 2-vertex stubs must
    /// get exactly those channels completed from the configured substitutes, and
    /// every other channel must stay byte-identical.
    #[test]
    fn modern_stub_channels_are_completed_from_substitutes() {
        assert_eq!(ShapeKeyLayout::detect(&[1, 2, 3]), ShapeKeyLayout::Malformed);
        let mut cfg = config();
        cfg.channel_substitutes = Some([(113.to_string(), 44.to_string())].into_iter().collect());
        let fixer = ShapeKeyRebuilder::new(&cfg, "RoverFemale").unwrap();

        // batch 0: ch44 = 10 verts, ch113 = 2 verts (stub); batch 1: ch0 = 4 verts
        let mut counts0 = [0u32; 127];
        counts0[44] = 10;
        counts0[113] = 2;
        let mut counts1 = [0u32; 127];
        counts1[0] = 4;
        let mut off = Vec::new();
        off.extend_from_slice(&batch_slots(&counts0));
        off.extend_from_slice(&batch_slots(&counts1));

        let mut ids = Vec::new();
        let mut vals = Vec::new();
        for ch in [44usize, 113] {
            for i in 0..counts0[ch] {
                ids.extend_from_slice(&((ch * 100 + i as usize) as u32).to_le_bytes());
                vals.extend_from_slice(&[ch as u8; 12]);
            }
        }
        for i in 0..4usize {
            ids.extend_from_slice(&(9000 + i as u32).to_le_bytes());
            vals.extend_from_slice(&[7u8; 12]);
        }

        assert!(fixer.needs_fix(&off));
        let out = fixer.rebuild_buffers(&off, &ids, &vals, None).unwrap();

        let slots: Vec<u32> = out
            .offset_buf
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        let cnt = |k: usize| slots[k + 1] - slots[k];
        assert_eq!(cnt(44), 10);
        assert_eq!(cnt(113), 10, "stub channel must be completed");
        // batch 1 starts at slot 128 in the flattened table
        assert_eq!(slots[129] - slots[128], 4);
        assert_eq!(slots[255], 4);
        // the completed payload equals the source channel payload
        let a = (slots[44] as usize * 12)..(slots[45] as usize * 12);
        let b = (slots[113] as usize * 12)..(slots[114] as usize * 12);
        assert_eq!(out.vertex_offset_buf[a], out.vertex_offset_buf[b]);
        let ia = (slots[44] as usize * 4)..(slots[45] as usize * 4);
        let ib = (slots[113] as usize * 4)..(slots[114] as usize * 4);
        assert_eq!(out.vertex_id_buf[ia], out.vertex_id_buf[ib]);
    }

    #[test]
    fn legacy_rebuild_applies_scaled_channel_substitutes() {
        use crate::config_loader::{SymmetryFilter, TargetShapeKey};
        use std::collections::HashMap;

        let mut cfg = config();
        let mut remap = HashMap::new();
        remap.insert(
            22u16,
            vec![TargetShapeKey {
                target_channel: 44,
                filter: SymmetryFilter::All,
            }],
        );
        cfg.expression_remap = Some(remap);
        cfg.channel_substitutes = Some([(113.to_string(), "44:0.72".to_string())].into_iter().collect());

        let mut counts = [0u32; 127];
        counts[22] = 5;
        let offset = batch_slots(&counts);
        assert_eq!(ShapeKeyLayout::detect(&offset), ShapeKeyLayout::Legacy);
        let mut ids = Vec::new();
        let mut vals = Vec::new();
        for i in 0..5u32 {
            ids.extend_from_slice(&(100 + i).to_le_bytes());
            // Pack f16 values representing 1.0
            let f16_one = f32_to_f16(1.0);
            for _ in 0..6 {
                vals.extend_from_slice(&f16_one.to_le_bytes());
            }
        }

        let fixer = ShapeKeyRebuilder::new(&cfg, "RoverFemale").unwrap();
        assert!(fixer.needs_fix(&offset));
        let out = fixer.rebuild_buffers(&offset, &ids, &vals, None).unwrap();

        let slots: Vec<u32> = out
            .offset_buf
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(out.offset_buf.len(), 512);
        assert_eq!(slots[0], 0);
        assert!(slots.windows(2).all(|w| w[1] >= w[0]), "offsets must be monotonic");
        assert_eq!(out.batch0_count, slots[127]);
        let cnt = |k: usize| slots[k + 1] - slots[k];
        assert_eq!(cnt(44), 5, "legacy 22 must remap 1:1 to 44");
        assert_eq!(cnt(113), 5, "channel 113 must be completed from 44 via substitutes");

        // Verify that 113 payload is scaled by 0.72
        let start_113 = slots[113] as usize * 12;
        let val_113_u16 = u16::from_le_bytes([out.vertex_offset_buf[start_113], out.vertex_offset_buf[start_113 + 1]]);
        let val_113_f32 = f16_to_f32(val_113_u16);
        assert!(
            (val_113_f32 - 0.72).abs() < 0.01,
            "expected scaled ~0.72, got {}",
            val_113_f32
        );
    }

    #[test]
    fn heal_only_heals_hybrid_uv_head_but_skips_fully_custom_uv_head() {
        let (_guard, ref_path, ref_pos_bytes) = write_temp_skref(
            "hybrid_uv_heal",
            &[[0.0, 0.0, 0.0], [1.0, 0.0, 0.0], [2.0, 0.0, 0.0]],
            &[[0.1, 0.1], [0.2, 0.2], [0.3, 0.3]],
            &[
                (44, &[0, 1, 2], [0x3c00, 0, 0, 0, 0, 0]),
                (75, &[0, 1, 2], [0x3c00, 0, 0, 0, 0, 0]),
            ],
        );

        let mut cfg = config();
        cfg.reference_asset = Some(ref_path);
        let fixer = ShapeKeyRebuilder::new(&cfg, "RoverFemale").unwrap();

        let mut counts = [0; 127];
        counts[44] = 3;
        let off = [batch_slots(&counts), batch_slots(&[0; 127])].concat();
        let ids: Vec<u8> = [0u32, 1, 2].iter().flat_map(|x| x.to_le_bytes()).collect();
        // Divergent ch 44 payload (2.0 instead of 1.0)
        let vals = [0x4000u16, 0, 0, 0, 0, 0]
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect::<Vec<_>>()
            .repeat(3);

        let build_tc = |pairs: &[[f32; 2]]| -> Vec<u8> {
            let mut tc = Vec::with_capacity(pairs.len() * 16);
            for &[u, v] in pairs {
                tc.extend_from_slice(&f32_to_f16(u).to_le_bytes());
                tc.extend_from_slice(&f32_to_f16(v).to_le_bytes());
                tc.extend_from_slice(&[0; 12]);
            }
            tc
        };

        // 1) Hybrid head: 2/3 (66.7%) official UVs, 1/3 custom UV -> must heal divergent ch44 and complete ch75.
        let part_hybrid = transplant::ComponentPartition {
            face_candidates: vec![0, 1, 2],
            texcoords: build_tc(&[[0.1, 0.1], [0.2, 0.2], [0.85, 0.85]]),
            ..Default::default()
        };
        let healed = fixer
            .rebuild_buffers_partitioned(&off, &ids, &vals, Some(&ref_pos_bytes), Some(&part_hybrid))
            .unwrap();
        let ch75_s = u32::from_le_bytes(healed.offset_buf[75 * 4..76 * 4].try_into().unwrap());
        let ch75_e = u32::from_le_bytes(healed.offset_buf[76 * 4..77 * 4].try_into().unwrap());
        assert_eq!(ch75_e - ch75_s, 3, "hybrid head must complete missing ch75");

        // 2) Fully custom head: 1/3 (33.3%) official UV (< 50%) -> must preserve custom ch44 and skip heal_only.
        let part_custom = transplant::ComponentPartition {
            face_candidates: vec![0, 1, 2],
            texcoords: build_tc(&[[0.1, 0.1], [0.75, 0.75], [0.85, 0.85]]),
            ..Default::default()
        };
        let preserved = fixer
            .rebuild_buffers_partitioned(&off, &ids, &vals, Some(&ref_pos_bytes), Some(&part_custom))
            .unwrap();
        let ch75_s_c = u32::from_le_bytes(preserved.offset_buf[75 * 4..76 * 4].try_into().unwrap());
        let ch75_e_c = u32::from_le_bytes(preserved.offset_buf[76 * 4..77 * 4].try_into().unwrap());
        assert_eq!(ch75_s_c, ch75_e_c, "fully custom head (<50% UV) must skip heal_only");
        assert_eq!(preserved.vertex_offset_buf, vals);
    }
}
