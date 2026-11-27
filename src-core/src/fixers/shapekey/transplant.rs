//! Transfer expression fields through one component, position and UV correspondence.
//! Static vertices and split seams participate in the same map as moving vertices.
//! Authored mouth motion distinguishes touching upper and lower surfaces. The older
//! per-channel positional matcher remains a fallback for assets without UV metadata.

use std::io::{Read, Write};

use super::rebuilder::{f16_to_f32, f32_to_f16};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RigKind {
    #[default]
    Unspecified = 0,
    Female = 1,
    Male = 2,
}

/// Binary layout (see `scripts/build_shapekey_ref_asset.py`).
#[derive(Default)]
pub struct ReferenceAsset {
    pub positions: Vec<[f32; 3]>,
    /// channel -> (vertex ids, 6 x f16 per entry)
    pub channels: Vec<(usize, Vec<u32>, Vec<u16>)>,
    pub surface: Vec<([f32; 2], u32)>,
    pub vectors: Vec<[u8; 8]>,
    pub colors: Vec<[u8; 4]>,
    pub rig_kind: RigKind,
    pub roles: Vec<ComponentType>,
}

const MAGIC_V1: &[u8; 8] = b"SKREF1\0\0";
const MAGIC_V2: &[u8; 8] = b"SKREF2\0\0";
const MAGIC_V2_BROTLI: &[u8; 8] = b"SKREF2B\0";

const FLAG_VECTORS: u8 = 1 << 0;
const FLAG_COLORS: u8 = 1 << 1;
const FLAG_ROLES: u8 = 1 << 2;

fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn push_varint(out: &mut Vec<u8>, mut n: u32) {
    while n >= 0x80 {
        out.push(((n & 0x7F) as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

fn read_varint(buf: &[u8], cursor: &mut usize) -> Result<u32, String> {
    let mut val = 0u32;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*cursor).ok_or("truncated varint")?;
        *cursor += 1;
        if shift >= 32 {
            return Err("varint overflow".into());
        }
        val |= ((b & 0x7F) as u32) << shift;
        if b & 0x80 == 0 {
            return Ok(val);
        }
        shift += 7;
    }
}

fn read_delta_indices(buf: &[u8], cursor: &mut usize, count: usize) -> Result<Vec<u32>, String> {
    let mut ids = Vec::with_capacity(count);
    let mut prev = 0u32;
    for _ in 0..count {
        let delta = read_varint(buf, cursor)?;
        prev = prev.checked_add(delta).ok_or("delta index overflow")?;
        ids.push(prev);
    }
    Ok(ids)
}

fn role_to_u8(role: ComponentType) -> u8 {
    match role {
        ComponentType::Other => 0,
        ComponentType::FaceSkin => 1,
        ComponentType::TeethUpper => 2,
        ComponentType::TeethLower => 3,
        ComponentType::Eyes => 4,
    }
}

fn u8_to_role(v: u8) -> Result<ComponentType, String> {
    match v {
        0 => Ok(ComponentType::Other),
        1 => Ok(ComponentType::FaceSkin),
        2 => Ok(ComponentType::TeethUpper),
        3 => Ok(ComponentType::TeethLower),
        4 => Ok(ComponentType::Eyes),
        _ => Err(format!("invalid vertex role byte: {v}")),
    }
}

impl ReferenceAsset {
    pub fn parse(buf: &[u8]) -> Result<Self, String> {
        if buf.len() >= 8 && &buf[0..8] == MAGIC_V2_BROTLI {
            let mut decompressed = Vec::new();
            let mut reader = brotli::Decompressor::new(&buf[8..], 4096);
            reader
                .read_to_end(&mut decompressed)
                .map_err(|e| format!("brotli decompress failed: {e}"))?;
            return Self::parse_v2(&decompressed);
        }
        if buf.len() >= 8 && &buf[0..8] == MAGIC_V2 {
            return Self::parse_v2(buf);
        }
        Self::parse_v1(buf)
    }

    fn parse_v1(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 16 || &buf[0..8] != MAGIC_V1 {
            return Err("not a SKREF asset".into());
        }
        let pos_count = u32_at(buf, 8).ok_or("truncated header")? as usize;
        let channel_count = u32_at(buf, 12).ok_or("truncated header")? as usize;
        let mut cursor = 16;

        let pos_bytes = pos_count.checked_mul(12).ok_or("position count overflow")?;
        let raw = buf.get(cursor..cursor + pos_bytes).ok_or("truncated positions")?;
        let positions: Vec<[f32; 3]> = raw
            .chunks_exact(12)
            .map(|c| {
                [
                    f32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                    f32::from_le_bytes([c[4], c[5], c[6], c[7]]),
                    f32::from_le_bytes([c[8], c[9], c[10], c[11]]),
                ]
            })
            .collect();
        cursor += pos_bytes;

        let mut channels = Vec::with_capacity(channel_count);
        for _ in 0..channel_count {
            let ch = u32_at(buf, cursor).ok_or("truncated channel header")? as usize;
            let n = u32_at(buf, cursor + 4).ok_or("truncated channel header")? as usize;
            cursor += 8;
            let ids_len = n.checked_mul(4).ok_or("id count overflow")?;
            let vals_len = n.checked_mul(12).ok_or("val count overflow")?;
            let id_raw = buf.get(cursor..cursor + ids_len).ok_or("truncated ids")?;
            let ids: Vec<u32> = id_raw
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            cursor += ids_len;
            let val_raw = buf.get(cursor..cursor + vals_len).ok_or("truncated vals")?;
            let vals: Vec<u16> = val_raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            cursor += vals_len;
            channels.push((ch, ids, vals));
        }
        let mut surface = Vec::new();
        if buf.get(cursor..cursor + 8) == Some(b"SKUV1\0\0\0") {
            cursor += 8;
            let raw = buf
                .get(cursor..cursor + pos_count * 12)
                .ok_or("truncated surface metadata")?;
            for row in raw.chunks_exact(12) {
                surface.push((
                    [
                        f32::from_le_bytes(row[0..4].try_into().unwrap()),
                        f32::from_le_bytes(row[4..8].try_into().unwrap()),
                    ],
                    u32::from_le_bytes(row[8..12].try_into().unwrap()),
                ));
            }
            cursor += pos_count * 12;
        }
        let mut vectors = Vec::new();
        if buf.get(cursor..cursor + 8) == Some(b"SKVT1\0\0\0") {
            cursor += 8;
            let raw = buf
                .get(cursor..cursor + pos_count * 8)
                .ok_or("truncated reference vectors")?;
            vectors = raw.chunks_exact(8).map(|row| row.try_into().unwrap()).collect();
            cursor += pos_count * 8;
        }
        let mut colors = Vec::new();
        if buf.get(cursor..cursor + 8) == Some(b"SKCL1\0\0\0") {
            cursor += 8;
            let raw = buf
                .get(cursor..cursor + pos_count * 4)
                .ok_or("truncated reference colors")?;
            colors = raw.chunks_exact(4).map(|row| [row[0], row[1], row[2], row[3]]).collect();
        }
        let rig_kind = if (40000..=45000).contains(&positions.len()) {
            RigKind::Female
        } else if (65000..=70000).contains(&positions.len()) {
            RigKind::Male
        } else {
            RigKind::Unspecified
        };
        Ok(Self {
            positions,
            channels,
            surface,
            vectors,
            colors,
            rig_kind,
            roles: Vec::new(),
        })
    }

    fn parse_v2(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 20 || &buf[0..8] != MAGIC_V2 {
            return Err("not a SKREF2 asset".into());
        }
        let rig_kind = match buf[8] {
            0 => RigKind::Unspecified,
            1 => RigKind::Female,
            2 => RigKind::Male,
            other => return Err(format!("invalid rig kind: {other}")),
        };
        let flags = buf[9];
        let pos_count = u32_at(buf, 12).ok_or("truncated SKREF2 header")? as usize;
        let channel_count = u32_at(buf, 16).ok_or("truncated SKREF2 header")? as usize;
        let mut cursor = 20;

        let pos_bytes = pos_count.checked_mul(12).ok_or("position count overflow")?;
        let pos_raw = buf.get(cursor..cursor + pos_bytes).ok_or("truncated positions")?;
        let positions: Vec<[f32; 3]> = pos_raw
            .chunks_exact(12)
            .map(|c| {
                [
                    f32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                    f32::from_le_bytes([c[4], c[5], c[6], c[7]]),
                    f32::from_le_bytes([c[8], c[9], c[10], c[11]]),
                ]
            })
            .collect();
        cursor += pos_bytes;

        let surf_bytes = pos_count.checked_mul(5).ok_or("surface count overflow")?;
        let surf_raw = buf.get(cursor..cursor + surf_bytes).ok_or("truncated surface")?;
        let surface: Vec<([f32; 2], u32)> = surf_raw
            .chunks_exact(5)
            .map(|row| {
                let u = f16_to_f32(u16::from_le_bytes([row[0], row[1]]));
                let v = f16_to_f32(u16::from_le_bytes([row[2], row[3]]));
                ([u, v], row[4] as u32)
            })
            .collect();
        cursor += surf_bytes;

        let mut roles = Vec::new();
        if flags & FLAG_ROLES != 0 {
            let role_raw = buf.get(cursor..cursor + pos_count).ok_or("truncated roles")?;
            roles = role_raw.iter().copied().map(u8_to_role).collect::<Result<_, _>>()?;
            cursor += pos_count;
        }

        let mut vectors = Vec::new();
        if flags & FLAG_VECTORS != 0 {
            let count = u32_at(buf, cursor).ok_or("truncated vector count")? as usize;
            cursor += 4;
            let indices = read_delta_indices(buf, &mut cursor, count)?;
            let data_len = count.checked_mul(8).ok_or("vector count overflow")?;
            let data = buf.get(cursor..cursor + data_len).ok_or("truncated vectors")?;
            cursor += data_len;
            vectors = vec![[0u8; 8]; pos_count];
            for (idx, row) in indices.into_iter().zip(data.chunks_exact(8)) {
                let dst = vectors.get_mut(idx as usize).ok_or("vector index out of range")?;
                *dst = row.try_into().unwrap();
            }
        }

        let mut colors = Vec::new();
        if flags & FLAG_COLORS != 0 {
            let count = u32_at(buf, cursor).ok_or("truncated color count")? as usize;
            cursor += 4;
            let indices = read_delta_indices(buf, &mut cursor, count)?;
            let data_len = count.checked_mul(4).ok_or("color count overflow")?;
            let data = buf.get(cursor..cursor + data_len).ok_or("truncated colors")?;
            cursor += data_len;
            colors = vec![[0u8; 4]; pos_count];
            for (idx, row) in indices.into_iter().zip(data.chunks_exact(4)) {
                let dst = colors.get_mut(idx as usize).ok_or("color index out of range")?;
                *dst = [row[0], row[1], row[2], row[3]];
            }
        }

        let mut channels = Vec::with_capacity(channel_count);
        for _ in 0..channel_count {
            let ch = u32_at(buf, cursor).ok_or("truncated channel header")? as usize;
            let n = u32_at(buf, cursor + 4).ok_or("truncated channel header")? as usize;
            cursor += 8;
            let ids = read_delta_indices(buf, &mut cursor, n)?;
            let val_bytes = n.checked_mul(6).ok_or("val count overflow")?;
            let val_raw = buf.get(cursor..cursor + val_bytes).ok_or("truncated vals")?;
            cursor += val_bytes;
            let mut vals = Vec::with_capacity(n * 6);
            for chunk in val_raw.chunks_exact(6) {
                vals.push(u16::from_le_bytes([chunk[0], chunk[1]]));
                vals.push(u16::from_le_bytes([chunk[2], chunk[3]]));
                vals.push(u16::from_le_bytes([chunk[4], chunk[5]]));
                vals.extend_from_slice(&[0, 0, 0]);
            }
            channels.push((ch, ids, vals));
        }

        Ok(Self {
            positions,
            channels,
            surface,
            vectors,
            colors,
            rig_kind,
            roles,
        })
    }

    /// Serializes a compact, Brotli-compressed `SKREF2B` asset keeping only
    /// vertices in `keep_components` (and stripping redundant zero normal-deltas
    /// and unused per-component attributes).
    pub fn to_skref2_brotli(
        &self,
        keep_components: &[u32],
        hair_component: Option<u32>,
        face_component: u32,
    ) -> Result<Vec<u8>, String> {
        self.to_skref2_brotli_with_quality(keep_components, hair_component, face_component, 11)
    }

    pub fn to_skref2_brotli_with_quality(
        &self,
        keep_components: &[u32],
        hair_component: Option<u32>,
        face_component: u32,
        quality: u32,
    ) -> Result<Vec<u8>, String> {
        if self.surface.len() != self.positions.len() {
            return Err("surface metadata length mismatch".into());
        }
        let mut active = Vec::new();
        let mut remap = vec![u32::MAX; self.positions.len()];
        for (old_idx, (_, comp)) in self.surface.iter().enumerate() {
            if keep_components.contains(comp) {
                remap[old_idx] = active.len() as u32;
                active.push(old_idx);
            }
        }
        let npc = active.len();
        let has_roles = self.rig_kind != RigKind::Unspecified || !self.roles.is_empty();
        let hair_indices: Vec<usize> = match hair_component {
            Some(hc) if self.vectors.len() == self.positions.len() => active
                .iter()
                .enumerate()
                .filter_map(|(k, &old)| (self.surface[old].1 == hc).then_some(k))
                .collect(),
            _ => Vec::new(),
        };
        let color_indices: Vec<usize> = if self.colors.len() == self.positions.len() {
            active
                .iter()
                .enumerate()
                .filter_map(|(k, &old)| (self.surface[old].1 == face_component).then_some(k))
                .collect()
        } else {
            Vec::new()
        };

        let mut flags = 0u8;
        if !hair_indices.is_empty() {
            flags |= FLAG_VECTORS;
        }
        if !color_indices.is_empty() {
            flags |= FLAG_COLORS;
        }
        if has_roles {
            flags |= FLAG_ROLES;
        }

        let mut raw = Vec::with_capacity(npc * 20);
        raw.extend_from_slice(MAGIC_V2);
        raw.push(self.rig_kind as u8);
        raw.push(flags);
        raw.extend_from_slice(&0u16.to_le_bytes());
        raw.extend_from_slice(&(npc as u32).to_le_bytes());
        raw.extend_from_slice(&(self.channels.len() as u32).to_le_bytes());

        for &old in &active {
            for f in self.positions[old] {
                raw.extend_from_slice(&f.to_le_bytes());
            }
        }
        for &old in &active {
            let (uv, comp) = self.surface[old];
            let u = f32_to_f16(uv[0]);
            let v = f32_to_f16(uv[1]);
            if (f16_to_f32(u) - uv[0]).abs() > 1e-6 || (f16_to_f32(v) - uv[1]).abs() > 1e-6 {
                return Err(format!("non-f16 UV at vertex {old}: {uv:?}"));
            }
            let comp_u8 = u8::try_from(comp).map_err(|_| format!("component id out of u8 range: {comp}"))?;
            raw.extend_from_slice(&u.to_le_bytes());
            raw.extend_from_slice(&v.to_le_bytes());
            raw.push(comp_u8);
        }
        if has_roles {
            for &old in &active {
                let role = if !self.roles.is_empty() {
                    self.roles[old]
                } else {
                    ref_vertex_component(self.positions.len(), old).unwrap_or(ComponentType::Other)
                };
                raw.push(role_to_u8(role));
            }
        }
        if !hair_indices.is_empty() {
            raw.extend_from_slice(&(hair_indices.len() as u32).to_le_bytes());
            let mut prev = 0u32;
            for &k in &hair_indices {
                push_varint(&mut raw, k as u32 - prev);
                prev = k as u32;
            }
            for &k in &hair_indices {
                raw.extend_from_slice(&self.vectors[active[k]]);
            }
        }
        if !color_indices.is_empty() {
            raw.extend_from_slice(&(color_indices.len() as u32).to_le_bytes());
            let mut prev = 0u32;
            for &k in &color_indices {
                push_varint(&mut raw, k as u32 - prev);
                prev = k as u32;
            }
            for &k in &color_indices {
                raw.extend_from_slice(&self.colors[active[k]]);
            }
        }
        for (ch, ids, vals) in &self.channels {
            let mut kept_ids = Vec::new();
            let mut kept_vals = Vec::new();
            for (&old_id, chunk) in ids.iter().zip(vals.chunks_exact(6)) {
                let new_id = remap
                    .get(old_id as usize)
                    .copied()
                    .filter(|&v| v != u32::MAX);
                if let Some(id) = new_id {
                    if chunk[3] != 0 || chunk[4] != 0 || chunk[5] != 0 {
                        return Err(format!("non-zero trailing displacement in ch{ch} at {old_id}"));
                    }
                    kept_ids.push(id);
                    kept_vals.extend_from_slice(&chunk[..3]);
                }
            }
            raw.extend_from_slice(&(*ch as u32).to_le_bytes());
            raw.extend_from_slice(&(kept_ids.len() as u32).to_le_bytes());
            let mut prev = 0u32;
            for id in kept_ids {
                push_varint(&mut raw, id - prev);
                prev = id;
            }
            for v in kept_vals {
                raw.extend_from_slice(&v.to_le_bytes());
            }
        }

        let mut out = Vec::from(*MAGIC_V2_BROTLI);
        {
            let mut writer = brotli::CompressorWriter::new(&mut out, 4096, quality, 22);
            writer
                .write_all(&raw)
                .map_err(|e| format!("brotli compress failed: {e}"))?;
        }
        Ok(out)
    }

    pub fn is_female(&self) -> bool {
        self.rig_kind == RigKind::Female || (40000..=45000).contains(&self.positions.len())
    }

    pub fn is_male(&self) -> bool {
        self.rig_kind == RigKind::Male || (65000..=70000).contains(&self.positions.len())
    }

    pub fn channel(&self, ch: usize) -> Option<&(usize, Vec<u32>, Vec<u16>)> {
        self.channels.iter().find(|c| c.0 == ch)
    }
}

fn embedded_asset_bytes(rel: &str) -> Option<&'static [u8]> {
    let normalized = rel.replace('\\', "/");
    let stripped = normalized.strip_prefix("./").unwrap_or(&normalized);
    let name = stripped
        .strip_prefix("resources/shapekey/")
        .or_else(|| stripped.strip_prefix("src-core/src/resources/shapekey/"))
        .or_else(|| stripped.strip_prefix("assets/shapekey/"))?;
    match name {
        "FRoverSkin1.skref" => Some(include_bytes!("../../resources/shapekey/FRoverSkin1.skref")),
        "MRoverSkin1.skref" => Some(include_bytes!("../../resources/shapekey/MRoverSkin1.skref")),
        "RoverFemale.skref" => Some(include_bytes!("../../resources/shapekey/RoverFemale.skref")),
        "RoverMale.skref" => Some(include_bytes!("../../resources/shapekey/RoverMale.skref")),
        _ => None,
    }
}

/// Loads a `.skref` asset from disk first (allowing local overrides in dev or
/// beside the executable), falling back to the copy embedded at build time so
/// standalone packaged binaries do not depend on an external directory.
pub fn load_asset(rel: &str) -> Result<ReferenceAsset, String> {
    let mut candidates = vec![std::path::PathBuf::from(rel)];
    let dev_rel = format!("src-core/src/{rel}");
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join(rel));
        candidates.push(cwd.join(&dev_rel));
        if let Some(parent) = cwd.parent() {
            candidates.push(parent.join(rel));
            candidates.push(parent.join(&dev_rel));
        }
    }
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    {
        candidates.push(exe_dir.join(rel));
        if let Some(parent) = exe_dir.parent() {
            candidates.push(parent.join(rel));
        }
    }
    for path in candidates {
        if path.is_file() {
            let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            return ReferenceAsset::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()));
        }
    }
    if let Some(bytes) = embedded_asset_bytes(rel) {
        return ReferenceAsset::parse(bytes).map_err(|e| format!("{rel} (embedded): {e}"));
    }
    Err(format!("no such reference asset: {rel}"))
}

/// Result of transplanting one channel.
pub struct Transplanted {
    pub channel: usize,
    /// mod vertex ids (sorted, unique) with their 6 x f16 payload
    pub ids: Vec<u32>,
    pub vals: Vec<u16>,
    pub matched: usize,
    pub reference_len: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ComponentPartition {
    pub face_candidates: Vec<u32>,
    pub eyes_candidates: Vec<u32>,
    pub teeth_candidates: Vec<u32>,
    /// Original UV0 (R16G16_FLOAT in the 16-byte WWMI TexCoord record).
    pub texcoords: Vec<u8>,
    /// Authored AA motion disambiguates touching upper/lower mouth surfaces.
    pub mouth_motion: std::collections::HashMap<u32, [f32; 3]>,
}

impl ComponentPartition {
    /// Keep authored AA evidence local to the touching inner-mouth UV islands
    /// (female rover uses v ~ 0.90..0.93, male rover uses v ~ 0.68..0.72).
    pub fn with_mouth_motion(&self, ids: &[u8], values: &[u8]) -> Self {
        let mut part = self.clone();
        for (id, value) in ids.chunks_exact(4).zip(values.chunks_exact(12)) {
            let vid = u32::from_le_bytes(id.try_into().unwrap());
            if let Some(uv) = part.texcoords.get(vid as usize * 16..vid as usize * 16 + 4) {
                let half = |b: &[u8]| f16_to_f32(u16::from_le_bytes(b.try_into().unwrap()));
                let u = half(&uv[..2]);
                let v = half(&uv[2..4]);
                if (0.4..0.6).contains(&u) && ((0.90..0.93).contains(&v) || (0.68..0.72).contains(&v)) {
                    part.mouth_motion
                        .insert(vid, std::array::from_fn(|i| half(&value[i * 2..i * 2 + 2])));
                }
            }
        }
        part
    }
}

#[derive(Default)]
pub struct SurfaceTransfer {
    pub correspondence: Vec<(u32, usize)>,
    /// Includes static vertices, so the caller can remove stale author motion.
    pub vertices: Vec<u32>,
    pub channels: Vec<Transplanted>,
    /// Rigid translation from mod space to reference space estimated on the face component.
    pub head_shift: [f32; 3],
    /// Fraction of face candidates matching an official UV at aligned coordinates.
    pub uv_coverage: f32,
    /// True when the face component uses a custom UV layout that diverges from the reference.
    pub uv_untrusted: bool,
    /// Mod vertices that matched an official reference vertex with an exact UV nearby.
    pub uv_matched: std::collections::HashSet<u32>,
}

fn median_f32(vals: &mut [f32]) -> f32 {
    if vals.is_empty() {
        return 0.0;
    }
    vals.sort_by(|a, b| a.total_cmp(b));
    vals[vals.len() / 2]
}

/// Build correspondence once against the *whole* neutral surface, then sample
/// every expression through it. Searching only active vertices per expression
/// incorrectly moves static neighbours and collapses split/seam vertices.
pub fn transfer_legacy_surface(
    asset: &ReferenceAsset,
    positions: &[u8],
    partition: &ComponentPartition,
    face_component: u32,
    eyes_component: u32,
) -> Option<SurfaceTransfer> {
    if asset.surface.len() != asset.positions.len() || partition.texcoords.is_empty() {
        return None;
    }
    let mut mapping = Vec::new();
    let mut face_head_shift = [0.0f32; 3];
    let mut face_uv_coverage = 1.0f32;
    let mut face_uv_untrusted = false;
    let mut uv_matched = std::collections::HashSet::new();
    let mut mouth = vec![[0f32; 3]; asset.positions.len()];
    if let Some((_, ids, vals)) = asset.channel(44) {
        for (&id, value) in ids.iter().zip(vals.chunks_exact(6)) {
            if let Some(dst) = mouth.get_mut(id as usize) {
                *dst = std::array::from_fn(|i| f16_to_f32(value[i]));
            }
        }
    }
    let is_tooth_uv = |uv: [f32; 2]| (0.35..=0.65).contains(&uv[0]) && (0.93..=1.05).contains(&uv[1]);
    let face_all_refs: Vec<usize> = asset
        .surface
        .iter()
        .enumerate()
        .filter_map(|(i, (_, c))| (*c == face_component).then_some(i))
        .collect();
    let face_skin_refs: Vec<usize> = face_all_refs
        .iter()
        .copied()
        .filter(|&i| !is_tooth_uv(asset.surface[i].0))
        .collect();
    let teeth_refs: Vec<usize> = face_all_refs
        .iter()
        .copied()
        .filter(|&i| is_tooth_uv(asset.surface[i].0))
        .collect();
    let eyes_refs: Vec<usize> = asset
        .surface
        .iter()
        .enumerate()
        .filter_map(|(i, (_, c))| (*c == eyes_component).then_some(i))
        .collect();

    let total_candidates =
        partition.face_candidates.len() + partition.teeth_candidates.len() + partition.eyes_candidates.len();
    for (is_face_skin, candidates, refs) in [
        (
            true,
            partition.face_candidates.as_slice(),
            if face_skin_refs.is_empty() {
                face_all_refs.as_slice()
            } else {
                face_skin_refs.as_slice()
            },
        ),
        (
            false,
            partition.teeth_candidates.as_slice(),
            if teeth_refs.is_empty() {
                face_all_refs.as_slice()
            } else {
                teeth_refs.as_slice()
            },
        ),
        (false, partition.eyes_candidates.as_slice(), eyes_refs.as_slice()),
    ] {
        if candidates.is_empty() || refs.is_empty() {
            continue;
        }
        let ref_positions: Vec<_> = refs.iter().map(|&i| asset.positions[i]).collect();
        let ref_uvs: Vec<_> = refs
            .iter()
            .map(|&i| [asset.surface[i].0[0], asset.surface[i].0[1], 0.0])
            .collect();
        let position_grid = SpatialGrid::new(&ref_positions, 0.35);
        let uv_grid = SpatialGrid::new(&ref_uvs, 0.001);

        let mut parsed = Vec::with_capacity(candidates.len());
        let mut spatial_deltas: [Vec<f32>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        let mut uv_deltas: [Vec<f32>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        let mut uv_hits = 0usize;

        for &vid in candidates {
            let p = positions.get(vid as usize * 12..vid as usize * 12 + 12)?;
            let uv = partition.texcoords.get(vid as usize * 16..vid as usize * 16 + 4)?;
            let p: [f32; 3] = std::array::from_fn(|i| f32::from_le_bytes(p[i * 4..i * 4 + 4].try_into().unwrap()));
            let uv: [f32; 2] = std::array::from_fn(|i| {
                f16_to_f32(u16::from_le_bytes(uv[i * 2..i * 2 + 2].try_into().unwrap()))
            });
            if !p.iter().chain(&uv).all(|x| x.is_finite()) {
                continue;
            }
            parsed.push((vid, p, uv));

            let mut best_spatial: Option<(usize, f32)> = None;
            position_grid.for_each_within(p, 0.35, |i, dist| {
                if best_spatial.is_none_or(|(_, bd)| dist < bd) {
                    best_spatial = Some((refs[i], dist));
                }
            });
            if let Some((ri, _)) = best_spatial {
                let rp = asset.positions[ri];
                for a in 0..3 {
                    spatial_deltas[a].push(rp[a] - p[a]);
                }
            }

            let mut best_uv: Option<(usize, f32)> = None;
            uv_grid.for_each_within([uv[0], uv[1], 0.0], 0.001, |i, _| {
                let ri = refs[i];
                let rp = asset.positions[ri];
                let ruv = asset.surface[ri].0;
                let u: f32 = (0..2).map(|k| (ruv[k] - uv[k]).powi(2)).sum();
                let d: f32 = (0..3).map(|k| (rp[k] - p[k]).powi(2)).sum();
                if u < 1e-8 && d < 4.0 && best_uv.is_none_or(|(_, bd)| d < bd) {
                    best_uv = Some((ri, d));
                }
            });
            if let Some((ri, _)) = best_uv {
                uv_hits += 1;
                let rp = asset.positions[ri];
                for a in 0..3 {
                    uv_deltas[a].push(rp[a] - p[a]);
                }
            }
        }

        let min_samples = (parsed.len() / 4).max(1);
        let mut shift = if spatial_deltas[0].len() >= min_samples {
            std::array::from_fn(|a| median_f32(&mut spatial_deltas[a]))
        } else if uv_deltas[0].len() >= min_samples {
            std::array::from_fn(|a| median_f32(&mut uv_deltas[a]))
        } else {
            [0.0f32; 3]
        };
        if shift.iter().map(|v| v * v).sum::<f32>() <= 0.01f32.powi(2) {
            shift = [0.0; 3];
        }
        let uv_coverage = uv_hits as f32 / parsed.len().max(1) as f32;
        let uv_trustworthy = uv_coverage >= 0.90;
        if is_face_skin {
            face_head_shift = shift;
            face_uv_coverage = uv_coverage;
            face_uv_untrusted = !uv_trustworthy;
        }

        for (vid, p, uv) in parsed {
            let p_aligned = [p[0] + shift[0], p[1] + shift[1], p[2] + shift[2]];
            let mut exact: Option<(usize, f32, f32)> = None;
            let mut anatomical: Option<(usize, f32, f32)> = None;
            let mut tight_uv_match: Option<(usize, f32)> = None;
            let mut tight_nearest: Option<(usize, f32)> = None;
            let mut uv_match: Option<(usize, f32)> = None;
            let mut nearest: Option<(usize, f32)> = None;
            // Every accepted match is either within 0.35 in aligned position or
            // within 0.001 in UV. Query their union instead of scanning the
            // entire reference surface for every mod vertex. Sort to preserve
            // deterministic reference-id tie breaking across hash seeds.
            let mut nearby = Vec::new();
            position_grid.for_each_within(p_aligned, 0.35, |i, _| nearby.push(i));
            uv_grid.for_each_within([uv[0], uv[1], 0.0], 0.001, |i, _| nearby.push(i));
            nearby.sort_unstable();
            nearby.dedup();
            for i in nearby {
                let ri = refs[i];
                let rp = asset.positions[ri];
                let ruv = asset.surface[ri].0;
                let d: f32 = (0..3).map(|k| (rp[k] - p_aligned[k]).powi(2)).sum();
                let u: f32 = (0..2).map(|k| (ruv[k] - uv[k]).powi(2)).sum();
                // Closed inner lips can share position AND UV but move in
                // opposite directions when opened. Their authored AA motion is
                // independent evidence of which side of the cut they belong to.
                if d < 0.35f32.powi(2) && u < 1e-6 {
                    if let Some(hint) = partition.mouth_motion.get(&vid) {
                        let motion_error: f32 = (0..3).map(|k| (hint[k] - mouth[ri][k]).powi(2)).sum();
                        if anatomical.is_none_or(|(_, best_motion, best_d)| (motion_error, d) < (best_motion, best_d)) {
                            anatomical = Some((ri, motion_error, d));
                        }
                    }
                }
                if d < 1e-6 && exact.is_none_or(|(_, best_uv, best_d)| (u, d) < (best_uv, best_d)) {
                    exact = Some((ri, u, d));
                }
                if u < 1e-8 && d < 0.06f32.powi(2) && tight_uv_match.is_none_or(|(_, best)| d < best) {
                    tight_uv_match = Some((ri, d));
                }
                if d < 0.05f32.powi(2) && tight_nearest.is_none_or(|(_, best)| d < best) {
                    tight_nearest = Some((ri, d));
                }
                if u < 1e-8 && d < 4.0 && uv_match.is_none_or(|(_, best)| d < best) {
                    uv_match = Some((ri, d));
                }
                if d < 0.35f32.powi(2) && nearest.is_none_or(|(_, best)| d < best) {
                    nearest = Some((ri, d));
                }
            }
            if anatomical.is_some()
                || exact.is_some_and(|(_, u, _)| u < 1e-6)
                || tight_uv_match.is_some()
                || (!is_face_skin && uv_match.is_some())
            {
                uv_matched.insert(vid);
            }
            let picked = if uv_trustworthy {
                anatomical
                    .map(|(ri, _, d)| (ri, d))
                    .or(exact.map(|(ri, _, d)| (ri, d)))
                    .or(uv_match)
                    .or(nearest)
            } else {
                // On custom-UV heads, preserve exact official-UV pairs within tight aligned
                // proximity (critical for coincident inner-lip seams), then fall back to
                // tight aligned spatial proximity for custom-UV vertices before broad UV matches.
                anatomical
                    .map(|(ri, _, d)| (ri, d))
                    .or(exact.map(|(ri, _, d)| (ri, d)))
                    .or(tight_uv_match)
                    .or(tight_nearest)
                    .or(uv_match)
                    .or(nearest)
            };
            if let Some((ri, _)) = picked {
                mapping.push((vid, ri));
            }
        }
    }
    mapping.sort_unstable_by_key(|m| m.0);
    mapping.dedup_by_key(|m| m.0);
    if mapping.is_empty() {
        return None;
    }
    let vertices: Vec<u32> = mapping.iter().map(|m| m.0).collect();
    let mut channels = Vec::new();
    let max_ch = asset.channels.iter().map(|c| c.0).max().unwrap_or(146);
    for ch in 0..=max_ch {
        let mut dense = vec![[0u16; 6]; asset.positions.len()];
        if let Some((_, ids, vals)) = asset.channel(ch) {
            for (&id, value) in ids.iter().zip(vals.chunks_exact(6)) {
                if let Some(dst) = dense.get_mut(id as usize) {
                    dst.copy_from_slice(value);
                }
            }
        }
        let mut ids = Vec::new();
        let mut vals = Vec::new();
        for &(vid, ri) in &mapping {
            if dense[ri].iter().any(|v| v & 0x7fff != 0) {
                ids.push(vid);
                vals.extend_from_slice(&dense[ri]);
            }
        }
        channels.push(Transplanted {
            channel: ch,
            matched: ids.len(),
            reference_len: ids.len(),
            ids,
            vals,
        });
    }
    log::info!(
        "Legacy surface correspondence: {}/{} face/eye vertices; static vertices included",
        vertices.len(),
        total_candidates
    );
    Some(SurfaceTransfer {
        vertices,
        channels,
        correspondence: mapping,
        head_shift: face_head_shift,
        uv_coverage: face_uv_coverage,
        uv_untrusted: face_uv_untrusted,
        uv_matched,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentType {
    FaceSkin,
    TeethUpper,
    TeethLower,
    Eyes,
    Other,
}

pub fn ref_vertex_component(ref_position_count: usize, ref_vid: usize) -> Option<ComponentType> {
    if (40000..=45000).contains(&ref_position_count) {
        // Female Rover reference space (~41562 - 41591)
        if (11281..=11306).contains(&ref_vid) {
            Some(ComponentType::TeethUpper)
        } else if (12115..=12226).contains(&ref_vid) {
            Some(ComponentType::TeethLower)
        } else if (11240..=14678).contains(&ref_vid) {
            Some(ComponentType::FaceSkin)
        } else if (41089..=41555).contains(&ref_vid) {
            Some(ComponentType::Eyes)
        } else {
            Some(ComponentType::Other)
        }
    } else if (65000..=70000).contains(&ref_position_count) {
        // Male Rover reference space (~66580 - 66626)
        if (11434..=11475).contains(&ref_vid) {
            Some(ComponentType::TeethUpper)
        } else if (12770..=12895).contains(&ref_vid) {
            Some(ComponentType::TeethLower)
        } else if (14280..=17720).contains(&ref_vid) {
            Some(ComponentType::FaceSkin)
        } else if (43762..=44125).contains(&ref_vid) {
            Some(ComponentType::Eyes)
        } else {
            Some(ComponentType::Other)
        }
    } else {
        None
    }
}

/// Nearest-position matching of every reference vertex of `channels` onto the
/// mod's shape-key vertices.
pub fn transplant(
    asset: &ReferenceAsset,
    mod_positions: &[u8],
    candidates: &[u32],
    channels: &[usize],
    tolerance: f32,
    diffusion: f32,
) -> Vec<Transplanted> {
    transplant_partitioned(asset, mod_positions, candidates, None, channels, tolerance, diffusion)
}

/// Spatial uniform grid for fast 3D proximity lookups.
struct SpatialGrid<'a> {
    inv_cell_size: f32,
    positions: &'a [[f32; 3]],
    grid: std::collections::HashMap<(i32, i32, i32), Vec<usize>>,
}

impl<'a> SpatialGrid<'a> {
    fn new(positions: &'a [[f32; 3]], cell_size: f32) -> Self {
        let inv_cell_size = 1.0 / cell_size;
        let mut grid: std::collections::HashMap<(i32, i32, i32), Vec<usize>> =
            std::collections::HashMap::with_capacity(positions.len().min(16384));
        for (i, p) in positions.iter().enumerate() {
            let cx = (p[0] * inv_cell_size).floor() as i32;
            let cy = (p[1] * inv_cell_size).floor() as i32;
            let cz = (p[2] * inv_cell_size).floor() as i32;
            grid.entry((cx, cy, cz)).or_default().push(i);
        }
        Self {
            inv_cell_size,
            positions,
            grid,
        }
    }

    fn for_each_within<F>(&self, rp: [f32; 3], max_radius: f32, mut f: F)
    where
        F: FnMut(usize, f32),
    {
        let max_r2 = max_radius * max_radius;
        let cx = (rp[0] * self.inv_cell_size).floor() as i32;
        let cy = (rp[1] * self.inv_cell_size).floor() as i32;
        let cz = (rp[2] * self.inv_cell_size).floor() as i32;

        let delta = (max_radius * self.inv_cell_size).ceil() as i32;

        for dx in -delta..=delta {
            for dy in -delta..=delta {
                for dz in -delta..=delta {
                    if let Some(indices) = self.grid.get(&(cx + dx, cy + dy, cz + dz)) {
                        for &j in indices {
                            let mp = &self.positions[j];
                            let d2 = (mp[0] - rp[0]).powi(2) + (mp[1] - rp[1]).powi(2) + (mp[2] - rp[2]).powi(2);
                            if d2 <= max_r2 {
                                f(j, d2.sqrt());
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Anatomical sub-regions for face feature isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnatomicalPool {
    UpperLip,
    LowerLip,
    UpperEyelid,
    LowerEyelid,
    FaceSkin,
}

/// Nearest-position matching with component-partitioned candidate pools to
/// prevent cross-component vertex bleed (e.g., eyes/face/hair isolation),
/// anatomical lip/eyelid cross-over prevention, dedicated teeth isolation, and coincident seam preservation.
pub fn transplant_partitioned(
    asset: &ReferenceAsset,
    mod_positions: &[u8],
    candidates: &[u32],
    partition: Option<&ComponentPartition>,
    channels: &[usize],
    tolerance: f32,
    _diffusion: f32,
) -> Vec<Transplanted> {
    let vertex_count = mod_positions.len() / 12;
    let pos_of = |id: u32| -> [f32; 3] {
        let o = id as usize * 12;
        [
            f32::from_le_bytes([
                mod_positions[o],
                mod_positions[o + 1],
                mod_positions[o + 2],
                mod_positions[o + 3],
            ]),
            f32::from_le_bytes([
                mod_positions[o + 4],
                mod_positions[o + 5],
                mod_positions[o + 6],
                mod_positions[o + 7],
            ]),
            f32::from_le_bytes([
                mod_positions[o + 8],
                mod_positions[o + 9],
                mod_positions[o + 10],
                mod_positions[o + 11],
            ]),
        ]
    };

    let filter_valid =
        |list: &[u32]| -> Vec<u32> { list.iter().copied().filter(|v| (*v as usize) < vertex_count).collect() };

    let default_cands = filter_valid(candidates);
    let default_pos: Vec<[f32; 3]> = default_cands.iter().map(|v| pos_of(*v)).collect();

    let is_female = asset.is_female();
    let is_male = asset.is_male();
    let is_rover = is_female || is_male;

    let mut up_tooth_rank = Vec::new();
    let mut lo_tooth_rank = Vec::new();
    if !asset.roles.is_empty() {
        up_tooth_rank.resize(asset.positions.len(), None);
        lo_tooth_rank.resize(asset.positions.len(), None);
        let mut up_idx = 0usize;
        let mut lo_idx = 0usize;
        for (ri, &role) in asset.roles.iter().enumerate() {
            match role {
                ComponentType::TeethUpper => {
                    up_tooth_rank[ri] = Some(up_idx);
                    up_idx += 1;
                }
                ComponentType::TeethLower => {
                    lo_tooth_rank[ri] = Some(lo_idx);
                    lo_idx += 1;
                }
                _ => {}
            }
        }
    }

    let (z_lip, lip_z_min, lip_z_max, z_lid, lid_z_min, lid_z_max) = if is_female {
        (135.405f32, 134.0f32, 137.5f32, 140.50f32, 138.0f32, 144.0f32)
    } else if is_male {
        (138.50f32, 136.5f32, 140.5f32, 146.50f32, 144.0f32, 150.0f32)
    } else {
        (0.0f32, 0.0f32, 0.0f32, 0.0f32, 0.0f32, 0.0f32)
    };

    let classify = |p: [f32; 3]| -> AnatomicalPool {
        if is_rover && p[0].abs() < 2.5 && p[2] > lip_z_min && p[2] < lip_z_max {
            if p[2] >= z_lip {
                AnatomicalPool::UpperLip
            } else {
                AnatomicalPool::LowerLip
            }
        } else if is_rover && p[0].abs() >= 1.0 && p[2] > lid_z_min && p[2] < lid_z_max {
            if p[2] >= z_lid {
                AnatomicalPool::UpperEyelid
            } else {
                AnatomicalPool::LowerEyelid
            }
        } else {
            AnatomicalPool::FaceSkin
        }
    };

    let face_cands = partition.map(|p| filter_valid(&p.face_candidates));
    let teeth_cands = partition.map(|p| filter_valid(&p.teeth_candidates)).unwrap_or_default();
    let teeth_pos: Vec<[f32; 3]> = teeth_cands.iter().map(|v| pos_of(*v)).collect();

    let (mod_up_teeth, mod_lo_teeth) = if is_female && teeth_cands.len() >= 138 {
        (teeth_cands[..26].to_vec(), teeth_cands[26..138].to_vec())
    } else if is_male && teeth_cands.len() >= 168 {
        (teeth_cands[..42].to_vec(), teeth_cands[42..168].to_vec())
    } else {
        (Vec::new(), Vec::new())
    };

    let mut coincident_map: std::collections::HashMap<(i32, i32, i32), Vec<u32>> = std::collections::HashMap::new();

    let (ulip_cands, ulip_pos, llip_cands, llip_pos, ulid_cands, ulid_pos, llid_cands, llid_pos, skin_cands, skin_pos) =
        if let Some(cands) = &face_cands {
            let mut uc = Vec::new();
            let mut up = Vec::new();
            let mut lc = Vec::new();
            let mut lp = Vec::new();
            let mut uec = Vec::new();
            let mut uep = Vec::new();
            let mut lec = Vec::new();
            let mut lep = Vec::new();
            let mut sc = Vec::new();
            let mut sp = Vec::new();

            for &v in cands {
                let p = pos_of(v);
                let key = (
                    (p[0] * 1000.0).round() as i32,
                    (p[1] * 1000.0).round() as i32,
                    (p[2] * 1000.0).round() as i32,
                );
                coincident_map.entry(key).or_default().push(v);

                match classify(p) {
                    AnatomicalPool::UpperLip => {
                        uc.push(v);
                        up.push(p);
                        sc.push(v);
                        sp.push(p);
                    }
                    AnatomicalPool::LowerLip => {
                        lc.push(v);
                        lp.push(p);
                        sc.push(v);
                        sp.push(p);
                    }
                    AnatomicalPool::UpperEyelid => {
                        uec.push(v);
                        uep.push(p);
                        sc.push(v);
                        sp.push(p);
                    }
                    AnatomicalPool::LowerEyelid => {
                        lec.push(v);
                        lep.push(p);
                        sc.push(v);
                        sp.push(p);
                    }
                    AnatomicalPool::FaceSkin => {
                        sc.push(v);
                        sp.push(p);
                    }
                }
            }
            (uc, up, lc, lp, uec, uep, lec, lep, sc, sp)
        } else {
            (
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
        };

    let eyes_cands = partition.map(|p| filter_valid(&p.eyes_candidates));
    let eyes_pos: Option<Vec<[f32; 3]>> = eyes_cands.as_ref().map(|c| c.iter().map(|v| pos_of(*v)).collect());

    let grid_cell_size = tolerance.max(0.5);
    let default_grid = if !default_pos.is_empty() {
        Some(SpatialGrid::new(&default_pos, grid_cell_size))
    } else {
        None
    };
    let teeth_grid = if !teeth_pos.is_empty() {
        Some(SpatialGrid::new(&teeth_pos, grid_cell_size))
    } else {
        None
    };
    let ulip_grid = if !ulip_pos.is_empty() {
        Some(SpatialGrid::new(&ulip_pos, grid_cell_size))
    } else {
        None
    };
    let llip_grid = if !llip_pos.is_empty() {
        Some(SpatialGrid::new(&llip_pos, grid_cell_size))
    } else {
        None
    };
    let ulid_grid = if !ulid_pos.is_empty() {
        Some(SpatialGrid::new(&ulid_pos, grid_cell_size))
    } else {
        None
    };
    let llid_grid = if !llid_pos.is_empty() {
        Some(SpatialGrid::new(&llid_pos, grid_cell_size))
    } else {
        None
    };
    let skin_grid = if !skin_pos.is_empty() {
        Some(SpatialGrid::new(&skin_pos, grid_cell_size))
    } else {
        None
    };
    let eyes_grid = eyes_pos
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| SpatialGrid::new(p, grid_cell_size));

    let is_compatible_hemisphere = |rx: f32, mx: f32| -> bool {
        if rx > 0.005 {
            mx > -0.005
        } else if rx < -0.005 {
            mx < 0.005
        } else {
            mx.abs() < 0.05
        }
    };

    let mut out = Vec::new();

    for &ch in channels {
        let Some((_, ref_ids, ref_vals)) = asset.channel(ch) else {
            continue;
        };

        let mut hits: Vec<(u32, f32, usize)> = Vec::new();
        for (i, rid) in ref_ids.iter().enumerate() {
            let ri = *rid as usize;
            if ri >= asset.positions.len() {
                continue;
            }
            let rp = asset.positions[ri];

            let comp_type = if !asset.roles.is_empty() {
                asset.roles.get(ri).copied()
            } else {
                ref_vertex_component(asset.positions.len(), ri)
            };
            match comp_type {
                Some(ComponentType::TeethUpper) => {
                    let k = if !up_tooth_rank.is_empty() {
                        up_tooth_rank.get(ri).copied().flatten()
                    } else if is_female {
                        ri.checked_sub(11281)
                    } else if is_male {
                        ri.checked_sub(11434)
                    } else {
                        None
                    };
                    if let Some(idx) = k {
                        if idx < mod_up_teeth.len() {
                            hits.push((mod_up_teeth[idx], 0.0, i));
                            continue;
                        }
                    }
                    if let Some(grid) = teeth_grid.as_ref() {
                        grid.for_each_within(rp, tolerance.min(0.25), |j, dist| {
                            hits.push((teeth_cands[j], dist, i));
                        });
                    }
                    continue;
                }
                Some(ComponentType::TeethLower) => {
                    let k = if !lo_tooth_rank.is_empty() {
                        lo_tooth_rank.get(ri).copied().flatten()
                    } else if is_female {
                        ri.checked_sub(12115)
                    } else if is_male {
                        ri.checked_sub(12770)
                    } else {
                        None
                    };
                    if let Some(idx) = k {
                        if idx < mod_lo_teeth.len() {
                            hits.push((mod_lo_teeth[idx], 0.0, i));
                            continue;
                        }
                    }
                    if let Some(grid) = teeth_grid.as_ref() {
                        grid.for_each_within(rp, tolerance.min(0.25), |j, dist| {
                            hits.push((teeth_cands[j], dist, i));
                        });
                    }
                    continue;
                }
                Some(ComponentType::Eyes) if eyes_grid.is_some() => {
                    let eyes_c = eyes_cands.as_ref().unwrap().as_slice();
                    let grid = eyes_grid.as_ref().unwrap();
                    let mut best: Option<(usize, f32)> = None;
                    grid.for_each_within(rp, tolerance.min(0.05), |j, dist| {
                        if let Some((_, best_d)) = best {
                            if dist < best_d {
                                best = Some((j, dist));
                            }
                        } else {
                            best = Some((j, dist));
                        }
                    });
                    if let Some((best_j, dist)) = best {
                        hits.push((eyes_c[best_j], dist, i));
                    }
                    continue;
                }
                Some(ComponentType::FaceSkin) => {
                    let (target_cands, maybe_grid, max_r) = match classify(rp) {
                        AnatomicalPool::UpperLip => {
                            if ulip_grid.is_some() {
                                (ulip_cands.as_slice(), ulip_grid.as_ref(), tolerance)
                            } else if skin_grid.is_some() {
                                (skin_cands.as_slice(), skin_grid.as_ref(), tolerance)
                            } else {
                                (default_cands.as_slice(), default_grid.as_ref(), tolerance)
                            }
                        }
                        AnatomicalPool::LowerLip => {
                            if llip_grid.is_some() {
                                (llip_cands.as_slice(), llip_grid.as_ref(), tolerance)
                            } else if skin_grid.is_some() {
                                (skin_cands.as_slice(), skin_grid.as_ref(), tolerance)
                            } else {
                                (default_cands.as_slice(), default_grid.as_ref(), tolerance)
                            }
                        }
                        AnatomicalPool::UpperEyelid => {
                            if ulid_grid.is_some() {
                                (ulid_cands.as_slice(), ulid_grid.as_ref(), tolerance)
                            } else if skin_grid.is_some() {
                                (skin_cands.as_slice(), skin_grid.as_ref(), tolerance)
                            } else {
                                (default_cands.as_slice(), default_grid.as_ref(), tolerance)
                            }
                        }
                        AnatomicalPool::LowerEyelid => {
                            if llid_grid.is_some() {
                                (llid_cands.as_slice(), llid_grid.as_ref(), tolerance)
                            } else if skin_grid.is_some() {
                                (skin_cands.as_slice(), skin_grid.as_ref(), tolerance)
                            } else {
                                (default_cands.as_slice(), default_grid.as_ref(), tolerance)
                            }
                        }
                        AnatomicalPool::FaceSkin => {
                            if skin_grid.is_some() {
                                (skin_cands.as_slice(), skin_grid.as_ref(), tolerance)
                            } else {
                                (default_cands.as_slice(), default_grid.as_ref(), tolerance)
                            }
                        }
                    };

                    let Some(grid) = maybe_grid else {
                        continue;
                    };

                    let mut best: Option<(usize, f32)> = None;
                    grid.for_each_within(rp, max_r, |j, dist| {
                        let mp = pos_of(target_cands[j]);
                        if is_compatible_hemisphere(rp[0], mp[0]) {
                            if let Some((_, best_d)) = best {
                                if dist < best_d {
                                    best = Some((j, dist));
                                }
                            } else {
                                best = Some((j, dist));
                            }
                        }
                    });

                    if let Some((best_j, dist)) = best {
                        let cand_vid = target_cands[best_j];
                        let p = pos_of(cand_vid);
                        let key = (
                            (p[0] * 1000.0).round() as i32,
                            (p[1] * 1000.0).round() as i32,
                            (p[2] * 1000.0).round() as i32,
                        );
                        if let Some(coincident) = coincident_map.get(&key) {
                            for &cv in coincident {
                                hits.push((cv, dist, i));
                            }
                        } else {
                            hits.push((cand_vid, dist, i));
                        }
                    }
                    continue;
                }
                Some(ComponentType::Other) if skin_grid.is_some() || eyes_grid.is_some() => {
                    continue; // Skip reference clothing/body for Rover models with partitions
                }
                _ => {
                    let Some(grid) = default_grid.as_ref() else {
                        continue;
                    };
                    let mut best: Option<(usize, f32)> = None;
                    grid.for_each_within(rp, tolerance, |j, dist| {
                        if let Some((_, best_d)) = best {
                            if dist < best_d {
                                best = Some((j, dist));
                            }
                        } else {
                            best = Some((j, dist));
                        }
                    });
                    if let Some((best_j, dist)) = best {
                        hits.push((default_cands[best_j], dist, i));
                    }
                }
            }
        }

        hits.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)));
        hits.dedup_by_key(|h| h.0);

        let mut ids = Vec::with_capacity(hits.len());
        let mut vals = Vec::with_capacity(hits.len() * 6);
        for (mod_id, _, i) in &hits {
            ids.push(*mod_id);
            vals.extend_from_slice(&ref_vals[i * 6..i * 6 + 6]);
        }
        out.push(Transplanted {
            channel: ch,
            ids,
            vals,
            matched: hits.len(),
            reference_len: ref_ids.len(),
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal in-memory asset: two positions, one channel with 2 vertices.
    fn sample() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(MAGIC_V1);
        b.extend_from_slice(&2u32.to_le_bytes()); // positions
        b.extend_from_slice(&1u32.to_le_bytes()); // channels
        for p in [[0.0f32, 0.0, 0.0], [1.0, 0.0, 0.0]] {
            for c in p {
                b.extend_from_slice(&c.to_le_bytes());
            }
        }
        b.extend_from_slice(&7u32.to_le_bytes()); // channel 7
        b.extend_from_slice(&2u32.to_le_bytes()); // 2 entries
        b.extend_from_slice(&0u32.to_le_bytes()); // ref vertex 0
        b.extend_from_slice(&1u32.to_le_bytes()); // ref vertex 1
        for v in [1u16, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b
    }

    fn mod_positions() -> Vec<u8> {
        // mod vertices: id 0 at (0.01,0,0), id 1 at (0.99,0,0), id 2 far away
        let mut b = Vec::new();
        for p in [[0.0f32, 0.0, 0.0], [0.99, 0.0, 0.0], [50.0, 0.0, 0.0]] {
            for c in p {
                b.extend_from_slice(&c.to_le_bytes());
            }
        }
        b
    }

    #[test]
    fn parses_and_matches_within_radius() {
        let raw = sample();
        assert!(ReferenceAsset::parse(b"not an asset at all").is_err());
        assert!(ReferenceAsset::parse(&raw[..20]).is_err());

        let asset = ReferenceAsset::parse(&raw).expect("parse");
        assert_eq!(asset.positions.len(), 2);

        let within = transplant(&asset, &mod_positions(), &[0, 1, 2], &[7], 0.1, 0.0);
        assert_eq!(within.len(), 1);
        assert_eq!(within[0].channel, 7);
        assert_eq!(within[0].matched, 2);
        assert_eq!(within[0].ids, vec![0, 1]);
        assert_eq!(&within[0].vals[0..6], &[1, 2, 3, 4, 5, 6]);

        let tight = transplant(&asset, &mod_positions(), &[0, 1, 2], &[7], 0.001, 0.0);
        assert_eq!(tight[0].matched, 1);
        assert_eq!(tight[0].ids, vec![0]);
    }

    #[test]
    fn legacy_surface_keeps_static_vertices_static_and_copies_split_vertices() {
        let mut asset = ReferenceAsset::parse(&sample()).unwrap();
        // Only reference vertex 0 moves in this expression. Vertex 1 is static,
        // even though the moving vertex is within the position search radius.
        asset.channels = vec![(7, vec![0], vec![0x3c00, 0, 0, 0, 0, 0])];
        asset.surface = vec![([0.1, 0.1], 2), ([0.2, 0.1], 2)];
        let mut uv = Vec::new();
        for pair in [[0x2e66u16, 0x2e66u16], [0x3266, 0x2e66], [0x2e66, 0x2e66]] {
            for value in pair {
                uv.extend_from_slice(&value.to_le_bytes());
            }
            uv.extend_from_slice(&[0; 12]);
        }
        let mut positions = mod_positions();
        let first = positions[0..12].to_vec();
        positions[24..36].copy_from_slice(&first);
        let part = ComponentPartition {
            face_candidates: vec![0, 1, 2],
            texcoords: uv,
            ..Default::default()
        };
        let result = transfer_legacy_surface(&asset, &positions, &part, 2, 5).unwrap();
        let channel = result.channels.iter().find(|c| c.channel == 7).unwrap();
        assert_eq!(
            channel.ids,
            vec![0, 2],
            "static neighbour must not acquire motion; both seam copies must move"
        );
        assert_eq!(channel.vals, [0x3c00, 0, 0, 0, 0, 0].repeat(2));
        assert_eq!(result.vertices, vec![0, 1, 2]);
    }

    #[test]
    fn coincident_uv_uses_closest_neutral_position() {
        let mut asset = ReferenceAsset::parse(&sample()).unwrap();
        asset.positions[1] = [0.0008, 0.0, 0.0];
        asset.surface = vec![([0.0, 0.0], 2); 2];
        asset.channels = vec![(7, vec![0], vec![0x3c00, 0, 0, 0, 0, 0])];
        let positions: Vec<u8> = [0.00079f32, 0.0, 0.0].iter().flat_map(|x| x.to_le_bytes()).collect();
        let part = ComponentPartition {
            face_candidates: vec![0],
            texcoords: vec![0; 16],
            ..Default::default()
        };
        let result = transfer_legacy_surface(&asset, &positions, &part, 2, 5).unwrap();
        assert!(result.channels.iter().find(|c| c.channel == 7).unwrap().ids.is_empty());
    }

    #[test]
    fn touching_inner_lips_use_authored_motion_to_choose_the_correct_surface() {
        let mut asset = ReferenceAsset::parse(&sample()).unwrap();
        asset.positions[1] = [0.0008, 0.0, 0.0];
        asset.surface = vec![([0.5, 0.915], 2); 2];
        asset.channels = vec![(44, vec![0, 1], vec![0, 0, 0x3c00, 0, 0, 0, 0, 0, 0xbc00, 0, 0, 0])];
        let positions = vec![0u8; 12];
        let mut uv = Vec::new();
        for value in [0x3800u16, 0x3b52u16] {
            uv.extend(value.to_le_bytes());
        }
        uv.resize(16, 0);
        let mut part = ComponentPartition {
            face_candidates: vec![0],
            texcoords: uv,
            ..Default::default()
        };
        let wrong = transfer_legacy_surface(&asset, &positions, &part, 2, 5).unwrap();
        assert_eq!(wrong.channels[44].vals[2], 0x3c00);
        part.mouth_motion.insert(0, [0.0, 0.0, -1.0]);
        let fixed = transfer_legacy_surface(&asset, &positions, &part, 2, 5).unwrap();
        assert_eq!(
            fixed.channels[44].vals[2], 0xbc00,
            "lower inner lip must move down even when the upper surface is closer"
        );
    }

    #[test]
    fn touching_male_rover_lips_use_authored_motion_to_choose_the_correct_surface() {
        let mut asset = ReferenceAsset::parse(&sample()).unwrap();
        asset.positions[1] = [0.0008, 0.0, 0.0];
        asset.surface = vec![([0.5, 0.6992], 1); 2];
        asset.channels = vec![(44, vec![0, 1], vec![0, 0, 0x3c00, 0, 0, 0, 0, 0, 0xbc00, 0, 0, 0])];
        let positions = vec![0u8; 12];
        let mut uv = Vec::new();
        for value in [0x3800u16, 0x3998u16] {
            uv.extend(value.to_le_bytes());
        }
        uv.resize(16, 0);
        let part = ComponentPartition {
            face_candidates: vec![0],
            texcoords: uv,
            ..Default::default()
        };
        let wrong = transfer_legacy_surface(&asset, &positions, &part, 1, 4).unwrap();
        assert_eq!(wrong.channels[44].vals[2], 0x3c00);

        let ids = 0u32.to_le_bytes();
        let mut vals = [0u8; 12];
        vals[4..6].copy_from_slice(&0xbc00u16.to_le_bytes());
        let part_with_motion = part.with_mouth_motion(&ids, &vals);
        assert!(part_with_motion.mouth_motion.contains_key(&0));

        let fixed = transfer_legacy_surface(&asset, &positions, &part_with_motion, 1, 4).unwrap();
        assert_eq!(
            fixed.channels[44].vals[2], 0xbc00,
            "male rover lower inner lip must move down when authored aa motion is present"
        );
    }

    #[test]
    fn test_embedded_reference_assets_cover_config() {
        let cfg: crate::config_loader::GlobalConfig =
            serde_json::from_str(include_str!("../../../../config.json")).expect("parse embedded config.json");
        let refs: Vec<String> = cfg
            .characters_ref()
            .values()
            .filter_map(|c| c.shapekey_fix.as_ref()?.reference_asset.clone())
            .collect();
        assert!(!refs.is_empty(), "expected at least one configured reference_asset");
        for rel in refs {
            let bytes = embedded_asset_bytes(&rel)
                .unwrap_or_else(|| panic!("missing embedded shapekey reference asset for config entry: {rel}"));
            let parsed =
                ReferenceAsset::parse(bytes).unwrap_or_else(|e| panic!("failed to parse embedded asset {rel}: {e}"));
            assert!(!parsed.positions.is_empty(), "embedded asset {rel} has no positions");
        }
        assert!(embedded_asset_bytes(r"src-core\src\resources\shapekey\RoverFemale.skref").is_some());
        assert!(embedded_asset_bytes("assets/shapekey/RoverFemale.skref").is_some());
        assert!(load_asset("src-core/src/resources/shapekey/DoesNotExist.skref").is_err());
    }

    #[test]
    fn test_skref2_brotli_roundtrip_and_equivalence() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/resources/shapekey");
        let specs: &[(&str, &[u32], Option<u32>, u32)] = &[
            ("FRoverSkin1.skref", &[2, 5], None, 2),
            ("RoverFemale.skref", &[2, 5], None, 2),
            ("MRoverSkin1.skref", &[0, 1, 4], Some(0), 1),
            ("RoverMale.skref", &[1, 4], None, 1),
        ];
        let mut total_disk = 0usize;
        let mut total_repacked = 0usize;
        for &(name, keep, hair, face) in specs {
            let raw = std::fs::read(dir.join(name)).expect("read skref");
            let orig = ReferenceAsset::parse(&raw).expect("parse original");
            let packed = orig
                .to_skref2_brotli_with_quality(keep, hair, face, 4)
                .unwrap_or_else(|e| panic!("encode {name}: {e}"));
            total_disk += raw.len();
            total_repacked += packed.len();
            let decoded = ReferenceAsset::parse(&packed).unwrap_or_else(|e| panic!("decode {name}: {e}"));
            assert_eq!(orig.is_female(), decoded.is_female(), "{name} is_female");
            assert_eq!(orig.is_male(), decoded.is_male(), "{name} is_male");

            let mut remap = vec![u32::MAX; orig.positions.len()];
            let mut active = Vec::new();
            for (i, (_, c)) in orig.surface.iter().enumerate() {
                if keep.contains(c) {
                    remap[i] = active.len() as u32;
                    active.push(i);
                }
            }
            assert_eq!(decoded.positions.len(), active.len(), "{name} active count");
            for (new_i, &old_i) in active.iter().enumerate() {
                assert_eq!(decoded.positions[new_i], orig.positions[old_i], "{name} pos {new_i}");
                assert_eq!(decoded.surface[new_i].1, orig.surface[old_i].1, "{name} comp {new_i}");
                assert!(
                    (decoded.surface[new_i].0[0] - orig.surface[old_i].0[0]).abs() < 1e-6
                        && (decoded.surface[new_i].0[1] - orig.surface[old_i].0[1]).abs() < 1e-6,
                    "{name} uv {new_i}"
                );
                if orig.surface[old_i].1 == face {
                    assert_eq!(decoded.colors[new_i], orig.colors[old_i], "{name} color {new_i}");
                }
                if hair == Some(orig.surface[old_i].1) {
                    assert_eq!(decoded.vectors[new_i], orig.vectors[old_i], "{name} vec {new_i}");
                }
            }
            assert_eq!(decoded.channels.len(), orig.channels.len());
            for ((och, oids, ovals), (dch, dids, dvals)) in orig.channels.iter().zip(&decoded.channels) {
                assert_eq!(och, dch);
                let mut exp_ids = Vec::new();
                let mut exp_vals = Vec::new();
                for (&oid, chunk) in oids.iter().zip(ovals.chunks_exact(6)) {
                    let nid = remap[oid as usize];
                    if nid != u32::MAX {
                        exp_ids.push(nid);
                        exp_vals.extend_from_slice(chunk);
                    }
                }
                assert_eq!(dids, &exp_ids, "{name} ch{och} ids");
                assert_eq!(dvals, &exp_vals, "{name} ch{och} vals");
            }
        }
        assert!(
            total_disk < 1_200_000,
            "expected on-disk SKREF2B assets under 1.2 MB total, got {total_disk}"
        );
        assert!(
            total_repacked < 1_500_000,
            "expected repacked assets under 1.5 MB total, got {total_repacked}"
        );
    }

    #[test]
    fn shifted_custom_uv_head_prefers_aligned_spatial_match_over_uv_collision() {
        let mut asset = ReferenceAsset::parse(&sample()).unwrap();
        // Reference has vertex 0 at (0,0,0) with UV (0.1,0.1), vertex 1 at (-0.08,0,0) with UV (0.5,0.5).
        asset.positions = vec![[0.0, 0.0, 0.0], [-0.08, 0.0, 0.0]];
        asset.surface = vec![([0.1, 0.1], 2), ([0.5, 0.5], 2)];
        asset.channels = vec![(44, vec![0, 1], vec![0x3c00, 0, 0, 0, 0, 0, 0xbc00, 0, 0, 0, 0, 0])];

        // Mod face is shifted by -0.10 in X and has custom UVs:
        // v0 is at (-0.10, 0, 0) (aligned to ref 0) but its custom UV (0.5, 0.5) collides with ref 1!
        // v1 is at (-0.18, 0, 0) (aligned to ref 1) with unmatched UV (0.05, 0.05) -> uv_coverage = 50% (< 90%).
        // v2 is a tooth vertex shifted -0.09 in Z near ref 1 (face skin), which must still match tooth ref 2 by UV.
        asset.positions.push([0.0, 0.0, 0.09]);
        asset.surface.push(([0.5, 0.95], 2));
        let mod_pos: Vec<u8> = [-0.10f32, 0.0, 0.0, -0.18, 0.0, 0.0, -0.10, 0.0, 0.0]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let mut uv = Vec::new();
        for pair in [[0x3800u16, 0x3800u16], [0x2666, 0x2666], [0x3800, 0x3b9a]] {
            for value in pair {
                uv.extend_from_slice(&value.to_le_bytes());
            }
            uv.extend_from_slice(&[0; 12]);
        }
        let part = ComponentPartition {
            face_candidates: vec![0, 1],
            teeth_candidates: vec![2],
            texcoords: uv,
            ..Default::default()
        };
        let transfer = transfer_legacy_surface(&asset, &mod_pos, &part, 2, 5).unwrap();
        assert!(transfer.uv_untrusted);
        assert!((transfer.head_shift[0] - 0.10).abs() < 1e-4);
        assert_eq!(transfer.correspondence, vec![(0, 0), (1, 1), (2, 2)]);
    }

    #[test]
    fn tight_uv_match_beats_tight_nearest_on_coincident_mouth_seam() {
        let mut asset = ReferenceAsset::parse(&sample()).unwrap();
        let q = |x: f32| f16_to_f32(f32_to_f16(x));
        // ref 0 = upper inner lip (UV 0.50, 0.91), ref 1 = lower inner lip (UV 0.92, 0.56),
        // ref 2..4 = anchor skin vertices establishing a pure +0.10 X head shift.
        asset.positions = vec![
            [0.0, 3.04, 135.69],
            [0.0, 3.04, 135.71],
            [1.0, 0.0, 0.0],
            [2.0, 0.0, 0.0],
            [3.0, 0.0, 0.0],
        ];
        asset.surface = vec![
            ([q(0.50), q(0.91)], 2),
            ([q(0.92), q(0.56)], 2),
            ([q(0.10), q(0.10)], 2),
            ([q(0.15), q(0.15)], 2),
            ([q(0.20), q(0.20)], 2),
        ];
        asset.channels = vec![(113, vec![0, 1], vec![0, 0, 0x3200, 0, 0, 0, 0, 0, 0xba00, 0, 0, 0])];

        // Custom-UV shifted head (v1 has custom UV -> uv_coverage = 80% < 90%):
        // v0 is lower inner lip (UV 0.92, 0.56) at aligned z=135.67 -> closer to upper ref 0 (0.02) than lower ref 1 (0.04).
        // Exact official UV within tight radius must select ref 1 instead of wrong-lip ref 0.
        let mod_pos: Vec<u8> = [
            -0.10f32, 3.04, 135.67,
            0.90, 0.0, 0.0,
            1.90, 0.0, 0.0,
            2.90, 0.0, 0.0,
            2.95, 0.0, 0.0,
        ]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
        let mut uv = Vec::new();
        for pair in [[0.92f32, 0.56], [0.10, 0.10], [0.15, 0.15], [0.20, 0.20], [0.77, 0.77]] {
            for value in pair {
                uv.extend_from_slice(&f32_to_f16(value).to_le_bytes());
            }
            uv.extend_from_slice(&[0; 12]);
        }
        let part = ComponentPartition {
            face_candidates: vec![0, 1, 2, 3, 4],
            texcoords: uv,
            ..Default::default()
        };
        let transfer = transfer_legacy_surface(&asset, &mod_pos, &part, 2, 5).unwrap();
        assert!(transfer.uv_untrusted);
        assert!(transfer.uv_matched.contains(&0));
        assert!(!transfer.uv_matched.contains(&4));
        assert_eq!(transfer.correspondence, vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 4)]);
    }

    /// Real data: the 3.5 default export is used as both reference and "mod".
    /// Every reference vertex must find its own position, so the transplant has
    /// to reproduce the payload exactly.
    #[test]
    fn real_asset_round_trip() {
        let asset_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/resources/shapekey/FRover35.skref");
        let bytes = std::fs::read(&asset_path).expect("read FRover35.skref");
        let asset = ReferenceAsset::parse(&bytes).expect("parse real asset");
        let pos: Vec<u8> = asset
            .positions
            .iter()
            .flat_map(|p| p.iter().flat_map(|f| f.to_le_bytes()))
            .collect();

        // candidates = every vertex id referenced by the asset's channels
        let mut candidates: Vec<u32> = asset.channels.iter().flat_map(|c| c.1.iter().copied()).collect();
        candidates.sort_unstable();
        candidates.dedup();

        let mut face_candidates = Vec::new();
        let mut eyes_candidates = Vec::new();
        let mut upper_teeth = Vec::new();
        let mut lower_teeth = Vec::new();
        for vid in 0..asset.positions.len() {
            match ref_vertex_component(asset.positions.len(), vid) {
                Some(ComponentType::FaceSkin) => face_candidates.push(vid as u32),
                Some(ComponentType::Eyes) => eyes_candidates.push(vid as u32),
                Some(ComponentType::TeethUpper) => upper_teeth.push(vid as u32),
                Some(ComponentType::TeethLower) => lower_teeth.push(vid as u32),
                _ => {}
            }
        }
        let mut teeth_candidates = upper_teeth;
        teeth_candidates.extend(lower_teeth);
        let partition = ComponentPartition {
            face_candidates,
            eyes_candidates,
            teeth_candidates,
            ..Default::default()
        };

        let channels: Vec<usize> = asset.channels.iter().map(|c| c.0).collect();
        let out = transplant_partitioned(&asset, &pos, &candidates, Some(&partition), &channels, 0.05, 0.0);
        for t in &out {
            assert!(
                t.matched as f32 >= t.reference_len as f32 * 0.95,
                "channel {} matched only {}/{}",
                t.channel,
                t.matched,
                t.reference_len
            );
        }
        // ch44 of the 3.5 export has 258 vertices; positions are identical on
        // both sides so a correct transplant reproduces them 1:1
        let ch44 = out.iter().find(|t| t.channel == 44).expect("ch44");
        assert_eq!(ch44.reference_len, 258);
        assert_eq!(ch44.matched, 258);
    }
}
