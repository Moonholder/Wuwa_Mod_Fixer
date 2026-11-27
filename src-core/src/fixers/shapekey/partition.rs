//! Extracts component mesh partitions (face, eyes, teeth) from model context.
use crate::{collector, fixers::traits::FixerContext};

use super::{rebuilder::f16_to_f32, transplant::ComponentPartition};

/// Builds a `ComponentPartition` by analyzing the mod's draw components, index buffer, and UV coordinates.
pub fn extract_component_partition(
    ctx: &FixerContext,
    index_bytes: Option<&[u8]>,
    tc_bytes: Option<&[u8]>,
) -> Option<ComponentPartition> {
    let idx_bytes = index_bytes?;
    let ini_str = ctx.ini().to_string();
    let comp_indices = collector::parse_component_indices(&ini_str);

    let (face_comp_id, eyes_comp_id) = match ctx.char_name {
        "RoverFemale" | "FRoverSkin1" => (Some(2u8), Some(5u8)),
        "RoverMale" | "MRoverSkin1" => (Some(1u8), Some(4u8)),
        _ => (None, None),
    };

    let get_vids = |comp_id: Option<u8>| -> Vec<u32> {
        let Some(cid) = comp_id else {
            return Vec::new();
        };
        if let Some(&(count, offset)) = comp_indices.get(&cid) {
            let start = offset * 4;
            let end = (offset + count) * 4;
            if end <= idx_bytes.len() {
                let mut vids: Vec<u32> = idx_bytes[start..end]
                    .chunks_exact(4)
                    .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                    .collect();
                vids.sort_unstable();
                vids.dedup();
                return vids;
            }
        }
        Vec::new()
    };

    let face_all = get_vids(face_comp_id);
    let eyes = get_vids(eyes_comp_id);

    // Separate teeth candidates from face skin candidates using UV coordinates.
    let (face, teeth) = if let Some(tc) = tc_bytes {
        let mut f = Vec::new();
        let mut t = Vec::new();
        for &v in &face_all {
            let o = v as usize * 16;
            if o + 4 <= tc.len() {
                let u_raw = u16::from_le_bytes([tc[o], tc[o + 1]]);
                let v_raw = u16::from_le_bytes([tc[o + 2], tc[o + 3]]);
                let u = f16_to_f32(u_raw);
                let v_coord = f16_to_f32(v_raw);
                if (0.35..=0.65).contains(&u) && (0.93..=1.05).contains(&v_coord) {
                    t.push(v);
                    continue;
                }
            }
            f.push(v);
        }
        (f, t)
    } else {
        (face_all, Vec::new())
    };

    if !face.is_empty() || !eyes.is_empty() || !teeth.is_empty() {
        Some(ComponentPartition {
            face_candidates: face,
            eyes_candidates: eyes,
            teeth_candidates: teeth,
            texcoords: tc_bytes.map(|b| b.to_vec()).unwrap_or_default(),
            mouth_motion: Default::default(),
        })
    } else {
        None
    }
}
