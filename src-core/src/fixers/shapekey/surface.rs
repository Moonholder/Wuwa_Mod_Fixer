//! Rest geometry, color mask, and tangent-frame corrections for Rover models.
use std::collections::{HashMap, HashSet};

use super::{
    rebuilder::f16_to_f32,
    transplant::{ComponentPartition, ReferenceAsset, SurfaceTransfer},
};

fn position(bytes: &[u8], id: usize) -> Option<[f32; 3]> {
    let row = bytes.get(id * 12..id * 12 + 12)?;
    Some(std::array::from_fn(|i| {
        f32::from_le_bytes(row[i * 4..i * 4 + 4].try_into().unwrap())
    }))
}

fn uv(bytes: &[u8], id: usize) -> Option<[f32; 2]> {
    let row = bytes.get(id * 16..id * 16 + 4)?;
    Some(std::array::from_fn(|i| {
        f16_to_f32(u16::from_le_bytes(row[i * 2..i * 2 + 2].try_into().unwrap()))
    }))
}

fn tooth(t: [f32; 2]) -> bool {
    0.35 < t[0] && t[0] < 0.65 && 0.93 < t[1] && t[1] < 1.0
}

fn distance(a: [f32; 3], b: [f32; 3]) -> f32 {
    (0..3).map(|i| (a[i] - b[i]).powi(2)).sum()
}

fn write_position(bytes: &mut [u8], id: usize, p: [f32; 3]) {
    for i in 0..3 {
        bytes[id * 12 + i * 4..id * 12 + i * 4 + 4].copy_from_slice(&p[i].to_le_bytes());
    }
}

/// Project the lip area onto the official neutral surface used for motion.
/// This is a projection (no repeated fractional correction), hence idempotent.
/// Teeth retain their sculpt: only demonstrably rigid shell offsets are removed.
pub fn repair_mouth_rest(
    asset: &ReferenceAsset,
    map: &SurfaceTransfer,
    part: &ComponentPartition,
    indices: &[u8],
    positions: &mut [u8],
    face_component: u32,
) -> (usize, usize) {
    let teeth: Vec<_> = asset
        .surface
        .iter()
        .enumerate()
        .filter_map(|(i, (t, c))| (*c == face_component && tooth(*t)).then_some(asset.positions[i]))
        .collect();
    if teeth.is_empty() {
        return (0, 0);
    }
    let center: [f32; 3] = std::array::from_fn(|a| teeth.iter().map(|p| p[a]).sum::<f32>() / teeth.len() as f32);
    let face: HashSet<_> = part.face_candidates.iter().copied().collect();
    let mut lips = 0;
    if !map.uv_untrusted || map.uv_coverage >= 0.50 {
        for &(id, ri) in &map.correspondence {
            if !face.contains(&id) || asset.surface[ri].1 != face_component || tooth(asset.surface[ri].0) {
                continue;
            }
            let target_ref = asset.positions[ri];
            // Measured mouth volume in reference model units, excluding nose, eyelids, and hair.
            if (target_ref[0] - center[0]).abs() > 2.6
                || (target_ref[2] - center[2]).abs() > 1.3
                || target_ref[1] < center[1] - 0.4
            {
                continue;
            }
            let target: [f32; 3] = std::array::from_fn(|a| target_ref[a] - map.head_shift[a]);
            let Some(old) = position(positions, id as usize) else {
                continue;
            };
            let d = distance(old, target);
            if d > 1e-6 && d < 1.0 {
                write_position(positions, id as usize, target);
                lips += 1;
            }
        }
    }
    let mapping: HashMap<_, _> = map.correspondence.iter().copied().collect();
    let candidates: HashSet<u32> = part
        .teeth_candidates
        .iter()
        .copied()
        .filter(|&i| uv(&part.texcoords, i as usize).is_some_and(tooth))
        .collect();
    let mut parent: HashMap<u32, u32> = candidates.iter().map(|&i| (i, i)).collect();
    fn root(parent: &HashMap<u32, u32>, mut id: u32) -> u32 {
        while parent[&id] != id {
            id = parent[&id]
        }
        id
    }
    for tri in indices.chunks_exact(12) {
        let ids: [u32; 3] = std::array::from_fn(|i| u32::from_le_bytes(tri[i * 4..i * 4 + 4].try_into().unwrap()));
        if !ids.iter().all(|i| candidates.contains(i)) {
            continue;
        }
        for j in 1..3 {
            let a = root(&parent, ids[0]);
            let b = root(&parent, ids[j]);
            parent.insert(b, a);
        }
    }
    let mut groups: HashMap<u32, Vec<u32>> = HashMap::new();
    for &id in &candidates {
        groups.entry(root(&parent, id)).or_default().push(id);
    }
    let mut moved = 0;
    for group in groups.values() {
        if group.len() < 20 {
            continue;
        }
        let mut deltas = Vec::new();
        for &id in group {
            let (Some(&ri), Some(p)) = (mapping.get(&id), position(positions, id as usize)) else {
                continue;
            };
            if asset.surface[ri].1 != face_component {
                continue;
            }
            deltas.push(std::array::from_fn::<_, 3, _>(|a| {
                (asset.positions[ri][a] - map.head_shift[a]) - p[a]
            }));
        }
        if deltas.len() != group.len() {
            continue;
        }
        let mean: [f32; 3] = std::array::from_fn(|a| deltas.iter().map(|d| d[a]).sum::<f32>() / deltas.len() as f32);
        let variance: f32 = deltas.iter().map(|&d| distance(d, mean)).sum::<f32>() / deltas.len() as f32;
        if variance > 1e-6 || distance(mean, [0.; 3]) <= 1e-4 || distance(mean, [0.; 3]) >= 0.15f32.powi(2) {
            continue;
        }
        for &id in group {
            let p = position(positions, id as usize).unwrap();
            write_position(positions, id as usize, std::array::from_fn(|a| p[a] + mean[a]));
            moved += 1;
        }
    }
    (lips, moved)
}

/// Exact neutral-position/UV matching prevents touching custom hair geometry.
/// Preserve authored normal XYZ; restore only tangent XYZW and handedness.
pub fn repair_hair_frame(
    asset: &ReferenceAsset,
    positions: &[u8],
    texcoords: &[u8],
    hair: &[u32],
    vectors: &mut [u8],
) -> usize {
    if asset.vectors.len() != asset.positions.len() {
        return 0;
    }
    let refs: Vec<_> = asset
        .surface
        .iter()
        .enumerate()
        .filter_map(|(i, (_, c))| (*c == 0).then_some(i))
        .collect();
    let mut grid: HashMap<(i32, i32, i32), Vec<usize>> = HashMap::new();
    let key = |p: [f32; 3]| {
        (
            (p[0] * 1000.).floor() as i32,
            (p[1] * 1000.).floor() as i32,
            (p[2] * 1000.).floor() as i32,
        )
    };
    for ri in refs {
        grid.entry(key(asset.positions[ri])).or_default().push(ri);
    }
    let mut changed = 0;
    for &id in hair {
        let id = id as usize;
        let (Some(p), Some(t), Some(old)) = (
            position(positions, id),
            uv(texcoords, id),
            vectors.get(id * 8..id * 8 + 8),
        ) else {
            continue;
        };
        if !p.iter().chain(&t).all(|v| v.is_finite()) {
            continue;
        }
        let (x, y, z) = key(p);
        let mut best: Option<(usize, i32, f32)> = None;
        for dx in -1..=1 {
            for dy in -1..=1 {
                for dz in -1..=1 {
                    if let Some(rs) = grid.get(&(x + dx, y + dy, z + dz)) {
                        for &ri in rs {
                            let d = distance(p, asset.positions[ri]);
                            let rt = asset.surface[ri].0;
                            if d >= 1e-6 || (t[0] - rt[0]).powi(2) + (t[1] - rt[1]).powi(2) >= 1e-8 {
                                continue;
                            }
                            let normal_error: i32 = (4..7)
                                .map(|a| (old[a] as i8 as i32 - asset.vectors[ri][a] as i8 as i32).pow(2))
                                .sum();
                            if (4..7).any(|a| (old[a] as i8 as i32 - asset.vectors[ri][a] as i8 as i32).abs() > 2) {
                                continue;
                            }
                            if best.is_none_or(|(r, n, b)| (normal_error, d, ri) < (n, b, r)) {
                                best = Some((ri, normal_error, d));
                            }
                        }
                    }
                }
            }
        }
        if let Some((ri, _, _)) = best {
            let row = &mut vectors[id * 8..id * 8 + 8];
            let reference = asset.vectors[ri];
            if [0, 1, 2, 3, 7].iter().any(|&a| row[a] != reference[a]) {
                for a in [0, 1, 2, 3, 7] {
                    row[a] = reference[a];
                }
                changed += 1;
            }
        }
    }
    changed
}

/// Matches face and teeth candidates by position and UV against official reference vertices
/// in `face_component`, and restores official COLOR0 values (outline suppression masks,
/// oral cavity masks, and shading). Idempotent; skips vertices that already match.
pub fn repair_face_color(
    asset: &ReferenceAsset,
    positions: &[u8],
    texcoords: &[u8],
    candidates: &[u32],
    face_component: u32,
    colors: &mut [u8],
) -> usize {
    repair_face_color_aligned(asset, positions, texcoords, candidates, face_component, [0.0; 3], colors)
}

/// Variant of [`repair_face_color`] that shifts mod positions by `head_shift` before
/// distance checks so globally translated custom heads still match their official UVs.
pub fn repair_face_color_aligned(
    asset: &ReferenceAsset,
    positions: &[u8],
    texcoords: &[u8],
    candidates: &[u32],
    face_component: u32,
    head_shift: [f32; 3],
    colors: &mut [u8],
) -> usize {
    if asset.colors.len() != asset.positions.len() || asset.surface.len() != asset.positions.len() {
        return 0;
    }
    let refs: Vec<usize> = asset
        .surface
        .iter()
        .enumerate()
        .filter_map(|(ri, (_, comp))| (*comp == face_component).then_some(ri))
        .collect();
    if refs.is_empty() {
        return 0;
    }

    let in_inner_lip_pocket = |uv: [f32; 2]| uv[0] > 0.0 && uv[0] < 0.15 && (0.45..=0.60).contains(&uv[1]);
    let mut grid: HashMap<(i32, i32), Vec<usize>> = HashMap::new();
    let mut pocket_refs: Vec<usize> = Vec::new();
    let key = |uv: [f32; 2]| ((uv[0] * 64.).floor() as i32, (uv[1] * 64.).floor() as i32);
    for &ri in &refs {
        let ru = asset.surface[ri].0;
        grid.entry(key(ru)).or_default().push(ri);
        if in_inner_lip_pocket(ru) {
            pocket_refs.push(ri);
        }
    }

    let mut changed = 0;
    for &id in candidates {
        let id = id as usize;
        let (Some(p), Some(t), Some(row)) = (
            position(positions, id),
            uv(texcoords, id),
            colors.get_mut(id * 4..id * 4 + 4),
        ) else {
            continue;
        };
        if !p.iter().chain(&t).all(|v| v.is_finite()) {
            continue;
        }
        let p_aligned = [p[0] + head_shift[0], p[1] + head_shift[1], p[2] + head_shift[2]];

        let (ku, kv) = key(t);
        // Tier 0: exact official UV; Tier 1: slightly nudged official UV near aligned vertex.
        let mut best: Option<(usize, u8, f32, f32)> = None;
        for du in -1..=1 {
            for dv in -1..=1 {
                if let Some(rs) = grid.get(&(ku + du, kv + dv)) {
                    for &ri in rs {
                        let ru = asset.surface[ri].0;
                        let uv_dist = (t[0] - ru[0]).powi(2) + (t[1] - ru[1]).powi(2);
                        let pos_dist = distance(p_aligned, asset.positions[ri]);
                        let candidate = if uv_dist <= 1e-6 && pos_dist <= 1.0 {
                            (0u8, uv_dist, pos_dist)
                        } else if uv_dist <= 2.25e-4 && pos_dist <= 0.0625 {
                            (1u8, uv_dist + 0.01 * pos_dist, pos_dist)
                        } else {
                            continue;
                        };
                        if best.is_none_or(|(_, bt, bs, bp)| candidate < (bt, bs, bp)) {
                            best = Some((ri, candidate.0, candidate.1, candidate.2));
                        }
                    }
                }
            }
        }

        // Inner-lip pocket vertices often undergo larger UV shifts inside the mouth-rim island
        // while staying within 0.05 units of the official surface; leaving Color0.B=255 creates dark lip outlines.
        if best.is_none() && in_inner_lip_pocket(t) {
            let mut pocket_best: Option<(usize, f32, f32)> = None;
            for &ri in &pocket_refs {
                let ru = asset.surface[ri].0;
                let pos_dist = distance(p_aligned, asset.positions[ri]);
                if pos_dist <= 0.0025 {
                    let uv_dist = (t[0] - ru[0]).powi(2) + (t[1] - ru[1]).powi(2);
                    if pocket_best.is_none_or(|(_, bp, bu)| (pos_dist, uv_dist) < (bp, bu)) {
                        pocket_best = Some((ri, pos_dist, uv_dist));
                    }
                }
            }
            if let Some((ri, _, _)) = pocket_best {
                best = Some((ri, 2, 0.0, 0.0));
            }
        }

        if let Some((ri, _, _, _)) = best {
            let reference = asset.colors[ri];
            if row != reference {
                row.copy_from_slice(&reference);
                changed += 1;
            }
        }
    }
    changed
}

#[allow(dead_code)]
pub fn repair_tooth_color(
    asset: &ReferenceAsset,
    positions: &[u8],
    texcoords: &[u8],
    teeth: &[u32],
    face_component: u32,
    colors: &mut [u8],
) -> usize {
    repair_face_color(asset, positions, texcoords, teeth, face_component, colors)
}

/// Sets tooth vertices to uniform red (255) for MRoverSkin1 outline suppression fallback.
pub fn repair_skin_tooth_red(colors: &mut [u8], texcoords: &[u8], teeth: &[u32]) -> usize {
    let mut changed = 0;
    for &id in teeth {
        let id = id as usize;
        let o = id * 16;
        if o + 4 > texcoords.len() {
            continue;
        }
        let u = f16_to_f32(u16::from_le_bytes([texcoords[o], texcoords[o + 1]]));
        let v = f16_to_f32(u16::from_le_bytes([texcoords[o + 2], texcoords[o + 3]]));
        if (0.35..=0.65).contains(&u) && (0.93..=1.05).contains(&v) {
            let co = id * 4;
            if co + 4 <= colors.len() && colors[co] != 255 {
                colors[co] = 255;
                changed += 1;
            }
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::rebuilder::f32_to_f16;

    fn bytes(p: &[[f32; 3]]) -> Vec<u8> {
        p.iter().flatten().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn asset(p: Vec<[f32; 3]>, surface: Vec<([f32; 2], u32)>) -> ReferenceAsset {
        ReferenceAsset {
            positions: p,
            surface,
            ..Default::default()
        }
    }

    #[test]
    fn lips_project_once_without_moving_eyes_or_outside_face() {
        let a = asset(
            vec![[0., 2., 10.], [0., 2., 10.], [0., 2., 15.]],
            vec![([0.5, 0.7], 1), ([0.5, 0.95], 1), ([0.5, 0.2], 1)],
        );
        let mut p = bytes(&[[0.2, 2., 10.], [0., 2., 10.], [0.2, 2., 15.]]);
        let outside = p[24..36].to_vec();
        let part = ComponentPartition {
            face_candidates: vec![0, 2],
            teeth_candidates: vec![1],
            ..Default::default()
        };
        let map = SurfaceTransfer {
            vertices: vec![0, 1, 2],
            channels: vec![],
            correspondence: vec![(0, 0), (1, 1), (2, 2)],
            ..Default::default()
        };
        assert_eq!(repair_mouth_rest(&a, &map, &part, &[], &mut p, 1), (1, 0));
        assert_eq!(position(&p, 0), Some(a.positions[0]));
        assert_eq!(&p[24..36], outside);
        assert_eq!(repair_mouth_rest(&a, &map, &part, &[], &mut p, 1), (0, 0));

        // Hybrid-UV shifted heads must project lips into their own shifted head frame.
        let shifted_map = SurfaceTransfer {
            correspondence: map.correspondence.clone(),
            head_shift: [0.1, 0.0, 0.0],
            uv_coverage: 0.62,
            uv_untrusted: true,
            ..Default::default()
        };
        let mut p_shifted = bytes(&[[0.15, 2., 10.], [0., 2., 10.], [0.2, 2., 15.]]);
        assert_eq!(repair_mouth_rest(&a, &shifted_map, &part, &[], &mut p_shifted, 1), (1, 0));
        assert_eq!(position(&p_shifted, 0), Some([-0.1, 2., 10.]));
        assert_eq!(&p_shifted[24..36], outside);
        assert_eq!(repair_mouth_rest(&a, &shifted_map, &part, &[], &mut p_shifted, 1), (0, 0));

        // Fully custom-UV heads must leave mouth vertices untouched.
        let custom_map = SurfaceTransfer {
            uv_coverage: 0.30,
            uv_untrusted: true,
            ..map
        };
        let mut p_custom = bytes(&[[0.2, 2., 10.], [0., 2., 10.], [0.2, 2., 15.]]);
        assert_eq!(repair_mouth_rest(&a, &custom_map, &part, &[], &mut p_custom, 1), (0, 0));
        assert_eq!(position(&p_custom, 0), Some([0.2, 2., 10.]));
    }

    #[test]
    fn rigid_tooth_shell_preserves_shape_but_sculpted_shell_is_not_snapped() {
        let rp: Vec<_> = (0..20).map(|i| [i as f32 * 0.01, 2., 10.]).collect();
        let a = asset(rp.clone(), vec![([0.5, 0.95], 1); 20]);
        let mut p = bytes(&rp.iter().map(|v| [v[0], v[1], v[2] - 0.09]).collect::<Vec<_>>());
        let mut tc = vec![0; 20 * 16];
        for i in 0..20 {
            tc[i * 16..i * 16 + 2].copy_from_slice(&0x3800u16.to_le_bytes());
            tc[i * 16 + 2..i * 16 + 4].copy_from_slice(&0x3b9au16.to_le_bytes());
        }
        let part = ComponentPartition {
            teeth_candidates: (0..20).collect(),
            texcoords: tc,
            ..Default::default()
        };
        let map = SurfaceTransfer {
            vertices: (0..20).collect(),
            channels: vec![],
            correspondence: (0..20).map(|i| (i, i as usize)).collect(),
            ..Default::default()
        };
        let ib: Vec<u8> = (1u32..19)
            .flat_map(|i| [0, i, i + 1])
            .flat_map(|i| i.to_le_bytes())
            .collect();
        assert_eq!(repair_mouth_rest(&a, &map, &part, &ib, &mut p, 1), (0, 20));
        for (i, r) in rp.iter().enumerate() {
            assert!(distance(position(&p, i).unwrap(), *r) < 1e-8);
        }
        assert_eq!(repair_mouth_rest(&a, &map, &part, &ib, &mut p, 1), (0, 0));
        let mut sculpt = bytes(
            &rp.iter()
                .enumerate()
                .map(|(i, v)| [v[0], v[1], v[2] - 0.09 - if i == 0 { 0.05 } else { 0. }])
                .collect::<Vec<_>>(),
        );
        let original = sculpt.clone();
        assert_eq!(repair_mouth_rest(&a, &map, &part, &ib, &mut sculpt, 1), (0, 0));
        assert_eq!(sculpt, original);

        // Head-shifted rigid tooth shell must align relative to head_shift.
        let mut shifted_p = bytes(&rp.iter().map(|v| [v[0] - 0.10, v[1], v[2] - 0.09]).collect::<Vec<_>>());
        let shifted_map = SurfaceTransfer {
            head_shift: [0.10, 0.0, 0.0],
            uv_coverage: 0.75,
            uv_untrusted: true,
            uv_matched: (0..20).collect(),
            ..map
        };
        assert_eq!(repair_mouth_rest(&a, &shifted_map, &part, &ib, &mut shifted_p, 1), (0, 20));
        for (i, r) in rp.iter().enumerate() {
            assert!(distance(position(&shifted_p, i).unwrap(), [r[0] - 0.10, r[1], r[2]]) < 1e-8);
        }
    }

    #[test]
    fn hair_tangent_restoration_preserves_normal_xyz_and_custom_geometry() {
        let mut a = asset(vec![[0., 0., 0.]], vec![([0., 0.], 0)]);
        a.vectors = vec![[127, 0, 0, 127, 0, 127, 0, 129]];
        let p = bytes(&[[0., 0., 0.], [0.01, 0., 0.]]);
        let mut v = [129, 0, 0, 127, 0, 126, 0, 127].repeat(2);
        let before = v.clone();
        assert_eq!(repair_hair_frame(&a, &p, &[0; 32], &[0, 1], &mut v), 1);
        assert_eq!(&v[4..7], &before[4..7]);
        assert_eq!(&v[8..], &before[8..]);
        assert_eq!(v[0], 127);
        assert_eq!(v[7], 129);
        assert_eq!(repair_hair_frame(&a, &p, &[0; 32], &[0, 1], &mut v), 0);
    }

    #[test]
    fn face_color_restoration_handles_exact_nudged_and_pocket_uvs() {
        let mut a = asset(
            vec![
                [0.0, 2.0, 10.0],  // exact tooth
                [0.5, 2.0, 10.0],  // nudged outer lip
                [0.1, 2.0, 10.02], // inner-lip pocket
                [0.0, 4.0, 12.0],  // official nose (must not touch custom UV overlay)
            ],
            vec![([0.5, 0.95], 1), ([0.52, 0.50], 1), ([0.055, 0.495], 1), ([0.50, 0.81], 1)],
        );
        a.colors = vec![
            [176, 51, 0, 255],
            [255, 58, 0, 255],
            [255, 36, 0, 255],
            [153, 0, 0, 255],
        ];

        // v0 exact UV, v1 nudged UV (+0.005, dp=0.02), v2 shifted inner-lip pocket (dp=0.025),
        // v3 custom nose overlay UV (far from [0.50, 0.81]), v4 far away geometry.
        let p = bytes(&[
            [-0.10, 2.0, 10.0],
            [0.41, 2.0, 10.0],
            [0.02, 2.0, 10.02],
            [-0.10, 4.0, 12.13],
            [99.0, 0.0, 0.0],
        ]);
        let mut tc = vec![0u8; 5 * 16];
        for (i, [u, v]) in [
            [0.5f32, 0.95],
            [0.525, 0.502],
            [0.016, 0.567],
            [0.678, 0.977],
            [0.5, 0.95],
        ]
        .iter()
        .enumerate()
        {
            tc[i * 16..i * 16 + 2].copy_from_slice(&f32_to_f16(*u).to_le_bytes());
            tc[i * 16 + 2..i * 16 + 4].copy_from_slice(&f32_to_f16(*v).to_le_bytes());
        }

        let custom_nose = [255u8, 16, 161, 255];
        let untouched_far = [0u8, 51, 255, 255];
        let mut colors = [0u8, 51, 255, 255].repeat(5);
        colors[12..16].copy_from_slice(&custom_nose);

        let changed = repair_face_color_aligned(&a, &p, &tc, &[0, 1, 2, 3, 4], 1, [0.10, 0.0, 0.0], &mut colors);
        assert_eq!(changed, 3);
        assert_eq!(&colors[0..4], &a.colors[0]);
        assert_eq!(&colors[4..8], &a.colors[1]);
        assert_eq!(&colors[8..12], &a.colors[2]);
        assert_eq!(&colors[12..16], &custom_nose);
        assert_eq!(&colors[16..20], &untouched_far);

        assert_eq!(
            repair_face_color_aligned(&a, &p, &tc, &[0, 1, 2, 3, 4], 1, [0.10, 0.0, 0.0], &mut colors),
            0
        );
    }
}
