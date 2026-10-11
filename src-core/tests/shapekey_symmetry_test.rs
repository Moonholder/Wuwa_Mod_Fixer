use std::collections::HashMap;

use wuwa_mod_core::{
    config_loader::{ShapeKeyFixConfig, SymmetryFilter, TargetShapeKey},
    shapekey_fixer::ShapeKeyRebuilder,
};

#[test]
fn test_target_shapekey_parsing() {
    let t_left = TargetShapeKey::parse("32L").unwrap();
    assert_eq!(t_left.target_channel, 32);
    assert_eq!(t_left.filter, SymmetryFilter::Left);

    let t_right = TargetShapeKey::parse("33r").unwrap();
    assert_eq!(t_right.target_channel, 33);
    assert_eq!(t_right.filter, SymmetryFilter::Right);

    let t_all = TargetShapeKey::parse("142").unwrap();
    assert_eq!(t_all.target_channel, 142);
    assert_eq!(t_all.filter, SymmetryFilter::All);

    let t_all_explicit = TargetShapeKey::parse("142A").unwrap();
    assert_eq!(t_all_explicit.target_channel, 142);
    assert_eq!(t_all_explicit.filter, SymmetryFilter::All);
}

#[test]
fn test_spatial_symmetry_split() {
    // Test vertex position payload:
    // v0: x = -2.0 (Left)
    // v1: x =  2.0 (Right)
    // v2: x = -1.5 (Left)
    // v3: x =  1.5 (Right)
    let mut pos_buf = Vec::new();
    let coords: [f32; 12] = [
        -2.0, 0.0, 100.0, // v0: Left
        2.0, 0.0, 100.0, // v1: Right
        -1.5, 0.0, 100.0, // v2: Left
        1.5, 0.0, 100.0, // v3: Right
    ];
    for c in coords {
        pos_buf.extend_from_slice(&c.to_le_bytes());
    }

    // Source ShapeKey payload:
    // Channel 14 contains 4 vertices (v0, v1, v2, v3)
    let mut old_offset = vec![0u8; 128 * 4];
    // Channel 14 starts at 0, count = 4
    let st = 0u32;
    let ed = 4u32;
    old_offset[14 * 4..14 * 4 + 4].copy_from_slice(&st.to_le_bytes());
    for i in 15..128 {
        old_offset[i * 4..i * 4 + 4].copy_from_slice(&ed.to_le_bytes());
    }

    let mut old_id = Vec::new();
    let mut old_val = Vec::new();
    for vid in 0..4u32 {
        old_id.extend_from_slice(&vid.to_le_bytes());
        // disp: 0, 0, 1.0
        old_val.extend_from_slice(&0.0f32.to_le_bytes());
        old_val.extend_from_slice(&0.0f32.to_le_bytes());
        old_val.extend_from_slice(&1.0f32.to_le_bytes());
    }

    let mut remap = HashMap::new();
    remap.insert(
        14,
        vec![
            TargetShapeKey {
                target_channel: 32,
                filter: SymmetryFilter::Left,
            },
            TargetShapeKey {
                target_channel: 33,
                filter: SymmetryFilter::Right,
            },
            TargetShapeKey {
                target_channel: 142,
                filter: SymmetryFilter::All,
            },
        ],
    );

    let config = ShapeKeyFixConfig {
        trigger_hash: vec![],
        section_rewrites: None,
        custom_values_array: None,
        expression_remap: Some(remap),
        offset_stride: Some(12),
    };

    let rebuilder = ShapeKeyRebuilder::new(&config, "RoverMale").unwrap();
    let result = rebuilder
        .rebuild_buffers(&old_offset, &old_id, &old_val, Some(&pos_buf))
        .expect("rebuild should succeed");

    // Verify rebuilt channel offsets:
    // batch0 covers channels 0..126; batch1 covers channels 127..253
    // Channel 32 maps to batch0 index 32
    // Channel 33 maps to batch0 index 33
    // Channel 142 maps to batch1 index 15 (142 - 127 = 15)
    let off32_st = u32::from_le_bytes(result.offset_buf[32 * 4..32 * 4 + 4].try_into().unwrap());
    let off32_ed = u32::from_le_bytes(result.offset_buf[33 * 4..33 * 4 + 4].try_into().unwrap());
    let cnt_32 = off32_ed - off32_st;
    assert_eq!(cnt_32, 2, "Channel 32 (Left) should contain exactly 2 left vertices");

    let off33_st = u32::from_le_bytes(result.offset_buf[33 * 4..33 * 4 + 4].try_into().unwrap());
    let off33_ed = u32::from_le_bytes(result.offset_buf[34 * 4..34 * 4 + 4].try_into().unwrap());
    let cnt_33 = off33_ed - off33_st;
    assert_eq!(cnt_33, 2, "Channel 33 (Right) should contain exactly 2 right vertices");

    // Batch 1 (starts at offset 512 bytes):
    let b1_base = 512;
    let k_142 = 142 - 127;
    let off142_st = u32::from_le_bytes(
        result.offset_buf[b1_base + k_142 * 4..b1_base + k_142 * 4 + 4]
            .try_into()
            .unwrap(),
    );
    let off142_ed = u32::from_le_bytes(
        result.offset_buf[b1_base + (k_142 + 1) * 4..b1_base + (k_142 + 1) * 4 + 4]
            .try_into()
            .unwrap(),
    );
    let cnt_142 = off142_ed - off142_st;
    assert_eq!(cnt_142, 4, "Channel 142 (All) should contain all 4 vertices");

    // Verify mapped vertex IDs:
    // Channel 32 must contain v0 and v2
    let id_32_0 = u32::from_le_bytes(
        result.vertex_id_buf[(off32_st as usize) * 4..(off32_st as usize) * 4 + 4]
            .try_into()
            .unwrap(),
    );
    let id_32_1 = u32::from_le_bytes(
        result.vertex_id_buf[(off32_st as usize + 1) * 4..(off32_st as usize + 1) * 4 + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(id_32_0, 0);
    assert_eq!(id_32_1, 2);

    // Channel 33 must contain v1 and v3
    let id_33_0 = u32::from_le_bytes(
        result.vertex_id_buf[(off33_st as usize) * 4..(off33_st as usize) * 4 + 4]
            .try_into()
            .unwrap(),
    );
    let id_33_1 = u32::from_le_bytes(
        result.vertex_id_buf[(off33_st as usize + 1) * 4..(off33_st as usize + 1) * 4 + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(id_33_0, 1);
    assert_eq!(id_33_1, 3);
}
