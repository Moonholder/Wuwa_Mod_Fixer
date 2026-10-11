// src-core/tests/materialmap_test.rs

use std::collections::{HashMap, HashSet};

use wuwa_mod_core::{
    config_loader::{CharacterConfig, MaterialmapAdaptRule, TextureMeta, TextureNode},
    domain::{context::ModContext, pipeline::PipelineFixer},
    fixers::{materialmap::MaterialmapFixer, traits::FixerContext},
};

const ROVER_FEMALE_HAIR_DDS: &[u8] = include_bytes!("../src/resources/FRoverHair_C0D.dds");

#[test]
fn test_adapt_rover_materialmaps_multi_lightmap() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_mat_multi_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let ini_path = temp_dir.join("test.ini");
    let textures_dir = temp_dir.join("Textures");
    std::fs::create_dir_all(&textures_dir).unwrap();

    let dds_1 = textures_dir.join("Components-4 t=372bd73a.dds");
    let dds_2 = textures_dir.join("Components-4 t=372bd73a-1.dds");
    std::fs::write(&dds_1, ROVER_FEMALE_HAIR_DDS).unwrap();
    std::fs::write(&dds_2, ROVER_FEMALE_HAIR_DDS).unwrap();

    let ini_content = r#"[ResourceTexture11]
filename = Textures/Components-4 t=372bd73a.dds

[ResourceTexture11_1]
filename = Textures/Components-4 t=372bd73a-1.dds

[TextureOverrideTexture11]
hash = 081efd79
match_priority = 0
if $object_detected
    if $key_18 == 1
        this = ResourceTexture11
    else
        this = ResourceTexture11_1
    endif
endif
"#;

    let mut textures = HashMap::new();
    textures.insert(
        "081efd79".to_string(),
        TextureNode {
            meta: Some(TextureMeta {
                id: vec![4],
                type_: "L".to_string(),
                slot: None,
            }),
            replace: vec!["372bd73a".to_string()],
            derive: HashMap::new(),
        },
    );

    let config = CharacterConfig {
        textures,
        materialmap_adapt: Some(vec![MaterialmapAdaptRule {
            component_id: 4,
            material_hash: "e40b43c4".to_string(),
            source_lightmap_hash: None,
            clothing_value: None,
            ..Default::default()
        }]),
        ..Default::default()
    };

    let mut original_hashes = HashSet::new();
    original_hashes.insert("372bd73a".to_string());

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        false,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverFemale");

    let fixer = MaterialmapFixer;
    let modified = fixer.run(&mut ctx).unwrap();
    assert!(modified);

    assert!(ctx.ini().has_section("ResourceTexture_Replace_e40b43c4"));
    assert!(ctx.ini().has_section("ResourceTexture_Replace_e40b43c4_372bd73a-1"));

    let res1 = ctx.ini().get_section("ResourceTexture_Replace_e40b43c4").unwrap();
    assert_eq!(
        res1.get_unquoted_value("filename"),
        Some("Textures/Components-4 t=372bd73a_c4_r8.png".to_string())
    );

    let res2 = ctx
        .ini()
        .get_section("ResourceTexture_Replace_e40b43c4_372bd73a-1")
        .unwrap();
    assert_eq!(
        res2.get_unquoted_value("filename"),
        Some("Textures/Components-4 t=372bd73a-1_c4_r8.png".to_string())
    );

    assert!(ctx.ini().has_section("TextureOverride_Replace_e40b43c4"));
    let ovr = ctx.ini().get_section("TextureOverride_Replace_e40b43c4").unwrap();
    assert_eq!(ovr.get_value("hash"), Some("e40b43c4".to_string()));
    assert_eq!(ovr.get_value("match_priority"), Some("0".to_string()));

    let ovr_lines = ovr.lines.join("\n");
    assert!(ovr_lines.contains("if $object_detected"));
    assert!(ovr_lines.contains("if $key_18 == 1"));
    assert!(ovr_lines.contains("this = ResourceTexture_Replace_e40b43c4"));
    assert!(ovr_lines.contains("else"));
    assert!(ovr_lines.contains("this = ResourceTexture_Replace_e40b43c4_372bd73a-1"));
    assert!(ovr_lines.contains("endif"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_adapt_rover_materialmaps_single_lightmap() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_mat_single_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let ini_path = temp_dir.join("test.ini");
    let textures_dir = temp_dir.join("Textures");
    std::fs::create_dir_all(&textures_dir).unwrap();

    let dds_1 = textures_dir.join("Components-4 t=372bd73a.dds");
    std::fs::write(&dds_1, ROVER_FEMALE_HAIR_DDS).unwrap();

    let ini_content = r#"[ResourceTexture11]
filename = Textures/Components-4 t=372bd73a.dds

[TextureOverrideTexture11]
hash = 081efd79
match_priority = 0
this = ResourceTexture11
"#;

    let mut textures = HashMap::new();
    textures.insert(
        "081efd79".to_string(),
        TextureNode {
            meta: Some(TextureMeta {
                id: vec![4],
                type_: "L".to_string(),
                slot: None,
            }),
            replace: vec!["372bd73a".to_string()],
            derive: HashMap::new(),
        },
    );

    let config = CharacterConfig {
        textures,
        materialmap_adapt: Some(vec![MaterialmapAdaptRule {
            component_id: 4,
            material_hash: "e40b43c4".to_string(),
            source_lightmap_hash: None,
            clothing_value: None,
            ..Default::default()
        }]),
        ..Default::default()
    };

    let mut original_hashes = HashSet::new();
    original_hashes.insert("372bd73a".to_string());

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        false,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverFemale");

    let fixer = MaterialmapFixer;
    let modified = fixer.run(&mut ctx).unwrap();
    assert!(modified);

    assert!(ctx.ini().has_section("ResourceTexture_Replace_e40b43c4"));

    let res1 = ctx.ini().get_section("ResourceTexture_Replace_e40b43c4").unwrap();
    assert_eq!(
        res1.get_unquoted_value("filename"),
        Some("Textures/Components-4 t=372bd73a_c4_r8.png".to_string())
    );

    let ovr = ctx.ini().get_section("TextureOverride_Replace_e40b43c4").unwrap();
    assert_eq!(ovr.get_value("hash"), Some("e40b43c4".to_string()));
    assert_eq!(
        ovr.get_value("this"),
        Some("ResourceTexture_Replace_e40b43c4".to_string())
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_adapt_materialmaps_path_with_leading_slashes() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_mat_slash_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let ini_path = temp_dir.join("test.ini");
    let textures_dir = temp_dir.join("Textures");
    std::fs::create_dir_all(&textures_dir).unwrap();

    let dds_1 = textures_dir.join("Components-4 t=372bd73a.dds");
    std::fs::write(&dds_1, ROVER_FEMALE_HAIR_DDS).unwrap();

    let ini_content = r#"[ResourceTexture11]
filename = \Textures\Components-4 t=372bd73a.dds

[TextureOverrideTexture11]
hash = 081efd79
match_priority = 0
this = ResourceTexture11
"#;

    let mut textures = HashMap::new();
    textures.insert(
        "081efd79".to_string(),
        TextureNode {
            meta: Some(TextureMeta {
                id: vec![4],
                type_: "L".to_string(),
                slot: None,
            }),
            replace: vec!["372bd73a".to_string()],
            derive: HashMap::new(),
        },
    );

    let config = CharacterConfig {
        textures,
        materialmap_adapt: Some(vec![MaterialmapAdaptRule {
            component_id: 4,
            material_hash: "e40b43c4".to_string(),
            source_lightmap_hash: None,
            clothing_value: None,
            ..Default::default()
        }]),
        ..Default::default()
    };

    let mut original_hashes = HashSet::new();
    original_hashes.insert("372bd73a".to_string());

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        false,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverFemale");

    let fixer = MaterialmapFixer;
    let modified = fixer.run(&mut ctx).unwrap();
    assert!(modified, "Must succeed even when source path has leading slash");

    assert!(ctx.ini().has_section("ResourceTexture_Replace_e40b43c4"));
    let res1 = ctx.ini().get_section("ResourceTexture_Replace_e40b43c4").unwrap();
    assert_eq!(
        res1.get_unquoted_value("filename"),
        Some("Textures/Components-4 t=372bd73a_c4_r8.png".to_string())
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_materialmap_fixer_idempotency_and_missing_source() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_mat_idemp_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let ini_path = temp_dir.join("mod.ini");

    let ini_content = r#"[TextureOverrideC4L]
hash = 081efd79
this = ref ResourceC4L

[TextureOverrideC4M]
hash = e40b43c4
this = ref ResourceC4M

[ResourceC4L]
filename = Textires/C4L_NonExistent.dds

[ResourceC4M]
filename = Textures/C4M.dds
"#;

    let mut textures = HashMap::new();
    textures.insert(
        "081efd79".to_string(),
        TextureNode {
            meta: Some(TextureMeta {
                id: vec![4],
                type_: "L".to_string(),
                slot: None,
            }),
            replace: vec![],
            derive: HashMap::new(),
        },
    );

    let config = CharacterConfig {
        textures,
        materialmap_adapt: Some(vec![MaterialmapAdaptRule {
            component_id: 4,
            material_hash: "e40b43c4".to_string(),
            source_lightmap_hash: None,
            clothing_value: None,
            ..Default::default()
        }]),
        ..Default::default()
    };

    let mut original_hashes = HashSet::new();
    original_hashes.insert("081efd79".to_string());
    original_hashes.insert("e40b43c4".to_string());

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes.clone(),
        true,
        false,
        false,
        0,
        false,
    );

    let fixer = MaterialmapFixer;

    {
        let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverFemale");
        let modified = fixer.run(&mut ctx).unwrap();
        assert!(!modified, "Should not modify INI when source texture does not exist");
    }

    {
        let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverFemale");
        let modified = fixer.run(&mut ctx).unwrap();
        assert!(!modified, "Second run must be strictly idempotent");
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_materialmap_fixer_no_trailing_comments_leaked() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_mat_no_comments_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let ini_path = temp_dir.join("mod.ini");
    let textures_dir = temp_dir.join("Textures");
    std::fs::create_dir_all(&textures_dir).unwrap();

    let dds_path = textures_dir.join("Uniform_ID.dds");
    std::fs::write(&dds_path, ROVER_FEMALE_HAIR_DDS).unwrap();

    let ini_content = r#"[TextureOverrideBody_ID]
hash = 5422dac8
match_priority = 0
if $object_detected
    if $body == 1
        this = ResourceTextureUniform_ID
    else if $body == 2
        this = ResourceTexturePowerArmor_ID
    endif
endif

; Textures: Accessories --------------

[ResourceTextureUniform_ID]
filename = Textures/Uniform_ID.dds
[ResourceTexturePowerArmor_ID]
filename = Textures/Uniform_ID.dds
"#;

    let mut textures = HashMap::new();
    textures.insert(
        "5422dac8".to_string(),
        TextureNode {
            meta: Some(TextureMeta {
                id: vec![2],
                type_: "L".to_string(),
                slot: None,
            }),
            replace: vec![],
            derive: HashMap::new(),
        },
    );

    let config = CharacterConfig {
        textures,
        materialmap_adapt: Some(vec![MaterialmapAdaptRule {
            component_id: 2,
            material_hash: "faf5e483".to_string(),
            source_lightmap_hash: None,
            clothing_value: Some(4),
            ..Default::default()
        }]),
        ..Default::default()
    };

    let mut original_hashes = HashSet::new();
    original_hashes.insert("5422dac8".to_string());

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        false,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverMale");
    let fixer = MaterialmapFixer;
    let modified = fixer.run(&mut ctx).unwrap();
    assert!(modified);

    let ovr_mat = ctx.ini().get_section("TextureOverride_Replace_faf5e483").unwrap();
    let ovr_mat_text = ovr_mat.lines.join("\n");

    // Verify valid conditional branches are generated
    assert!(ovr_mat_text.contains("ResourceTexture_Replace_faf5e483"));
    // Verify trailing comments from parent section are not leaked into the generated section
    assert!(!ovr_mat_text.contains("Textures: Accessories"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_adapt_rover_female_dual_constants() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_rf_dual_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let ini_path = temp_dir.join("test.ini");
    let textures_dir = temp_dir.join("Textures");
    std::fs::create_dir_all(&textures_dir).unwrap();

    let dds_path = textures_dir.join("Body_Lightmap.dds");
    std::fs::write(&dds_path, ROVER_FEMALE_HAIR_DDS).unwrap();

    let ini_content = r#"[ResourceTextureBodyLight]
filename = Textures/Body_Lightmap.dds

[TextureOverrideBodyLight]
hash = 8dee74d3
this = ResourceTextureBodyLight
"#;

    let mut textures = HashMap::new();
    textures.insert(
        "8dee74d3".to_string(),
        TextureNode {
            meta: Some(TextureMeta {
                id: vec![3],
                type_: "L".to_string(),
                slot: None,
            }),
            replace: vec![],
            derive: HashMap::new(),
        },
    );

    // RoverFemale Component 3: skin = 64, clothing = 0
    let config = CharacterConfig {
        textures,
        materialmap_adapt: Some(vec![MaterialmapAdaptRule {
            component_id: 3,
            material_hash: "f813702e".to_string(),
            source_lightmap_hash: None,
            clothing_value: Some(0),
            skin_value: Some(64),
        }]),
        ..Default::default()
    };

    let mut original_hashes = HashSet::new();
    original_hashes.insert("8dee74d3".to_string());

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        false,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverFemale");
    let fixer = MaterialmapFixer;
    let modified = fixer.run(&mut ctx).unwrap();
    assert!(modified);

    assert!(ctx.ini().has_section("TextureOverride_Replace_f813702e"));
    assert!(ctx.ini().has_section("ResourceTexture_Replace_f813702e"));

    let res = ctx.ini().get_section("ResourceTexture_Replace_f813702e").unwrap();
    let filename = res.get_unquoted_value("filename").unwrap();
    assert!(filename.ends_with("_c3_r8.png"));

    let generated_file = temp_dir.join(&filename);
    assert!(generated_file.exists());

    let _ = std::fs::remove_dir_all(&temp_dir);
}
