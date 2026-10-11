// src-core/tests/rover_fix_test.rs

use std::collections::{HashMap, HashSet};

use wuwa_mod_core::{
    config_loader::{CharacterConfig, TextureMeta, TextureNode},
    domain::{context::ModContext, pipeline::PipelineFixer},
    fixers::{rover_fix::RoverFixer, traits::FixerContext},
};

fn make_rover_male_config() -> CharacterConfig {
    let mut textures = HashMap::new();
    textures.insert(
        "e8349ade".to_string(),
        TextureNode {
            meta: Some(TextureMeta {
                id: vec![0],
                type_: "D".to_string(),
                slot: None,
            }),
            replace: vec![
                "old_hair_hash".to_string(),
                "7de9f13a".to_string(),
                "b4855e43".to_string(),
            ],
            derive: HashMap::new(),
        },
    );
    CharacterConfig {
        textures,
        hair_fix: Some(wuwa_mod_core::config_loader::HairFixConfig {
            trigger_hash: vec![
                "e8349ade".to_string(),
                "old_hair_hash".to_string(),
                "7de9f13a".to_string(),
                "b4855e43".to_string(),
            ],
            match_first_index: "144738".to_string(),
            match_index_count: "32112".to_string(),
            vg_offset: 139,
            vg_count: 24,
        }),
        ..Default::default()
    }
}

#[test]
fn test_rover_male_component6_split_and_idempotent() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_rover_male_c6_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let ini_path = temp_dir.join("mod.ini");
    let ini_content = r#"[Constants]
global $merge_status_id_0 = 0

[TextureOverrideComponent0]
hash = 12345678
match_first_index = 1000
match_index_count = 500
$\WWMIv1\vg_offset = 10
$\WWMIv1\vg_count = 5
$merge_status_id_0 = 1
run = CommandList\Handling\Skip

[CommandListUpdateMergedSkeleton]
$merge_status_id_0 = 0
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let config = make_rover_male_config();
    let mut original_hashes = HashSet::new();
    original_hashes.insert("old_hair_hash".to_string());

    // Initial run: splits Component6 and injects constants and command lists
    {
        let mut mod_ctx = ModContext::new(
            &ini_path,
            ini_content.to_string(),
            original_hashes,
            true,
            false,
            false,
            0,
            true,
        );

        let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverMale");
        let fixer = RoverFixer;
        let run_res = fixer.run(&mut ctx).unwrap();
        assert!(run_res, "First run of RoverFixer (RoverMale) must return true");

        let committed = mod_ctx.commit().unwrap();
        assert!(committed, "First run commit must be true");

        let updated_ini = std::fs::read_to_string(&ini_path).unwrap();
        assert!(updated_ini.contains("[TextureOverrideComponent6]"));
        assert!(updated_ini.contains("match_first_index = 144738"));
        assert!(updated_ini.contains("match_index_count = 32112"));
        assert!(updated_ini.contains("$\\WWMIv1\\vg_offset = 139"));
        assert!(updated_ini.contains("$\\WWMIv1\\vg_count = 24"));
        assert!(updated_ini.contains("global $merge_status_id_6 = 0"));
        assert!(updated_ini.contains("$merge_status_id_6 = 0"));
    }

    // Second run: idempotent check with zero modifications
    {
        let current_ini = std::fs::read_to_string(&ini_path).unwrap();
        let mut updated_hashes = HashSet::new();
        updated_hashes.insert("12345678".to_string());

        let mut mod_ctx2 = ModContext::new(&ini_path, current_ini, updated_hashes, true, false, false, 0, true);

        let mut ctx2 = FixerContext::new(&mut mod_ctx2, &config, "RoverMale");
        let fixer = RoverFixer;
        let run_res2 = fixer.run(&mut ctx2).unwrap();
        assert!(!run_res2, "Second run of RoverFixer must return false (already fixed)");

        let committed2 = mod_ctx2.commit().unwrap();
        assert!(!committed2, "Second run commit must be false (0 changes)");
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_rover_female_no_custom_hair_leaves_original_and_does_not_inject_fallback() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_rover_female_no_fallback_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let ini_path = temp_dir.join("mod.ini");
    let ini_content = r#"[TextureOverrideComponent0]
hash = 87654321
match_first_index = 2000
match_index_count = 1000
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let mut textures = HashMap::new();
    textures.insert(
        "c7953bd5".to_string(),
        TextureNode {
            meta: Some(TextureMeta {
                id: vec![0],
                type_: "D".to_string(),
                slot: None,
            }),
            replace: vec!["old_frover_hair_hash".to_string()],
            derive: HashMap::new(),
        },
    );
    let config = CharacterConfig {
        textures,
        hair_fix: Some(wuwa_mod_core::config_loader::HairFixConfig {
            trigger_hash: vec!["old_frover_hair_hash".to_string(), "c7953bd5".to_string()],
            match_first_index: String::new(),
            match_index_count: String::new(),
            vg_offset: 0,
            vg_count: 0,
        }),
        ..Default::default()
    };

    let mut original_hashes = HashSet::new();
    original_hashes.insert("old_frover_hair_hash".to_string());

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        true,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverFemale");
    let fixer = RoverFixer;
    let run_res = fixer.run(&mut ctx).unwrap();
    // RoverFemale has no custom hair textures, so it should not modify anything or inject fallback
    assert!(
        !run_res,
        "RoverFixer must return false when RoverFemale has no custom hair textures"
    );

    let committed = mod_ctx.commit().unwrap();
    assert!(!committed, "No changes committed");

    let updated_ini = std::fs::read_to_string(&ini_path).unwrap();
    assert!(
        !updated_ini.contains("[ResourceTextureRoverFemaleHair]"),
        "Must NOT inject RoverFemale fallback INI section"
    );
    assert!(
        !updated_ini.contains("[TextureOverrideTextureRoverFemaleHair]"),
        "Must NOT inject RoverFemale fallback override"
    );

    let dds_path = temp_dir.join("Textures").join("FRoverHair_C0D.dds");
    assert!(!dds_path.exists(), "FRoverHair_C0D.dds must NOT be created on disk");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_rover_non_target_character_skipped() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_rover_non_target_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let ini_path = temp_dir.join("mod.ini");
    let ini_content = r#"[TextureOverrideComponent0]
hash = 12345678
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let config = make_rover_male_config();
    let original_hashes = HashSet::new();

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        true,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "Lynae");
    let fixer = RoverFixer;
    let run_res = fixer.run(&mut ctx).unwrap();
    assert!(!run_res, "RoverFixer must return false for non-Rover character");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_rover_male_multi_hair_color_branch_collected_and_c6_injected() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_rover_multi_hair_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let tex_dir = temp_dir.join("Textures");
    std::fs::create_dir_all(&tex_dir).unwrap();

    let hair_names = [
        "Hair_Gray.dds",
        "Hair_Blonde.dds",
        "Hair_Brown.dds",
        "Hair_Purple.dds",
        "Hair_Orange.dds",
        "Hair_Black.dds",
        "HairPGR_Gray.dds",
        "HairPGR_Blonde.dds",
        "HairPGR_Brown.dds",
        "HairPGR_Purple.dds",
        "HairPGR_Orange.dds",
        "HairPGR_Black.dds",
    ];

    // Create BC7 dummy DDS files
    let dds_res = include_bytes!("../src/resources/MRoverHair_C6D.dds");
    for name in &hair_names {
        std::fs::write(tex_dir.join(name), dds_res).unwrap();
    }

    let ini_path = temp_dir.join("mod.ini");
    let ini_content = r#"[Constants]
global $merge_status_id_0 = 0

[TextureOverrideComponent0]
hash = 1e003b5a
match_first_index = 0
match_index_count = 42495
$\WWMIv1\vg_offset = 0
$\WWMIv1\vg_count = 46
$merge_status_id_0 = 1
run = CommandList\Handling\Skip
drawindexed = 37275, 0, 0

[TextureOverrideHairDiffuse]
hash = 7de9f13a
match_priority = 0
if $object_detected
    if $hair == 1 || $hair == 6 
        if $haircolor == 1
            this = ResourceTextureHair_GRAY
        else if $haircolor == 2
            this = ResourceTextureHair_BLONDE
        else if $haircolor == 3
            this = ResourceTextureHair_BROWN
        else if $haircolor == 4
            this = ResourceTextureHair_PURPLE
        else if $haircolor == 5
            this = ResourceTextureHair_ORANGE
        else if $haircolor == 6
            this = ResourceTextureHair_BLACK
        endif
    else
        if $haircolor == 1
            this = ResourceTexturePGRHair_GRAY
        else if $haircolor == 2
            this = ResourceTexturePGRHair_BLONDE
        else if $haircolor == 3
            this = ResourceTexturePGRHair_BROWN
        else if $haircolor == 4
            this = ResourceTexturePGRHair_PURPLE
        else if $haircolor == 5
            this = ResourceTexturePGRHair_ORANGE
        else if $haircolor == 6
            this = ResourceTexturePGRHair_BLACK
        endif
    endif
endif

[ResourceTextureHair_GRAY]
filename = Textures/Hair_Gray.dds
[ResourceTextureHair_BLONDE]
filename = Textures/Hair_Blonde.dds
[ResourceTextureHair_BROWN]
filename = Textures/Hair_Brown.dds
[ResourceTextureHair_PURPLE]
filename = Textures/Hair_Purple.dds
[ResourceTextureHair_ORANGE]
filename = Textures/Hair_Orange.dds
[ResourceTextureHair_BLACK]
filename = Textures/Hair_Black.dds

[ResourceTexturePGRHair_GRAY]
filename = Textures/HairPGR_Gray.dds
[ResourceTexturePGRHair_BLONDE]
filename = Textures/HairPGR_Blonde.dds
[ResourceTexturePGRHair_BROWN]
filename = Textures/HairPGR_Brown.dds
[ResourceTexturePGRHair_PURPLE]
filename = Textures/HairPGR_Purple.dds
[ResourceTexturePGRHair_ORANGE]
filename = Textures/HairPGR_Orange.dds
[ResourceTexturePGRHair_BLACK]
filename = Textures/HairPGR_Black.dds
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let config = make_rover_male_config();

    let mut original_hashes = HashSet::new();
    original_hashes.insert("7de9f13a".to_string());

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        true,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverMale");
    let fixer = RoverFixer;
    let run_res = fixer.run(&mut ctx).unwrap();
    assert!(run_res, "RoverFixer must succeed");

    let committed = mod_ctx.commit().unwrap();
    assert!(committed, "Must commit changes");

    let updated_ini = std::fs::read_to_string(&ini_path).unwrap();
    assert!(updated_ini.contains("[TextureOverrideComponent6]"));
    assert!(updated_ini.contains("ps-t1 = ResourceTextureHair_GRAY"));
    assert!(updated_ini.contains("ps-t1 = ResourceTextureHair_BLONDE"));
    assert!(updated_ini.contains("ps-t1 = ResourceTexturePGRHair_BLACK"));
    assert!(updated_ini.contains("match_first_index = 144738"));
    assert!(updated_ini.contains("match_index_count = 32112"));
    assert!(updated_ini.contains("$\\WWMIv1\\vg_offset = 139"));
    assert!(updated_ini.contains("$\\WWMIv1\\vg_count = 24"));

    let comp6 = mod_ctx.ini.get_section("TextureOverrideComponent6").unwrap();
    let comp6_text = comp6.lines.join("\n");
    // Must not wrap an extra outer if $object_detected
    assert!(!comp6_text.contains("if $object_detected"));
    // Verify relative indentation is normalized to base indent
    assert!(comp6_text.contains("if $hair == 1 || $hair == 6"));
    assert!(comp6_text.contains("    if $haircolor == 1"));
    assert!(comp6_text.contains("        ps-t1 = ResourceTextureHair_GRAY"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_rover_no_component0_does_not_generate_fallback() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_rover_no_comp0_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let ini_path = temp_dir.join("mod.ini");
    let ini_content = r#"[TextureOverrideComponent2]
hash = 12345678
match_first_index = 0
match_index_count = 1000
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let config = make_rover_male_config();
    let original_hashes = HashSet::new();

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        true,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverMale");
    let fixer = RoverFixer;
    let run_res = fixer.run(&mut ctx).unwrap();
    assert!(
        !run_res,
        "RoverFixer must not generate fallback when Component0 is missing"
    );

    let updated_ini = std::fs::read_to_string(&ini_path).unwrap();
    assert!(!updated_ini.contains("ResourceTextureRoverMaleHair"));
    assert!(!updated_ini.contains("TextureOverrideComponent6"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_rover_unknown_future_hash_will_not_trigger() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_rover_future_hash_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let ini_path = temp_dir.join("mod.ini");
    // Simulate future asset variant with unknown hash
    let ini_content = r#"[TextureOverrideComponent0]
hash = future_hash_999999
match_first_index = 200000
match_index_count = 10000
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let config = make_rover_male_config();
    let mut original_hashes = HashSet::new();
    original_hashes.insert("future_hash_999999".to_string());

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        true,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverMale");
    let fixer = RoverFixer;
    let run_res = fixer.run(&mut ctx).unwrap();
    assert!(!run_res, "RoverFixer must NOT trigger on unknown future hashes");

    let updated_ini = std::fs::read_to_string(&ini_path).unwrap();
    assert!(
        !updated_ini.contains("[TextureOverrideComponent6]"),
        "Must NOT create Component6 for future unknown hash"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_rover_male_component6_split_without_merge_status_id_0() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_rover_no_merge_status_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let ini_path = temp_dir.join("mod.ini");
    // Legacy template without $merge_status_id_0
    let ini_content = r#"[Constants]
global $state_id = 0

[TextureOverrideComponent0]
hash = 12345678
match_first_index = 1000
match_index_count = 500
$\WWMIv1\vg_offset = 10
$\WWMIv1\vg_count = 5
run = CommandList\Handling\Skip

[CommandListUpdateMergedSkeleton]
if $state_id
    $state_id = 0
else
    $state_id = 1
endif
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let config = make_rover_male_config();
    let mut original_hashes = HashSet::new();
    original_hashes.insert("old_hair_hash".to_string());

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        true,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverMale");
    let fixer = RoverFixer;
    let run_res = fixer.run(&mut ctx).unwrap();
    assert!(run_res, "RoverFixer must succeed");

    let committed = mod_ctx.commit().unwrap();
    assert!(committed, "Must commit changes");

    let updated_ini = std::fs::read_to_string(&ini_path).unwrap();
    // Generates Component6 and its geometry parameters
    assert!(updated_ini.contains("[TextureOverrideComponent6]"));
    assert!(updated_ini.contains("match_first_index = 144738"));
    assert!(updated_ini.contains("match_index_count = 32112"));
    assert!(updated_ini.contains("$\\WWMIv1\\vg_offset = 139"));
    assert!(updated_ini.contains("$\\WWMIv1\\vg_count = 24"));

    // Should not inject $merge_status_id_6 without template support
    assert!(!updated_ini.contains("$merge_status_id_6"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_rover_female_without_trigger_hash_does_not_modify_textures_or_create_files() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_rover_no_trigger_hash_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let tex_dir = temp_dir.join("Textures");
    std::fs::create_dir_all(&tex_dir).unwrap();

    let dds_res = include_bytes!("../src/resources/FRoverHair_C0D.dds");
    let tex_path = tex_dir.join("Components-0 t=c7953bd5.dds");
    std::fs::write(&tex_path, dds_res).unwrap();
    let initial_tex_bytes = std::fs::read(&tex_path).unwrap();

    let ini_path = temp_dir.join("mod.ini");
    let ini_content = r#"[TextureOverrideComponent0]
hash = a38211d3
match_first_index = 0
match_index_count = 18831

[ResourceTexture1]
filename = Textures/Components-0 t=c7953bd5.dds

[TextureOverrideTexture1]
hash = c7953bd5
match_priority = 0
this = ResourceTexture1
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let mut textures = HashMap::new();
    textures.insert(
        "c7953bd5".to_string(),
        TextureNode {
            meta: Some(TextureMeta {
                id: vec![0],
                type_: "D".to_string(),
                slot: None,
            }),
            replace: vec!["6aac203f".to_string(), "04192868".to_string()],
            derive: HashMap::new(),
        },
    );

    let config = CharacterConfig {
        main_hashes: vec![wuwa_mod_core::config_loader::Replacement {
            old: vec!["a38211d3".to_string(), "be84b775".to_string()],
            new: "b7b6abd9".to_string(),
        }],
        textures,
        hair_fix: Some(wuwa_mod_core::config_loader::HairFixConfig {
            trigger_hash: vec!["6aac203f".to_string(), "04192868".to_string()],
            match_first_index: String::new(),
            match_index_count: String::new(),
            vg_offset: 0,
            vg_count: 0,
        }),
        ..Default::default()
    };

    let mut original_hashes = HashSet::new();
    original_hashes.insert("a38211d3".to_string());
    original_hashes.insert("c7953bd5".to_string());

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        true,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverFemale");
    let fixer = RoverFixer;
    let run_res = fixer.run(&mut ctx).unwrap();
    assert!(
        !run_res,
        "RoverFixer / HairFixer must NOT trigger when mod does not match trigger_hash"
    );

    let committed = mod_ctx.commit().unwrap();
    assert!(!committed, "No changes should be committed");

    // Texture content must remain completely untouched
    let after_tex_bytes = std::fs::read(&tex_path).unwrap();
    assert_eq!(
        initial_tex_bytes, after_tex_bytes,
        "Texture file must not be modified when trigger_hash is not matched"
    );

    // Verify zero BAK files generated
    for entry in walkdir::WalkDir::new(&temp_dir) {
        let entry = entry.unwrap();
        let fname = entry.file_name().to_string_lossy();
        assert!(
            !fname.ends_with(".BAK"),
            "No backup BAK file should be created: {}",
            fname
        );
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_rover_male_mesh_only_mod_splits_component6_and_injects_fallback() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_rover_male_mesh_only_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let ini_path = temp_dir.join("mod.ini");
    let ini_content = r#"[Constants]
global $merge_status_id_0 = 0

[TextureOverrideComponent0]
hash = 1e003b5a
match_first_index = 0
match_index_count = 52713
$\WWMIv1\vg_offset = 0
$\WWMIv1\vg_count = 46
$merge_status_id_0 = 1
run = CommandList\Handling\Skip

[CommandListUpdateMergedSkeleton]
$merge_status_id_0 = 0
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let config = CharacterConfig {
        main_hashes: vec![wuwa_mod_core::config_loader::Replacement {
            old: vec!["1e003b5a".to_string()],
            new: "52c1090e".to_string(),
        }],
        hair_fix: Some(wuwa_mod_core::config_loader::HairFixConfig {
            trigger_hash: vec!["b4855e43".to_string(), "7de9f13a".to_string()],
            match_first_index: "144738".to_string(),
            match_index_count: "32112".to_string(),
            vg_offset: 139,
            vg_count: 24,
        }),
        ..Default::default()
    };

    // Mod only has mesh hash 1e003b5a, NO trigger_hash (no b4855e43 or 7de9f13a)
    let mut original_hashes = HashSet::new();
    original_hashes.insert("1e003b5a".to_string());

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        true,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverMale");
    let fixer = RoverFixer;
    let run_res = fixer.run(&mut ctx).unwrap();
    assert!(
        run_res,
        "RoverMale mesh-only mod must trigger split_hair_component even without hair trigger_hash"
    );

    let committed = mod_ctx.commit().unwrap();
    assert!(committed, "Must commit Component6 and fallback changes");

    let updated_ini = std::fs::read_to_string(&ini_path).unwrap();
    assert!(updated_ini.contains("[TextureOverrideComponent6]"));
    assert!(updated_ini.contains("match_first_index = 144738"));
    assert!(updated_ini.contains("match_index_count = 32112"));
    assert!(updated_ini.contains("$\\WWMIv1\\vg_offset = 139"));
    assert!(updated_ini.contains("$\\WWMIv1\\vg_count = 24"));
    assert!(updated_ini.contains("ps-t1 = ResourceTextureRoverMaleHair"));
    assert!(updated_ini.contains("global $merge_status_id_6 = 0"));
    assert!(updated_ini.contains("$merge_status_id_6 = 0"));

    let fallback_dds = temp_dir.join("Textures").join("RoverMaleHair_D.dds");
    assert!(
        fallback_dds.exists(),
        "RoverMaleHair_D.dds fallback must be created for RoverMale"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}
