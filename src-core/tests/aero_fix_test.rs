// src-core/tests/aero_fix_test.rs

use std::collections::HashSet;

use wuwa_mod_core::{
    config_loader::CharacterConfig,
    domain::{context::ModContext, pipeline::PipelineFixer},
    fixers::{aero_fix::AeroFixer, traits::FixerContext},
};

#[test]
fn test_aero_rover_female_texcoord_idempotent() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_aero_texcoord_idempotent_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let ini_path = temp_dir.join("mod.ini");
    let tc_path = temp_dir.join("TexCoord.buf");
    let ib_path = temp_dir.join("Index.buf");

    let fixed_data = include_bytes!("../src/resources/FRoverC5_TexCoord.buf");
    let vertex_count = fixed_data.len() / 16;

    let tc_stride = 16usize;
    let mut initial_tc_data = vec![0u8; vertex_count * tc_stride];
    for b in &mut initial_tc_data {
        *b = 0xAA;
    }

    let mut index_data = Vec::with_capacity(vertex_count * 4);
    for i in 0..vertex_count as u32 {
        index_data.extend_from_slice(&i.to_le_bytes());
    }

    std::fs::write(&tc_path, &initial_tc_data).unwrap();
    std::fs::write(&ib_path, &index_data).unwrap();

    let ini_content = format!(
        r#"[TextureOverrideComponent5]
hash = e5d5062a
drawindexed = {}, 0, 0

[ResourceTexCoordBuffer]
type = Buffer
stride = 16
filename = TexCoord.buf

[ResourceIndexBuffer]
type = Buffer
stride = 4
filename = Index.buf
"#,
        vertex_count
    );
    std::fs::write(&ini_path, &ini_content).unwrap();

    let config = CharacterConfig::default();
    let mut original_hashes = HashSet::new();
    original_hashes.insert("e5d5062a".to_string());

    // Initial run: applies fix and writes back TexCoord.buf
    {
        let mut mod_ctx = ModContext::new(
            &ini_path,
            ini_content.clone(),
            original_hashes.clone(),
            true,
            false,
            false,
            1, // aero_fix_mode = 1 (TexCoord)
            false,
        );

        let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverFemale");
        let fixer = AeroFixer;
        let run_res = fixer.run(&mut ctx).unwrap();
        assert!(run_res, "First run of AeroFixer must return true");

        let committed = mod_ctx.commit().unwrap();
        assert!(committed, "First run commit must be true (TexCoord changed)");

        assert!(
            !mod_ctx.backed_up.contains(&ini_path.canonicalize().unwrap()),
            "mod.ini must NOT be backed up since it wasn't changed"
        );
        assert!(
            mod_ctx.backed_up.contains(&tc_path.canonicalize().unwrap()),
            "TexCoord.buf MUST be backed up"
        );
    }

    // Second run: must be idempotent and perform zero writes
    {
        let current_ini_content = std::fs::read_to_string(&ini_path).unwrap();
        let mut mod_ctx2 = ModContext::new(
            &ini_path,
            current_ini_content,
            original_hashes.clone(),
            true,
            false,
            false,
            1,
            false,
        );

        let mut ctx2 = FixerContext::new(&mut mod_ctx2, &config, "RoverFemale");
        let fixer = AeroFixer;
        let run_res2 = fixer.run(&mut ctx2).unwrap();
        assert!(!run_res2, "Second run of AeroFixer must return false (already fixed)");

        let committed2 = mod_ctx2.commit().unwrap();
        assert!(!committed2, "Second run commit must be false (0 changes detected)");
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_aero_rover_female_texture_mode_idempotent() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_aero_texture_idempotent_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let ini_path = temp_dir.join("mod.ini");
    let ini_content = r#"[TextureOverrideComponent5]
hash = e5d5062a
drawindexed = 6, 0, 0
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let config = CharacterConfig::default();
    let mut original_hashes = HashSet::new();
    original_hashes.insert("e5d5062a".to_string());

    // Initial run: Mode 2 texture override injection
    {
        let mut mod_ctx = ModContext::new(
            &ini_path,
            ini_content.to_string(),
            original_hashes.clone(),
            true,
            false,
            false,
            2, // aero_fix_mode = 2 (Texture)
            false,
        );

        let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverFemale");
        let fixer = AeroFixer;
        let run_res = fixer.run(&mut ctx).unwrap();
        assert!(run_res, "First run of AeroFixer (Mode 2) must return true");

        let committed = mod_ctx.commit().unwrap();
        assert!(committed, "First run commit must be true (INI modified)");

        let updated_ini = std::fs::read_to_string(&ini_path).unwrap();
        assert!(updated_ini.contains("[Constants]"));
        assert!(updated_ini.contains("global $object_detected = 0"));
        assert!(updated_ini.contains("$object_detected = 1"));
        assert!(updated_ini.contains("[ResourceTextureFRoverAeroEyes]"));
        assert!(updated_ini.contains("filename = Textures/FRoverAeroEyes.dds"));
        assert!(updated_ini.contains("[TextureOverrideTextureFRoverAeroEyes]"));
        assert!(updated_ini.contains("hash = a856c4f2"));
        assert!(updated_ini.contains("if $object_detected"));

        let dds_path = temp_dir.join("Textures").join("FRoverAeroEyes.dds");
        assert!(dds_path.exists(), "FRoverAeroEyes.dds must be generated");
    }

    // Second run: must be strictly idempotent with zero modifications
    {
        let current_ini_content = std::fs::read_to_string(&ini_path).unwrap();
        let mut mod_ctx2 = ModContext::new(
            &ini_path,
            current_ini_content,
            original_hashes.clone(),
            true,
            false,
            false,
            2,
            false,
        );

        let mut ctx2 = FixerContext::new(&mut mod_ctx2, &config, "RoverFemale");
        let fixer = AeroFixer;
        let run_res2 = fixer.run(&mut ctx2).unwrap();
        assert!(!run_res2, "Second run of AeroFixer (Mode 2) must return false");

        let committed2 = mod_ctx2.commit().unwrap();
        assert!(!committed2, "Second run commit must be false (0 changes)");
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_aero_rover_female_texture_mode_no_comp5_skipped() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_aero_no_comp5_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let ini_path = temp_dir.join("mod.ini");
    let ini_content = r#"[TextureOverrideComponent0]
hash = e5d5062a
drawindexed = 100, 0, 0
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let config = CharacterConfig::default();
    let mut original_hashes = HashSet::new();
    original_hashes.insert("e5d5062a".to_string());

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        2, // Texture mode
        false,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverFemale");
    let fixer = AeroFixer;
    let run_res = fixer.run(&mut ctx).unwrap();
    assert!(!run_res, "AeroFixer must skip when Component 5 is not present");

    let committed = mod_ctx.commit().unwrap();
    assert!(!committed, "No changes should be committed");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_aero_non_target_character_skipped() {
    let temp_dir = std::env::temp_dir().join(format!(
        "wuwa_test_aero_non_target_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let ini_path = temp_dir.join("mod.ini");
    let ini_content = r#"[TextureOverrideComponent5]
hash = e5d5062a
drawindexed = 6, 0, 0
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let config = CharacterConfig::default();
    let original_hashes = HashSet::new();

    let mut mod_ctx = ModContext::new(
        &ini_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        1,
        false,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "RoverMale");
    let fixer = AeroFixer;
    let run_res = fixer.run(&mut ctx).unwrap();
    assert!(!run_res, "AeroFixer must return false for non-RoverFemale character");

    let _ = std::fs::remove_dir_all(&temp_dir);
}
