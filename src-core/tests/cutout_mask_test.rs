// src-core/tests/cutout_mask_test.rs

use std::collections::HashSet;

use wuwa_mod_core::{
    config_loader::{CharacterConfig, FallbackMaskRule, TextureNode},
    domain::{context::ModContext, pipeline::PipelineFixer},
    fixers::{cutout_mask::CutoutMaskFixer, traits::FixerContext},
};

fn make_test_config(hash: &str) -> CharacterConfig {
    let mut config = CharacterConfig::default();
    config.fallback_masks = Some(vec![FallbackMaskRule {
        hash: hash.to_string(),
        resource_name: "Resource_Mask_White".to_string(),
        filename: "Textures/mask_white.png".to_string(),
    }]);

    let mut node = TextureNode::default();
    node.replace = vec![format!("old_{}", hash)];
    config.textures.insert(hash.to_string(), node);

    config
}

#[test]
fn test_cutout_mask_inject_missing_override_and_idempotent() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_cutout_inject_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let ini_path = temp_dir.join("mod.ini");
    let ini_content = r#"[TextureOverrideComponent0]
hash = 7e400733
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let config = make_test_config("d63a624a");
    let original_hashes = HashSet::new();

    // Initial run: automatically injects missing mask
    {
        let mut mod_ctx = ModContext::new(
            &ini_path,
            ini_content.to_string(),
            original_hashes.clone(),
            true,
            false,
            false,
            0,
            true,
        );

        let mut ctx = FixerContext::new(&mut mod_ctx, &config, "TestChar");
        let fixer = CutoutMaskFixer;
        let run_res = fixer.run(&mut ctx).unwrap();
        assert!(run_res, "First run of CutoutMaskFixer must return true");

        let committed = mod_ctx.commit().unwrap();
        assert!(committed, "First run commit must be true");

        let updated_ini = std::fs::read_to_string(&ini_path).unwrap();
        assert!(updated_ini.contains("[TextureOverride_Replace_d63a624a]"));
        assert!(updated_ini.contains("[Resource_Mask_White]"));
        assert!(updated_ini.contains("filename = Textures/mask_white.png"));

        let png_path = temp_dir.join("Textures").join("mask_white.png");
        assert!(png_path.exists(), "mask_white.png must be created on disk");
    }

    // Second run: idempotence test with zero modifications
    {
        let current_ini = std::fs::read_to_string(&ini_path).unwrap();
        let mut mod_ctx2 = ModContext::new(&ini_path, current_ini, original_hashes, true, false, false, 0, true);

        let mut ctx2 = FixerContext::new(&mut mod_ctx2, &config, "TestChar");
        let fixer = CutoutMaskFixer;
        let run_res2 = fixer.run(&mut ctx2).unwrap();
        assert!(
            !run_res2,
            "Second run of CutoutMaskFixer must return false (idempotent)"
        );

        let committed2 = mod_ctx2.commit().unwrap();
        assert!(!committed2, "Second run commit must be false (0 changes)");
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cutout_mask_correct_invalid_this_null() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_cutout_null_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let ini_path = temp_dir.join("mod.ini");
    let ini_content = r#"[TextureOverrideMask]
hash = d63a624a
this = null
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let config = make_test_config("d63a624a");
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

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "TestChar");
    let fixer = CutoutMaskFixer;
    let run_res = fixer.run(&mut ctx).unwrap();
    assert!(run_res, "Should correct invalid this = null");

    let committed = mod_ctx.commit().unwrap();
    assert!(committed);

    let updated_ini = std::fs::read_to_string(&ini_path).unwrap();
    assert!(
        updated_ini.contains("this = Resource_Mask_White") || updated_ini.contains("this = ref Resource_Mask_White"),
        "Invalid null must be replaced with fallback mask"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cutout_mask_preserves_valid_custom_mask() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_cutout_custom_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let textures_dir = temp_dir.join("Textures");
    std::fs::create_dir_all(&textures_dir).unwrap();
    std::fs::write(textures_dir.join("CustomMask.png"), b"fake mask png").unwrap();

    let ini_path = temp_dir.join("mod.ini");
    let ini_content = r#"[TextureOverrideMask]
hash = d63a624a
this = ResourceCustomMask

[ResourceCustomMask]
filename = Textures/CustomMask.png
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let config = make_test_config("d63a624a");
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

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "TestChar");
    let fixer = CutoutMaskFixer;
    let run_res = fixer.run(&mut ctx).unwrap();
    assert!(!run_res, "Must NOT touch valid custom masks");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cutout_mask_path_with_leading_slashes() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_cutout_slash_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let textures_dir = temp_dir.join("Textures");
    std::fs::create_dir_all(&textures_dir).unwrap();
    std::fs::write(textures_dir.join("custom_mask.png"), b"fake mask png").unwrap();

    let ini_path = temp_dir.join("mod.ini");
    let ini_content = r#"[ResourceMyCutout]
filename = \Textures\custom_mask.png

[TextureOverrideMyCutout]
hash = d63a624a
this = ResourceMyCutout
"#;
    std::fs::write(&ini_path, ini_content).unwrap();

    let config = make_test_config("d63a624a");
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

    let mut ctx = FixerContext::new(&mut mod_ctx, &config, "TestChar");
    let fixer = CutoutMaskFixer;
    let run_res = fixer.run(&mut ctx).unwrap();
    assert!(!run_res, "Should recognize valid custom mask even with leading slash");

    let _ = std::fs::remove_dir_all(&temp_dir);
}
