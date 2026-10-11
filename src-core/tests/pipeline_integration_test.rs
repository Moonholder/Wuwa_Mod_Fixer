// src-core/tests/pipeline_integration_test.rs

use std::{collections::HashSet, path::Path};

use wuwa_mod_core::{
    domain::{context::ModContext, cst::IniCstDocument, pipeline::PipelineFixer},
    fixers::{
        cutout_mask::CutoutMaskFixer, derive_redirect::DeriveRedirectFixer, resource_override::ResourceOverrideFixer,
        traits::FixerContext,
    },
};

#[tokio::test]
async fn test_resource_override_fixer_slots() {
    wuwa_mod_core::config_loader::init_config().await;
    let global_config = wuwa_mod_core::config_loader::config();
    let lynae_cfg = &global_config.characters_ref()["Lynae"];

    let ini_content = r#"
[TextureOverrideComponent4]
hash = 7e400733
match_first_index = 173856
match_index_count = 100314

[CommandListTriggerResourceOverrides]
    CheckTextureOverride = ps-t0
    CheckTextureOverride = ps-t1
    CheckTextureOverride = ps-t2
    CheckTextureOverride = ps-t3
    CheckTextureOverride = ps-t4
    CheckTextureOverride = ps-t5
    CheckTextureOverride = ps-t6
    CheckTextureOverride = ps-t7

[TextureOverrideTexture3]
hash = c3375aee
match_priority = 0
if $object_detected
    this = ResourceTEX
endif
"#;

    let dummy_path = Path::new("dummy_test_dir/mod.ini");
    let mut original_hashes = HashSet::new();
    original_hashes.insert("c3375aee".to_string());

    let mut mod_ctx = ModContext::new(
        dummy_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        true,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, lynae_cfg, "Lynae");

    let res_fixer = ResourceOverrideFixer;
    let modified = res_fixer.run(&mut ctx).unwrap();
    assert!(modified);

    let cmd_sec = ctx.ini().get_section("CommandListTriggerResourceOverrides").unwrap();
    assert!(
        cmd_sec
            .get_all_values("CheckTextureOverride")
            .iter()
            .any(|v| v.eq_ignore_ascii_case("ps-t9")),
        "ps-t9 must be in CheckTextureOverride"
    );
}

#[tokio::test]
async fn test_cutout_mask_fixer_and_pipeline() {
    wuwa_mod_core::config_loader::init_config().await;
    let global_config = wuwa_mod_core::config_loader::config();
    let lynae_cfg = &global_config.characters_ref()["Lynae"];

    let ini_content = r#"
[TextureOverrideComponent4]
hash = 7e400733
match_first_index = 173856
match_index_count = 100314

[CommandListTriggerResourceOverrides]
    CheckTextureOverride = ps-t0
    CheckTextureOverride = ps-t1
    CheckTextureOverride = ps-t2
    CheckTextureOverride = ps-t3
    CheckTextureOverride = ps-t4
    CheckTextureOverride = ps-t5
    CheckTextureOverride = ps-t6
    CheckTextureOverride = ps-t7
"#;

    let dummy_path = Path::new("dummy_test_dir/mod.ini");
    let mut original_hashes = HashSet::new();
    original_hashes.insert("7e400733".to_string());

    let mut mod_ctx = ModContext::new(
        dummy_path,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        true,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, lynae_cfg, "Lynae");

    // 1. Run CutoutMaskFixer
    let cutout_fixer = CutoutMaskFixer;
    let mod1 = cutout_fixer.run(&mut ctx).unwrap();
    assert!(mod1, "CutoutMaskFixer must inject missing cutout mask");

    assert!(ctx.ini().has_section("TextureOverride_Replace_d63a624a"));
    assert!(ctx.ini().has_section("Resource_Mask_White"));

    // 2. Run ResourceOverrideFixer
    let res_fixer = ResourceOverrideFixer;
    let mod2 = res_fixer.run(&mut ctx).unwrap();
    assert!(mod2, "ResourceOverrideFixer must register ps-t8");

    let cmd_sec = ctx.ini().get_section("CommandListTriggerResourceOverrides").unwrap();
    assert!(
        cmd_sec
            .get_all_values("CheckTextureOverride")
            .iter()
            .any(|v| v.eq_ignore_ascii_case("ps-t8")),
        "ps-t8 must be added to CheckTextureOverride"
    );

    // 3. Run DeriveRedirectFixer
    let mod3 = DeriveRedirectFixer::run_multi(ctx.ini_mut(), &[lynae_cfg]).unwrap();
    assert!(mod3, "DeriveRedirectFixer must derive 994322a0");

    let has_994 = ctx.ini().sections.iter().any(|s| {
        s.get_value("hash")
            .map_or(false, |h| h.eq_ignore_ascii_case("994322a0"))
    });
    assert!(
        has_994,
        "994322a0 LOD override must be automatically generated from injected d63a624a"
    );
}

#[tokio::test]
async fn test_cutout_mask_fixer_handles_null_resource() {
    wuwa_mod_core::config_loader::init_config().await;
    let global_config = wuwa_mod_core::config_loader::config();
    let lynae_cfg = &global_config.characters_ref()["Lynae"];

    let ini_content = r#"
[ResourceTexture4]
filename = Textures/Components-0-1-2-3-4-5 t=7f91ca3e.dds

[TextureOverrideTexture4]
hash = d63a624a
this = null
"#;

    let temp_dir = std::env::temp_dir().join("wwmi_test_cutout_null_pipe");
    let _ = std::fs::create_dir_all(&temp_dir);
    let temp_ini = temp_dir.join("mod.ini");

    let mut original_hashes = HashSet::new();
    original_hashes.insert("d63a624a".to_string());

    let mut mod_ctx = ModContext::new(
        &temp_ini,
        ini_content.to_string(),
        original_hashes,
        true,
        false,
        false,
        0,
        true,
    );

    let mut ctx = FixerContext::new(&mut mod_ctx, lynae_cfg, "Lynae");

    let cutout_fixer = CutoutMaskFixer;
    let modified = cutout_fixer.run(&mut ctx).unwrap();
    assert!(modified, "CutoutMaskFixer must fix this = null");

    let sec = ctx.ini().get_section("TextureOverrideTexture4").unwrap();
    assert_eq!(
        sec.get_value("this").unwrap(),
        "Resource_Mask_White",
        "this = null must be corrected to Resource_Mask_White"
    );
    assert!(ctx.ini().has_section("Resource_Mask_White"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_rover_rabbitfx_and_materialmap_injection_clean() {
    let ini_txt = r#"[TextureOverrideComponent0]
hash = c698c02f
match_first_index = 0
match_index_count = 53259
"#;
    let doc = IniCstDocument::parse(ini_txt);

    if let Some(comp0) = doc.get_section("TextureOverrideComponent0") {
        let hash_count = comp0.lines.iter().filter(|l| l.trim().starts_with("hash")).count();
        let priority_count = comp0
            .lines
            .iter()
            .filter(|l| l.trim().starts_with("match_priority"))
            .count();
        assert!(hash_count <= 1, "TextureOverrideComponent0 must have at most 1 hash");
        assert_eq!(
            priority_count, 0,
            "TextureOverrideComponent0 must NOT contain 'match_priority'"
        );
    }
}
