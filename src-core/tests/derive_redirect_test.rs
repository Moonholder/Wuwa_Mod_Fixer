// src-core/tests/derive_redirect_test.rs

use wuwa_mod_core::{domain::cst::IniCstDocument, fixers::derive_redirect::DeriveRedirectFixer};

#[tokio::test]
async fn test_derive_redirect_multiple_sections_same_hash() {
    wuwa_mod_core::config_loader::init_config().await;
    let global_config = wuwa_mod_core::config_loader::config();
    let hiyuki_cfg = global_config
        .characters_ref()
        .get("Hiyuki")
        .expect("Hiyuki config must exist");

    let ini_content = r#"
[TextureOverrideDetectFaceTex]
hash = 0b71b442
$tex_active_ef4a = 1

[TextureOverrideTexture24]
hash = 0b71b442
match_priority = 0
if $object_detected && $siwacolor == 0
    this = ResourceTexture24
elif $object_detected && $siwacolor == 1
    this = ResourceTexture24.1
endif
"#;

    let mut ini = IniCstDocument::parse(ini_content);

    // 1. First run: should generate adjacent derive sections immediately after base sections
    let modified = DeriveRedirectFixer::run_multi(&mut ini, &[hiyuki_cfg]).unwrap();
    assert!(modified, "Must modify ini to add derive sections");

    // Verify TextureOverrideDetectFaceTex derives
    let face_lod = ini
        .get_section("TextureOverrideDetectFaceTex_LOD")
        .expect("TextureOverrideDetectFaceTex_LOD must exist");
    assert!(face_lod.get_value("hash").unwrap().eq_ignore_ascii_case("136e8f0e"));
    assert!(face_lod.lines.iter().any(|l| l.contains("$tex_active_ef4a = 1")));

    // Verify Texture24 LOD sections exist
    assert!(
        ini.has_section("TextureOverrideTexture24_LOD"),
        "TextureOverrideTexture24_LOD must exist"
    );

    // Verify insertion ordering: DetectFaceTex LOD section must precede TextureOverrideTexture24
    let face_pos = ini
        .sections
        .iter()
        .position(|s| s.name == "TextureOverrideDetectFaceTex")
        .unwrap();
    let face_lod_pos = ini
        .sections
        .iter()
        .position(|s| s.name == "TextureOverrideDetectFaceTex_LOD")
        .unwrap();
    let tex24_pos = ini
        .sections
        .iter()
        .position(|s| s.name == "TextureOverrideTexture24")
        .unwrap();

    assert_eq!(
        face_lod_pos,
        face_pos + 1,
        "Face LOD must be placed IMMEDIATELY after Face base section"
    );
    assert!(
        face_lod_pos < tex24_pos,
        "Face LOD must be BEFORE Texture24 base section"
    );

    // 3. Second run: idempotency test, should not make further modifications
    let modified_again = DeriveRedirectFixer::run_multi(&mut ini, &[hiyuki_cfg]).unwrap();
    assert!(!modified_again, "Second run must be idempotent (no modification)");
}

#[tokio::test]
async fn test_derive_redirect_partial_existing_sections() {
    wuwa_mod_core::config_loader::init_config().await;
    let global_config = wuwa_mod_core::config_loader::config();
    let hiyuki_cfg = global_config
        .characters_ref()
        .get("Hiyuki")
        .expect("Hiyuki config must exist");

    let ini_content = r#"
[TextureOverrideDetectFaceTex]
hash = 0b71b442
$tex_active_ef4a = 1

[TextureOverrideDetectFaceTex_LOD]
hash = 136e8f0e
match_priority = 0
$tex_active_ef4a = 1

[TextureOverrideTexture24]
hash = 0b71b442
match_priority = 0
if $object_detected && $siwacolor == 0
    this = ResourceTexture24
elif $object_detected && $siwacolor == 1
    this = ResourceTexture24.1
endif
"#;

    let mut ini = IniCstDocument::parse(ini_content);
    let modified = DeriveRedirectFixer::run_multi(&mut ini, &[hiyuki_cfg]).unwrap();
    assert!(modified, "Must add missing TextureOverrideTexture24 LOD sections");

    assert!(ini.has_section("TextureOverrideTexture24_LOD"));

    let detect_count = ini
        .sections
        .iter()
        .filter(|s| s.name.to_lowercase().starts_with("textureoverridedetectfacetex_lod"))
        .count();
    assert_eq!(detect_count, 2, "DetectFaceTex LOD sections must not be duplicated");
}

#[tokio::test]
async fn test_derive_redirect_incremental_duplicate_section() {
    use std::collections::HashMap;

    use wuwa_mod_core::config_loader::{CharacterConfig, TextureNode};

    let mut cfg1 = CharacterConfig::default();
    let mut derive1 = HashMap::new();
    derive1.insert("LOD".to_string(), vec!["7e6c8d99".to_string()]);
    cfg1.textures.insert(
        "0b71b442".to_string(),
        TextureNode {
            derive: derive1,
            ..Default::default()
        },
    );

    let ini_content = r#"
[TextureOverrideTexture24]
hash = 0b71b442
match_priority = 0
this = ResourceTexture24
"#;

    let mut ini = IniCstDocument::parse(ini_content);
    // Initial run with derive = [7e6c8d99]
    let modified1 = DeriveRedirectFixer::run_multi(&mut ini, &[&cfg1]).unwrap();
    assert!(modified1);
    assert!(ini.has_section("TextureOverrideTexture24_LOD"));

    // Configuration updated with additional hash [78295019, 7e6c8d99]
    let mut cfg2 = CharacterConfig::default();
    let mut derive2 = HashMap::new();
    derive2.insert("LOD".to_string(), vec!["78295019".to_string(), "7e6c8d99".to_string()]);
    cfg2.textures.insert(
        "0b71b442".to_string(),
        TextureNode {
            derive: derive2,
            ..Default::default()
        },
    );

    // Second pass
    let modified2 = DeriveRedirectFixer::run_multi(&mut ini, &[&cfg2]).unwrap();
    assert!(modified2);

    // Verify no duplicate section headers exist
    let mut seen_names = std::collections::HashSet::new();
    for sec in &ini.sections {
        let lower = sec.name.to_lowercase();
        assert!(
            !seen_names.contains(&lower),
            "Duplicate section header found: [{}]",
            sec.name
        );
        seen_names.insert(lower);
    }

    // Third pass: verify strict idempotence
    let modified3 = DeriveRedirectFixer::run_multi(&mut ini, &[&cfg2]).unwrap();
    assert!(!modified3, "Third run must be idempotent");
}

#[tokio::test]
async fn test_derive_redirect_self_heal_duplicate_sections() {
    use std::collections::HashMap;

    use wuwa_mod_core::config_loader::{CharacterConfig, TextureNode};

    let mut cfg = CharacterConfig::default();
    let mut derive = HashMap::new();
    derive.insert("LOD".to_string(), vec!["78295019".to_string(), "7e6c8d99".to_string()]);
    cfg.textures.insert(
        "0b71b442".to_string(),
        TextureNode {
            derive,
            ..Default::default()
        },
    );

    // Simulate damaged ini with duplicate section headers
    let damaged_ini = r#"
[TextureOverrideTexture24]
hash = 0b71b442
match_priority = 0
this = ResourceTexture24

[TextureOverrideTexture24_LOD]
hash = 78295019
match_priority = 0
this = ResourceTexture24

[TextureOverrideTexture24_LOD]
hash = 7e6c8d99
match_priority = 0
this = ResourceTexture24
"#;

    let mut ini = IniCstDocument::parse(damaged_ini);
    let modified = DeriveRedirectFixer::run_multi(&mut ini, &[&cfg]).unwrap();
    assert!(modified, "Must fix and de-duplicate existing duplicate sections");

    // Verify all section names are unique after self-healing
    let mut seen_names = std::collections::HashSet::new();
    for sec in &ini.sections {
        let lower = sec.name.to_lowercase();
        assert!(
            !seen_names.contains(&lower),
            "Section name still duplicated after self-heal: [{}]",
            sec.name
        );
        seen_names.insert(lower);
    }

    // Verify both hashes are preserved in document
    let hashes: Vec<String> = ini
        .sections
        .iter()
        .filter(|s| s.name.to_lowercase().starts_with("textureoverridetexture24_lod"))
        .filter_map(|s| s.get_value("hash"))
        .collect();
    assert_eq!(hashes.len(), 2);
    assert!(hashes.iter().any(|h| h.trim().eq_ignore_ascii_case("78295019")));
    assert!(hashes.iter().any(|h| h.trim().eq_ignore_ascii_case("7e6c8d99")));

    // Idempotency check
    let modified_again = DeriveRedirectFixer::run_multi(&mut ini, &[&cfg]).unwrap();
    assert!(!modified_again, "Self-healed ini must be idempotent");
}

#[tokio::test]
async fn test_derive_redirect_multi_state_no_nesting() {
    use std::collections::HashMap;

    use wuwa_mod_core::config_loader::{CharacterConfig, TextureNode};

    let mut cfg = CharacterConfig::default();
    let mut derive = HashMap::new();
    derive.insert("LOD".to_string(), vec!["136e8f0e".to_string()]);
    derive.insert("Gacha".to_string(), vec!["994322a0".to_string()]);
    cfg.textures.insert(
        "0b71b442".to_string(),
        TextureNode {
            derive,
            ..Default::default()
        },
    );

    let ini_content = r#"
[TextureOverrideTexture24]
hash = 0b71b442
match_priority = 0
this = ResourceTexture24
"#;

    let mut ini = IniCstDocument::parse(ini_content);
    let modified = DeriveRedirectFixer::run_multi(&mut ini, &[&cfg]).unwrap();
    assert!(modified);

    // Verify both LOD and Gacha derived sections are created
    assert!(ini.has_section("TextureOverrideTexture24_LOD"));
    assert!(ini.has_section("TextureOverrideTexture24_Gacha"));

    // Verify no nested derived sections (e.g. LOD_Gacha) are generated
    for sec in &ini.sections {
        let lower = sec.name.to_lowercase();
        assert!(
            !lower.contains("lod_gacha") && !lower.contains("gacha_lod"),
            "Nested derived section detected: [{}]",
            sec.name
        );
    }

    // Total sections count must be exactly 3 (base + LOD + Gacha)
    assert_eq!(ini.sections.len(), 3);

    // Idempotency check
    let modified_again = DeriveRedirectFixer::run_multi(&mut ini, &[&cfg]).unwrap();
    assert!(!modified_again);
}
