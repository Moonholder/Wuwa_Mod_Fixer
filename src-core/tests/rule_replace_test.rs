// src-core/tests/rule_replace_test.rs

use std::{collections::HashSet, path::Path};

use wuwa_mod_core::{
    config_loader::{CharacterConfig, Replacement, ReplacementRule},
    domain::{context::ModContext, pipeline::PipelineFixer},
    fixers::{rule_replace::RuleReplaceFixer, traits::FixerContext},
};

#[test]
fn test_shapekey_checksum_replacement_and_idempotency() {
    let ini_content = r#"
[CommandListSetupShapeKeys]
; Pass 4 byte checksum of shapekey offsets to ensure that we only modify expected values
$\WWMIv1\shapekey_checksum = 2742
cs-t33 = ResourceShapeKeyOffsetBuffer

[CommandListOther]
shapekey_checksum = 9999 ; custom comment
"#;

    let mut mod_ctx = ModContext::new(
        Path::new("dummy/mod.ini"),
        ini_content.to_string(),
        HashSet::new(),
        true,
        false,
        false,
        0,
        true,
    );

    let mut char_cfg = CharacterConfig::default();
    char_cfg.checksum = Some("1718".to_string());

    let mut ctx = FixerContext::new(&mut mod_ctx, &char_cfg, "Rover");

    let fixer = RuleReplaceFixer;
    let modified = fixer.run(&mut ctx).expect("Fixer should run cleanly");
    assert!(modified, "Must detect and modify checksum lines");

    let setup_sec = ctx.ini().get_section("CommandListSetupShapeKeys").unwrap();
    assert!(
        setup_sec
            .lines
            .iter()
            .any(|l| l.contains(r"$\WWMIv1\shapekey_checksum = 1718")),
        r"$\WWMIv1\shapekey_checksum must be replaced with 1718"
    );
    assert!(
        setup_sec.lines.iter().any(|l| l.contains("Pass 4 byte checksum")),
        "Comments must be preserved"
    );

    let other_sec = ctx.ini().get_section("CommandListOther").unwrap();
    assert!(
        other_sec
            .lines
            .iter()
            .any(|l| l.contains("shapekey_checksum = 1718 ; custom comment")),
        "shapekey_checksum must be replaced with 1718 and preserve comment"
    );

    // Idempotence test: second run must not make any modifications
    let modified_second = fixer.run(&mut ctx).expect("Second run should run cleanly");
    assert!(!modified_second, "Second run must be strictly idempotent");
}

#[test]
fn test_combined_checksum_and_custom_rules() {
    let ini_content = r#"
[CommandListSetupShapeKeys]
$\WWMIv1\shapekey_checksum = 2742

[TextureOverrideComponent0]
match_first_index = 129168
match_index_count = 67176
"#;

    let mut mod_ctx = ModContext::new(
        Path::new("dummy/mod.ini"),
        ini_content.to_string(),
        HashSet::new(),
        true,
        false,
        false,
        0,
        true,
    );

    let mut char_cfg = CharacterConfig::default();
    char_cfg.checksum = Some("1718".to_string());
    char_cfg.rules = Some(vec![
        ReplacementRule {
            line_prefix: "match_first_index".to_string(),
            replacements: vec![Replacement {
                old: vec!["129168".to_string()],
                new: "130992".to_string(),
            }],
        },
        ReplacementRule {
            line_prefix: "match_index_count".to_string(),
            replacements: vec![Replacement {
                old: vec!["67176".to_string()],
                new: "69000".to_string(),
            }],
        },
    ]);

    let mut ctx = FixerContext::new(&mut mod_ctx, &char_cfg, "Rover");

    let fixer = RuleReplaceFixer;
    let modified = fixer.run(&mut ctx).expect("Fixer should run cleanly");
    assert!(modified);

    let setup_sec = ctx.ini().get_section("CommandListSetupShapeKeys").unwrap();
    assert!(
        setup_sec
            .lines
            .iter()
            .any(|l| l.contains(r"$\WWMIv1\shapekey_checksum = 1718"))
    );

    let comp0 = ctx.ini().get_section("TextureOverrideComponent0").unwrap();
    assert!(comp0.lines.iter().any(|l| l.contains("match_first_index = 130992")));
    assert!(comp0.lines.iter().any(|l| l.contains("match_index_count = 69000")));
}
