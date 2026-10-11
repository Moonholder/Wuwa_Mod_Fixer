// src-core/tests/rabbit_fx_test.rs

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use wuwa_mod_core::{
    config_loader::{CharacterConfig, TextureMeta, TextureNode},
    domain::{context::ModContext, pipeline::PipelineFixer},
    fixers::{rabbit_fx::RabbitFxFixer, traits::FixerContext},
};

#[test]
fn test_rabbit_fx_ignore_non_texture_section_with_same_hash() {
    let ini_content = r#"[TextureOverrideComponent2]
hash = 4d3d06a6
match_first_index = 41706
match_index_count = 14676
if $managed_slot_id == $\modmanageragl\group_12\active_slot
    $object_detected = 1
    if $mod_enabled
        if ResourceMergedSkeleton !== null
            handling = skip
            drawindexed = 14676, 41706, 0
        endif
    endif
endif

[TextureOverridePosition]
hash = 8b82d036
match_priority = 1
if $managed_slot_id == $\modmanageragl\group_12\active_slot
    ;检测语句，加载贴图的Hash（角色里随便选一个就行）
    $ModActive = 2
endif
;根据WuWa-Model-Importer.ini给出的[CommandListSetShapeKey]参考
;得出如下使用方式（名称可以自定义，不一定是CommandListSetShapeKey）

[TextureOverrideTexture4]
hash = 8b82d036
match_priority = 0
if $managed_slot_id == $\modmanageragl\group_12\active_slot
    if $object_detected
        this = ResourceTexture4
    endif
endif
"#;

    let mut textures = HashMap::new();
    textures.insert(
        "8b82d036".to_string(),
        TextureNode {
            meta: Some(TextureMeta {
                id: vec![2],
                type_: "D".to_string(),
                slot: None,
            }),
            replace: vec![],
            derive: HashMap::new(),
        },
    );

    let config = CharacterConfig {
        textures,
        ..Default::default()
    };

    let mut original_hashes = HashSet::new();
    original_hashes.insert("8b82d036".to_string());
    original_hashes.insert("4d3d06a6".to_string());

    let mut mod_ctx = ModContext::new(
        Path::new("test.ini"),
        ini_content.to_string(),
        original_hashes.clone(),
        true,
        false,
        false,
        0,
        false,
    );

    let fixer = RabbitFxFixer;

    // Initial run: injects TextureOverrideTexture4 resource bindings without TextureOverridePosition comments
    {
        let mut ctx = FixerContext::new(&mut mod_ctx, &config, "TestChar");
        let modified = fixer.run(&mut ctx).unwrap();
        assert!(modified, "First run must inject valid rabbit fx block");
    }

    let comp2 = mod_ctx.ini.get_section("TextureOverrideComponent2").unwrap();
    let comp2_text = comp2.lines.join("\n");

    // Must inject valid Resource\RabbitFX\Diffuse
    assert!(comp2_text.contains("Resource\\RabbitFX\\Diffuse = ref ResourceTexture4"));
    // Outer if $object_detected must not be included
    assert!(!comp2_text.contains("if $object_detected"));
    // Must not include ShapeKey comments or ModActive clauses from TextureOverridePosition
    assert!(!comp2_text.contains("CommandListSetShapeKey"));
    assert!(!comp2_text.contains("$ModActive = 2"));
    assert!(!comp2_text.contains("检测语句"));

    // Second pass: must be strictly idempotent
    {
        let mut ctx = FixerContext::new(&mut mod_ctx, &config, "TestChar");
        let modified = fixer.run(&mut ctx).unwrap();
        assert!(!modified, "Second run must be strictly idempotent");
    }

    // Verify no duplicate block was appended
    let comp2_second = mod_ctx.ini.get_section("TextureOverrideComponent2").unwrap();
    let diffuse_count = comp2_second
        .lines
        .iter()
        .filter(|l| l.contains("Resource\\RabbitFX\\Diffuse"))
        .count();
    assert_eq!(diffuse_count, 1, "Must contain exactly 1 RabbitFX Diffuse binding");
}
