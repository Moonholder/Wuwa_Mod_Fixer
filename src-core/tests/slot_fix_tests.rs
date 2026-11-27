// src-core/tests/slot_fix_tests.rs
//
// The mandatory test cases for the strictly idempotent statement-level slot-fix
// engine, driven by the *real* compiled Hiyuki rule:
//   rev = 1: ps-t6 -> ps-t7, ps-t7 -> ps-t8, ps-t9 -> ps-t10
//
//   T1  full chain, no cascade (single pass)
//   T2  ps-t9 companion auto-disambiguates ps-t7 (exclusive source)
//   T3  ps-t10 companion proves the shift already happened (exclusive target)
//   T4  strict same-revision idempotence
//   T5  cross-revision upgrade without any manual rollback
//   T6  user edit protection (dirty signature)
//   T7  unmarked lone ps-t7 is intercepted as ambiguous
//   T8  same-component vb0 co-mutation (A) and backup lineage (B)
//   T9  phase 2 decision fixation + shared-timestamp rollback
//
// Plus regression guards for real 3DMigoto constraints:
//   * provenance anchors are standalone comment lines (never trailing comments),
//     mirrored to the indentation of the statement they describe;
//   * `checktextureoverride` / `[CommandListTriggerResourceOverrides]` are never
//     touched.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
};

use wuwa_mod_core::{
    ModFixer,
    config_loader::{CharacterConfig, CompiledSlotRule},
    domain::cst::IniCstDocument,
    events::NullEventSink,
    slot_fix::{self, AmbiguousSlotItem, OverlapDecision, OverlapPolicy, SlotFixSession},
};

// ── Fixtures ────────────────────────────────────────────────────────────────

async fn hiyuki() -> (CharacterConfig, CompiledSlotRule) {
    wuwa_mod_core::config_loader::init_config().await;
    let cfg = wuwa_mod_core::config_loader::config();
    let char_cfg = cfg
        .characters_ref()
        .get("Hiyuki")
        .expect("Hiyuki must exist in config.json")
        .clone();
    let rule = char_cfg
        .slot_fix
        .clone()
        .expect("Hiyuki.slot_fix must be compiled into config.json by scripts/compile_config.js");
    assert_eq!(rule.latest_rev, 1);
    assert_eq!(rule.closures.get(&0).unwrap().get("ps-t6").map(|s| s.as_str()), Some("ps-t7"));
    assert_eq!(rule.closures.get(&0).unwrap().get("ps-t7").map(|s| s.as_str()), Some("ps-t8"));
    assert_eq!(rule.closures.get(&0).unwrap().get("ps-t9").map(|s| s.as_str()), Some("ps-t10"));
    assert_eq!(rule.valid_epochs.get("ps-t6"), Some(&vec![0]));
    assert_eq!(rule.valid_epochs.get("ps-t7"), Some(&vec![0, 1]));
    assert_eq!(rule.valid_epochs.get("ps-t8"), Some(&vec![1]));
    assert_eq!(rule.valid_epochs.get("ps-t9"), Some(&vec![0]));
    assert_eq!(rule.valid_epochs.get("ps-t10"), Some(&vec![1]));
    assert_eq!(rule.hashes, vec!["14d6362b", "d83b3034", "91cff509"]);
    (char_cfg, rule)
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("wmf_slot_fix_{tag}_{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn new_session(root: &Path, policy: OverlapPolicy) -> SlotFixSession {
    SlotFixSession::new("2026-01-01 00-00-00", policy, root.to_path_buf())
}

fn apply(
    doc: &mut IniCstDocument,
    rule: &CompiledSlotRule,
    config: &CharacterConfig,
    ini_path: &Path,
    co_mutated: &HashSet<String>,
    session: &SlotFixSession,
) -> slot_fix::SlotFixOutcome {
    slot_fix::apply_to_document(doc, rule, config, co_mutated, ini_path, session)
}

/// Runs the real production pipeline (hash replace -> slot fix -> ...) over a dir.
async fn run_full_fix(dir: &Path, policy: OverlapPolicy) -> wuwa_mod_core::FixSummary {
    wuwa_mod_core::config_loader::init_config().await;
    let cfg = wuwa_mod_core::config_loader::config();
    let fixer = ModFixer::with_event_sink(
        cfg.characters_ref(),
        false,
        false,
        false,
        false,
        0,
        Arc::new(NullEventSink),
        Arc::new(AtomicBool::new(false)),
    )
    .with_slot_overlap_policy(policy);
    fixer.process_directory(dir)
}

// ── Anchor assertions ──────────────────────────────────────────────────────

/// Every `@wmf(` occurrence must live on a comment-only line.
///
/// 3DMigoto treats everything right of `=` up to the newline as the value, so a
/// trailing anchor would corrupt the resource name and paint red errors.
fn assert_no_inline_anchor(text: &str) {
    for (idx, line) in text.lines().enumerate() {
        if line.contains("@wmf(") {
            assert!(
                line.trim_start().starts_with(';'),
                "line {} is not a standalone comment but carries an anchor: {line:?}",
                idx + 1
            );
        }
    }
}

/// Returns the raw line preceding the first line whose trimmed form starts with
/// `statement_prefix`.
fn anchor_above<'a>(lines: &'a [String], statement_prefix: &str) -> &'a str {
    let idx = lines
        .iter()
        .position(|l| l.trim().starts_with(statement_prefix))
        .unwrap_or_else(|| panic!("no statement starting with '{statement_prefix}' in {lines:#?}"));
    assert!(
        idx > 0,
        "statement '{statement_prefix}' is the first line, no anchor above"
    );
    &lines[idx - 1]
}

fn assert_anchor(anchor_line: &str, orig: &str) {
    let trimmed = anchor_line.trim_start();
    assert!(
        trimmed.starts_with(';'),
        "anchor must be a standalone comment line: {anchor_line:?}"
    );
    assert!(
        trimmed.contains("@wmf(rule=hiyuki_slot_fix"),
        "anchor must carry the rule id: {anchor_line:?}"
    );
    assert!(
        trimmed.contains(&format!("orig={orig}")),
        "anchor must carry orig={orig}: {anchor_line:?}"
    );
    assert!(
        trimmed.contains("sig="),
        "anchor must carry a signature: {anchor_line:?}"
    );
}

fn assert_anchor_rev(anchor_line: &str, orig: &str, rev: u32) {
    assert_anchor(anchor_line, orig);
    assert!(
        anchor_line.contains(&format!("rev={rev}")),
        "anchor must carry rev={rev}: {anchor_line:?}"
    );
}

/// The statements of the first `[TextureOverrideComponent0]` section.
fn component0_lines(doc: &IniCstDocument) -> Vec<String> {
    doc.get_section("TextureOverrideComponent0")
        .expect("component section must survive")
        .lines
        .clone()
}

// ── T1: full chain without cascade ─────────────────────────────────────────

#[tokio::test]
async fn t1_full_chain_no_cascade() {
    let (config, rule) = hiyuki().await;
    let content = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
match_first_index = 0\n\
ps-t6 = ResourceFx\n\
ps-t7 = ResourceFx\n\
ps-t9 = ResourceFx\n";
    let mut doc = IniCstDocument::parse(content);
    let session = new_session(Path::new("."), OverlapPolicy::Ask);

    let outcome = apply(
        &mut doc,
        &rule,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(outcome.modified);
    assert_eq!(outcome.shifted, 3, "all three statements must be rewritten in one pass");
    assert_eq!(outcome.pinned, 0);
    assert!(!session.has_ambiguous(), "T1 must never produce ambiguity");

    let lines = component0_lines(&doc);
    assert_anchor(anchor_above(&lines, "ps-t7 = ResourceFx"), "ps-t6");
    assert_anchor(anchor_above(&lines, "ps-t8 = ResourceFx"), "ps-t7");
    assert_anchor(anchor_above(&lines, "ps-t10 = ResourceFx"), "ps-t9");

    // No statement may skip a level (ps-t6 must never become ps-t8 directly).
    assert!(
        !lines.iter().any(|l| l.trim().starts_with("ps-t8 = ResourceFx")
            && anchor_above(&lines, "ps-t8 = ResourceFx").contains("orig=ps-t6")),
        "ps-t6 must not jump two levels"
    );
    assert_eq!(
        lines.iter().filter(|l| l.contains("ResourceFx")).count(),
        3,
        "the right-hand resources must be untouched: {lines:#?}"
    );
    assert_no_inline_anchor(&doc.to_string());
}

// ── T2: ps-t9 companion auto-disambiguates ps-t7 ───────────────────────────

#[tokio::test]
async fn t2_exclusive_source_companion() {
    let (config, rule) = hiyuki().await;
    let content = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
ps-t7 = ResourceA\n\
ps-t9 = ResourceB\n";
    let mut doc = IniCstDocument::parse(content);
    let session = new_session(Path::new("."), OverlapPolicy::Ask);

    let outcome = apply(
        &mut doc,
        &rule,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(outcome.modified);
    assert_eq!(outcome.ambiguous, 0, "ps-t9 is an exclusive source: no prompt at all");
    assert!(!session.has_ambiguous(), "T2 must never produce ambiguity");

    let lines = component0_lines(&doc);
    assert_anchor(anchor_above(&lines, "ps-t8 = ResourceA"), "ps-t7");
    assert_anchor(anchor_above(&lines, "ps-t10 = ResourceB"), "ps-t9");
    assert_no_inline_anchor(&doc.to_string());
}

// ── T3: ps-t10 companion proves it is already shifted ──────────────────────

#[tokio::test]
async fn t3_exclusive_target_companion_pins_only() {
    let (config, rule) = hiyuki().await;
    let content = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
ps-t7 = ResourceA\n\
ps-t10 = ResourceB\n";
    let mut doc = IniCstDocument::parse(content);
    let session = new_session(Path::new("."), OverlapPolicy::Ask);

    let outcome = apply(
        &mut doc,
        &rule,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(outcome.modified, "anchors must be back-filled");
    assert_eq!(outcome.ambiguous, 0, "ps-t10 is an exclusive target: no prompt at all");
    assert!(!session.has_ambiguous(), "T3 must never produce ambiguity");

    let lines = component0_lines(&doc);
    // Slots are kept verbatim; only the anchors are added.
    assert_anchor(anchor_above(&lines, "ps-t7 = ResourceA"), "ps-t7");
    assert_anchor(anchor_above(&lines, "ps-t10 = ResourceB"), "ps-t10");
    assert!(
        !lines.iter().any(|l| l.trim().starts_with("ps-t8")),
        "ps-t7 must not move"
    );
    assert_no_inline_anchor(&doc.to_string());
}

// ── T4: strict same-revision idempotence ───────────────────────────────────

#[tokio::test]
async fn t4_strict_idempotence() {
    let (config, rule) = hiyuki().await;
    let cases = [
        "[TextureOverrideComponent0]\nhash = 91cff509\nps-t6 = ResourceFx\nps-t7 = ResourceFx\nps-t9 = ResourceFx\n",
        "[TextureOverrideComponent0]\nhash = 91cff509\nps-t7 = ResourceA\nps-t9 = ResourceB\n",
        "[TextureOverrideComponent0]\nhash = 91cff509\nps-t7 = ResourceA\nps-t10 = ResourceB\n",
    ];

    for content in cases {
        let mut doc = IniCstDocument::parse(content);
        let session = new_session(Path::new("."), OverlapPolicy::Ask);
        let first = apply(
            &mut doc,
            &rule,
            &config,
            Path::new("Hiyuki.ini"),
            &HashSet::new(),
            &session,
        );
        assert!(first.modified);
        let after_first = doc.to_string();

        for round in 1..=3 {
            let mut again = IniCstDocument::parse(&after_first);
            let session = new_session(Path::new("."), OverlapPolicy::Ask);
            let outcome = apply(
                &mut again,
                &rule,
                &config,
                Path::new("Hiyuki.ini"),
                &HashSet::new(),
                &session,
            );
            assert!(!outcome.modified, "round {round} must be a no-op ({content})");
            assert_eq!(outcome.shifted, 0);
            assert_eq!(outcome.pinned, 0);
            assert_eq!(again.to_string(), after_first, "round {round} must be byte identical");
            assert_no_inline_anchor(&again.to_string());
        }
    }
}

// ── T5: cross-revision upgrade without rollback ─────────────────────────────

#[tokio::test]
async fn t5_cross_revision_upgrade() {
    let (config, rule) = hiyuki().await;
    let content = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
ps-t6 = ResourceFx\n\
ps-t7 = ResourceFx\n\
ps-t9 = ResourceFx\n";
    let mut doc = IniCstDocument::parse(content);
    let session = new_session(Path::new("."), OverlapPolicy::Ask);
    apply(
        &mut doc,
        &rule,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );

    // rev = 2: ps-t6 -> ps-t8, ps-t7 -> ps-t9, ps-t9 -> ps-t11
    let mut rev2 = rule.clone();
    rev2.latest_rev = 2;
    rev2.closures = HashMap::from([
        (
            0,
            HashMap::from([
                ("ps-t6".to_string(), "ps-t8".to_string()),
                ("ps-t7".to_string(), "ps-t9".to_string()),
                ("ps-t9".to_string(), "ps-t11".to_string()),
            ]),
        ),
        (
            1,
            HashMap::from([
                ("ps-t7".to_string(), "ps-t8".to_string()),
                ("ps-t8".to_string(), "ps-t9".to_string()),
                ("ps-t10".to_string(), "ps-t11".to_string()),
            ]),
        ),
        (2, HashMap::new()),
    ]);
    rev2.valid_epochs = HashMap::from([
        ("ps-t6".to_string(), vec![0]),
        ("ps-t7".to_string(), vec![0, 1]),
        ("ps-t8".to_string(), vec![1, 2]),
        ("ps-t9".to_string(), vec![0, 2]),
        ("ps-t10".to_string(), vec![1]),
        ("ps-t11".to_string(), vec![2]),
    ]);

    let session = new_session(Path::new("."), OverlapPolicy::Ask);
    let outcome = apply(
        &mut doc,
        &rev2,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(outcome.modified);
    assert_eq!(
        outcome.upgraded, 3,
        "all three anchored statements must be recomputed from orig"
    );

    let lines = component0_lines(&doc);
    assert_anchor_rev(anchor_above(&lines, "ps-t8 = ResourceFx"), "ps-t6", 2);
    assert_anchor_rev(anchor_above(&lines, "ps-t9 = ResourceFx"), "ps-t7", 2);
    assert_anchor_rev(anchor_above(&lines, "ps-t11 = ResourceFx"), "ps-t9", 2);
    assert!(
        !lines
            .iter()
            .any(|l| l.trim().starts_with("ps-t7 =") || l.trim().starts_with("ps-t10 =")),
        "rev=1 slots must be fully replaced: {lines:#?}"
    );
    assert_no_inline_anchor(&doc.to_string());

    // The upgraded output is stable at rev = 2.
    let once = doc.to_string();
    let mut again = IniCstDocument::parse(&once);
    let session = new_session(Path::new("."), OverlapPolicy::Ask);
    let outcome = apply(
        &mut again,
        &rev2,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(!outcome.modified);
    assert_eq!(again.to_string(), once);
}

// ── T6: user edit protection ───────────────────────────────────────────────

#[tokio::test]
async fn t6_dirty_signature_protection() {
    let (config, rule) = hiyuki().await;
    let content = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
ps-t6 = ResourceFx\n\
ps-t7 = ResourceFx\n\
ps-t9 = ResourceFx\n";
    let mut doc = IniCstDocument::parse(content);
    let session = new_session(Path::new("."), OverlapPolicy::Ask);
    apply(
        &mut doc,
        &rule,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );

    // The user hand-edits the statement but the stale anchor line stays above it.
    let edited = doc.to_string().replace("ps-t7 = ResourceFx", "ps-t4 = ResourceFx");
    let mut doc = IniCstDocument::parse(&edited);

    let session = new_session(Path::new("."), OverlapPolicy::Ask);
    let outcome = apply(
        &mut doc,
        &rule,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(
        !outcome.modified,
        "a stale anchor must never be trusted to overwrite user edits"
    );
    assert!(!session.has_ambiguous());

    let lines = component0_lines(&doc);
    assert!(
        lines.iter().any(|l| l.trim() == "ps-t4 = ResourceFx"),
        "the user's slot must survive: {lines:#?}"
    );
    assert!(
        !lines.iter().any(|l| l.trim().starts_with("ps-t7 = ResourceFx")),
        "the engine must not resurrect orig=ps-t6 over the user's ps-t4: {lines:#?}"
    );
    assert_no_inline_anchor(&doc.to_string());
}

// ── T7: unmarked lone ps-t7 is intercepted ─────────────────────────────────

#[tokio::test]
async fn t7_unmarked_lone_overlap_is_ambiguous() {
    let dir = temp_dir("t7");
    let ini_path = dir.join("Hiyuki.ini");
    let content = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
match_first_index = 0\n\
match_index_count = 100\n\
ps-t7 = ResourceFx\n\n\
[ResourceFx]\n\
filename = Textures/Fx.dds\n";
    std::fs::write(&ini_path, content).unwrap();

    let summary = run_full_fix(&dir, OverlapPolicy::Ask).await;
    assert_eq!(summary.success_count, 0, "phase 1 must not touch an ambiguous file");
    assert_eq!(summary.ambiguous_items.len(), 1, "exactly one ambiguous component");
    assert_eq!(
        std::fs::read_to_string(&ini_path).unwrap(),
        content,
        "file must stay pristine"
    );

    let item = &summary.ambiguous_items[0];
    assert_eq!(item.character, "Hiyuki");
    assert_eq!(item.section_name, "TextureOverrideComponent0");
    assert_eq!(item.affected_lines.len(), 1);
    assert_eq!(item.affected_lines[0].current_slot, "ps-t7");
    assert_eq!(item.affected_lines[0].if_shifted_slot, "ps-t8");
    assert_eq!(item.affected_lines[0].if_kept_orig_slot, "ps-t6");
    assert_eq!(item.item_id.len(), 8);
    assert!(summary.session_ts.is_some());

    let _ = std::fs::remove_dir_all(&dir);
}

// ── T8: same-component co-mutation + backup lineage ────────────────────────

#[tokio::test]
async fn t8a_co_mutated_component_shifts() {
    let (config, rule) = hiyuki().await;
    let dir = temp_dir("t8a");
    let ini_path = dir.join("Hiyuki.ini");
    let content = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
ps-t7 = ResourceFx\n";
    let mut doc = IniCstDocument::parse(content);
    let session = new_session(&dir, OverlapPolicy::Ask);

    // Simulates pipeline Step 1 having just rewritten this component's vb0 hash.
    let co_mutated: HashSet<String> = ["TextureOverrideComponent0".to_string()].into_iter().collect();
    let outcome = apply(&mut doc, &rule, &config, &ini_path, &co_mutated, &session);
    assert!(outcome.modified);
    assert_eq!(outcome.ambiguous, 0, "Level 2 short-circuit must settle it");
    assert!(!session.has_ambiguous());

    let lines = component0_lines(&doc);
    assert_anchor(anchor_above(&lines, "ps-t8 = ResourceFx"), "ps-t7");
    assert_no_inline_anchor(&doc.to_string());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn t8b_backup_lineage_keeps_and_pins() {
    let (config, rule) = hiyuki().await;
    let dir = temp_dir("t8b");
    let ini_path = dir.join("Hiyuki.ini");
    // Current file: already shifted (ps-t7 came from ps-t6), nothing else written.
    let current = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
ps-t7 = ResourceFx\n";
    std::fs::write(&ini_path, current).unwrap();
    // Earliest backup still holds the pristine, un-shifted statement.
    let backup = dir.join("Hiyuki.ini_2026-01-01 00-00-00.BAK");
    std::fs::write(
        &backup,
        "[TextureOverrideComponent0]\nhash = 14d6362b\nps-t6 = ResourceFx\n",
    )
    .unwrap();

    let mut doc = IniCstDocument::parse(current);
    let session = new_session(&dir, OverlapPolicy::Ask);
    let outcome = apply(&mut doc, &rule, &config, &ini_path, &HashSet::new(), &session);
    assert!(outcome.modified, "the anchor must be back-filled");
    assert_eq!(outcome.ambiguous, 0, "Level 4 backup lineage must settle it");
    assert!(!session.has_ambiguous());

    let lines = component0_lines(&doc);
    assert_anchor(anchor_above(&lines, "ps-t7 = ResourceFx"), "ps-t7");
    assert!(
        !lines.iter().any(|l| l.trim().starts_with("ps-t8")),
        "the slot must not move"
    );

    // The complementary lineage: the backup keeps ps-t7 and still has the old vb0
    // hash, which proves the file was never shifted.
    let current2 = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
ps-t7 = ResourceFx\n";
    std::fs::write(&ini_path, current2).unwrap();
    std::fs::write(
        &backup,
        "[TextureOverrideComponent0]\nhash = 14d6362b\nps-t7 = ResourceFx\n",
    )
    .unwrap();
    let mut doc = IniCstDocument::parse(current2);
    let session = new_session(&dir, OverlapPolicy::Ask);
    let outcome = apply(&mut doc, &rule, &config, &ini_path, &HashSet::new(), &session);
    assert!(outcome.modified);
    assert_eq!(outcome.ambiguous, 0);
    let lines = component0_lines(&doc);
    assert_anchor(anchor_above(&lines, "ps-t8 = ResourceFx"), "ps-t7");

    let _ = std::fs::remove_dir_all(&dir);
}

// ── T9: phase 2 fixation + shared-timestamp rollback ───────────────────────

#[tokio::test]
async fn t9_phase2_fixation_and_shared_rollback() {
    let dir = temp_dir("t9");
    let ini_path = dir.join("Hiyuki.ini");

    let original = "[TextureOverrideComponent0]\n\
hash = 14d6362b\n\
match_first_index = 0\n\
match_index_count = 100\n\
ps-t6 = ResourceFx\n\n\
[TextureOverrideComponent1]\n\
hash = 91cff509\n\
match_first_index = 200\n\
match_index_count = 100\n\
ps-t7 = ResourceMask\n\n\
[ResourceFx]\n\
filename = Textures/Fx.dds\n\n\
[ResourceMask]\n\
filename = Textures/Mask.dds\n";
    std::fs::write(&ini_path, original).unwrap();

    // ── Phase 1 ────────────────────────────────────────────────────────────
    let summary = run_full_fix(&dir, OverlapPolicy::Ask).await;
    assert_eq!(
        summary.success_count, 1,
        "phase 1 must rewrite the deterministic component"
    );
    assert_eq!(
        summary.ambiguous_items.len(),
        1,
        "component 1 is the genuinely ambiguous one"
    );
    let session_ts = summary
        .session_ts
        .clone()
        .expect("phase 1 must report its session timestamp");

    let phase1_text = std::fs::read_to_string(&ini_path).unwrap();
    assert_anchor(
        anchor_above(
            &phase1_text.lines().map(|s| s.to_string()).collect::<Vec<_>>(),
            "ps-t7 = ResourceFx",
        ),
        "ps-t6",
    );
    assert!(
        phase1_text.contains("ps-t7 = ResourceMask"),
        "the ambiguous slot must be untouched"
    );
    assert!(
        anchor_above(
            &phase1_text.lines().map(|s| s.to_string()).collect::<Vec<_>>(),
            "ps-t7 = ResourceMask"
        )
        .trim()
        .is_empty()
            || !anchor_above(
                &phase1_text.lines().map(|s| s.to_string()).collect::<Vec<_>>(),
                "ps-t7 = ResourceMask"
            )
            .contains("@wmf("),
        "phase 1 must not anchor the ambiguous statement"
    );
    assert_no_inline_anchor(&phase1_text);

    // ── Phase 2 ────────────────────────────────────────────────────────────
    let (config, rule) = hiyuki().await;
    let item: AmbiguousSlotItem = summary.ambiguous_items[0].clone();
    let changed = slot_fix::resolve_ambiguous_item(&item, &rule, &config, OverlapDecision::KeepAndPin, &session_ts)
        .expect("phase 2 must succeed");
    assert!(changed);

    let phase2_text = std::fs::read_to_string(&ini_path).unwrap();
    let phase2_lines: Vec<String> = phase2_text.lines().map(|s| s.to_string()).collect();
    assert_anchor(anchor_above(&phase2_lines, "ps-t7 = ResourceMask"), "ps-t7");
    assert!(
        !phase2_text.contains("ps-t8 = ResourceMask"),
        "KeepAndPin must not shift the slot"
    );
    assert_no_inline_anchor(&phase2_text);

    // ── A follow-up run is fully idempotent and asks nothing ───────────────
    let second = run_full_fix(&dir, OverlapPolicy::Ask).await;
    assert_eq!(second.success_count, 0, "the second run must be a no-op");
    assert!(second.ambiguous_items.is_empty(), "no ambiguity may resurface");
    assert_eq!(std::fs::read_to_string(&ini_path).unwrap(), phase2_text);

    // ── One rollback reverts phase 1 *and* phase 2 ─────────────────────────
    wuwa_mod_core::rollback::execute_rollback(&dir, &session_ts).expect("rollback must succeed");
    assert_eq!(
        std::fs::read_to_string(&ini_path).unwrap(),
        original,
        "a single rollback must restore the pristine bare file"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ── Shared sub-section isolation + Shift decision ──────────────────────────

#[tokio::test]
async fn shared_texture_binding_subsection_is_cloned() {
    let (config, rule) = hiyuki().await;
    let content = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
run = CommandListSetTextures\n\n\
[TextureOverrideComponent1]\n\
hash = 7e400733\n\
run = CommandListSetTextures\n\n\
[CommandListSetTextures]\n\
ps-t6 = ResourceFx\n";
    let mut doc = IniCstDocument::parse(content);
    let session = new_session(Path::new("."), OverlapPolicy::Ask);
    let outcome = apply(
        &mut doc,
        &rule,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(outcome.modified);

    // The shared command list was cloned for Hiyuki only.
    assert!(doc.has_section("CommandListSetTextures_hiyuki_slot_fix"));
    let hiyuki_root = doc.get_section("TextureOverrideComponent0").unwrap();
    assert!(
        hiyuki_root
            .lines
            .iter()
            .any(|l| l.contains("CommandListSetTextures_hiyuki_slot_fix")),
        "the Hiyuki root must be repointed to its clone"
    );
    // The other character's component keeps pointing at the untouched original.
    let foreign_root = doc.get_section("TextureOverrideComponent1").unwrap();
    assert!(
        foreign_root
            .lines
            .iter()
            .any(|l| l.trim() == "run = CommandListSetTextures"),
        "foreign components must not be repointed"
    );
    // And the original shared section is untouched (still ps-t6).
    let shared = doc.get_section("CommandListSetTextures").unwrap();
    assert!(
        shared.lines.iter().any(|l| l.contains("ps-t6")),
        "the shared section must not be rewritten: {:?}",
        shared.lines
    );
    let clone = doc.get_section("CommandListSetTextures_hiyuki_slot_fix").unwrap();
    let clone_lines = clone.lines.clone();
    assert_anchor(anchor_above(&clone_lines, "ps-t7 = ResourceFx"), "ps-t6");
    assert_no_inline_anchor(&doc.to_string());

    // Idempotent on the cloned layout too.
    let once = doc.to_string();
    let mut again = IniCstDocument::parse(&once);
    let session = new_session(Path::new("."), OverlapPolicy::Ask);
    let outcome = apply(
        &mut again,
        &rule,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(!outcome.modified, "cloned layout must be idempotent");
    assert_eq!(again.to_string(), once);
}

// ── Override-trigger bookkeeping is never touched ──────────────────────────

#[tokio::test]
async fn override_trigger_lists_are_never_touched() {
    let (config, rule) = hiyuki().await;
    let content = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
run = CommandListTriggerResourceOverrides\n\
ps-t6 = ResourceFx\n\n\
[TextureOverrideComponent1]\n\
hash = 7e400733\n\
run = CommandListTriggerResourceOverrides\n\n\
[CommandListTriggerResourceOverrides]\n\
checktextureoverride = ps-t6\n\
checktextureoverride = ps-t9\n";
    let mut doc = IniCstDocument::parse(content);
    let session = new_session(Path::new("."), OverlapPolicy::Ask);
    let outcome = apply(
        &mut doc,
        &rule,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(outcome.modified, "the real binding must still be shifted");

    // The override trigger list is neither cloned nor rewritten.
    assert!(
        !doc.has_section("CommandListTriggerResourceOverrides_hiyuki_slot_fix"),
        "an override-trigger list must never be cloned"
    );
    let trigger = doc.get_section("CommandListTriggerResourceOverrides").unwrap();
    let trigger_lines: Vec<String> = trigger.lines.clone();
    assert!(
        trigger_lines.iter().any(|l| l.trim() == "checktextureoverride = ps-t6"),
        "checktextureoverride must stay on ps-t6: {trigger_lines:#?}"
    );
    assert!(
        trigger_lines.iter().any(|l| l.trim() == "checktextureoverride = ps-t9"),
        "checktextureoverride must stay on ps-t9: {trigger_lines:#?}"
    );
    assert!(
        !trigger_lines.iter().any(|l| l.contains("@wmf(")),
        "our anchors must not be injected into an override-trigger list"
    );

    // Both roots still point at the single untouched shared list.
    let hiyuki_root = doc.get_section("TextureOverrideComponent0").unwrap();
    assert!(
        hiyuki_root
            .lines
            .iter()
            .any(|l| l.trim() == "run = CommandListTriggerResourceOverrides"),
        "the root must not be repointed: {:?}",
        hiyuki_root.lines
    );

    // The real binding in the root was shifted and anchored on its own line.
    let root_lines = component0_lines(&doc);
    assert_anchor(anchor_above(&root_lines, "ps-t7 = ResourceFx"), "ps-t6");
    assert_no_inline_anchor(&doc.to_string());
}

// ── Anchor indentation mirroring + policy coverage ─────────────────────────

#[tokio::test]
async fn anchors_mirror_statement_indentation() {
    let (config, rule) = hiyuki().await;
    let content = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
    if $object_detected\n\
        ps-t6 = ResourceFx\n\
        post ps-t9 = null\n\
    endif\n";
    let mut doc = IniCstDocument::parse(content);
    let session = new_session(Path::new("."), OverlapPolicy::Ask);
    let outcome = apply(
        &mut doc,
        &rule,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(outcome.modified);
    assert_eq!(outcome.shifted, 2);

    let lines = component0_lines(&doc);
    for stmt in ["ps-t7 = ResourceFx", "post ps-t10 = null"] {
        let anchor = anchor_above(&lines, stmt);
        let statement = lines
            .iter()
            .find(|l| l.trim().starts_with(stmt))
            .expect("statement must exist");
        let statement_indent = &statement[..statement.len() - statement.trim_start().len()];
        let anchor_indent = &anchor[..anchor.len() - anchor.trim_start().len()];
        assert_eq!(
            anchor_indent, statement_indent,
            "anchor indentation must mirror the statement ({stmt}): {anchor:?} vs {statement:?}"
        );
    }
    assert_no_inline_anchor(&doc.to_string());
}

#[tokio::test]
async fn shift_and_skip_policies_never_prompt() {
    let (config, rule) = hiyuki().await;
    let content = "[TextureOverrideComponent0]\nhash = 91cff509\nps-t7 = ResourceFx\n";

    let mut doc = IniCstDocument::parse(content);
    let session = new_session(Path::new("."), OverlapPolicy::ShiftAll);
    let outcome = apply(
        &mut doc,
        &rule,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(outcome.modified);
    assert_eq!(outcome.ambiguous, 0);
    let lines = component0_lines(&doc);
    assert_anchor(anchor_above(&lines, "ps-t8 = ResourceFx"), "ps-t7");

    // SkipAll leaves the statement completely untouched.
    let mut doc = IniCstDocument::parse(content);
    let session = new_session(Path::new("."), OverlapPolicy::SkipAll);
    let outcome = apply(
        &mut doc,
        &rule,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(!outcome.modified);
    assert!(!session.has_ambiguous());
    assert!(!doc.to_string().contains("@wmf"));
}

// ── Multi-Epoch Migration Chain (Rev >= 2) Tests ───────────────────────────

fn hiyuki_rev2(base_rule: &CompiledSlotRule) -> CompiledSlotRule {
    let mut rev2 = base_rule.clone();
    rev2.latest_rev = 2;
    rev2.closures = HashMap::from([
        (
            0,
            HashMap::from([
                ("ps-t6".to_string(), "ps-t7".to_string()),
                ("ps-t7".to_string(), "ps-t9".to_string()),
                ("ps-t9".to_string(), "ps-t10".to_string()),
            ]),
        ),
        (
            1,
            HashMap::from([
                ("ps-t8".to_string(), "ps-t9".to_string()),
            ]),
        ),
        (2, HashMap::new()),
    ]);
    rev2.valid_epochs = HashMap::from([
        ("ps-t6".to_string(), vec![0]),
        ("ps-t7".to_string(), vec![0, 1, 2]),
        ("ps-t8".to_string(), vec![1]),
        ("ps-t9".to_string(), vec![0, 2]),
        ("ps-t10".to_string(), vec![1, 2]),
    ]);
    rev2
}

fn assert_anchor_epoch(anchor_line: &str, orig: &str, rev: u32, base_rev: u32) {
    assert_anchor(anchor_line, orig);
    assert!(
        anchor_line.contains(&format!("rev={rev}")),
        "anchor must carry rev={rev}: {anchor_line:?}"
    );
    assert!(
        anchor_line.contains(&format!("base_rev={base_rev}")),
        "anchor must carry base_rev={base_rev}: {anchor_line:?}"
    );
}

#[tokio::test]
async fn multi_epoch_manual_edit_compatibility() {
    let (config, base_rule) = hiyuki().await;
    let rev2 = hiyuki_rev2(&base_rule);

    // Case A: Unmarked file with {ps-t7, ps-t8} -> intersection unique base_rev=1.
    // ps-t8 shifts to ps-t9, ps-t7 stays untouched, both write base_rev=1.
    let content_a = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
ps-t7 = ResourceA\n\
ps-t8 = ResourceB\n";
    let mut doc_a = IniCstDocument::parse(content_a);
    let session_a = new_session(Path::new("."), OverlapPolicy::Ask);
    let outcome_a = apply(
        &mut doc_a,
        &rev2,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session_a,
    );
    assert!(outcome_a.modified);
    assert_eq!(outcome_a.ambiguous, 0);
    assert_eq!(outcome_a.shifted, 1, "only ps-t8 moves");
    assert_eq!(outcome_a.pinned, 1, "ps-t7 is pinned");

    let lines_a = component0_lines(&doc_a);
    assert_anchor_epoch(anchor_above(&lines_a, "ps-t7 = ResourceA"), "ps-t7", 2, 1);
    assert_anchor_epoch(anchor_above(&lines_a, "ps-t9 = ResourceB"), "ps-t8", 2, 1);
    assert!(!lines_a.iter().any(|l| l.trim().starts_with("ps-t8 =")));

    // Case B: Unmarked file with lone ps-t8 -> intersection [1] -> base_rev=1.
    let content_b = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
ps-t8 = ResourceB\n";
    let mut doc_b = IniCstDocument::parse(content_b);
    let session_b = new_session(Path::new("."), OverlapPolicy::Ask);
    let outcome_b = apply(
        &mut doc_b,
        &rev2,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session_b,
    );
    assert!(outcome_b.modified);
    assert_eq!(outcome_b.ambiguous, 0);
    assert_eq!(outcome_b.shifted, 1);
    let lines_b = component0_lines(&doc_b);
    assert_anchor_epoch(anchor_above(&lines_b, "ps-t9 = ResourceB"), "ps-t8", 2, 1);
}

#[tokio::test]
async fn legacy_anchor_backward_compat_and_step_upgrade() {
    let (config, base_rule) = hiyuki().await;
    let rev2 = hiyuki_rev2(&base_rule);

    // Old rev=1 anchor without base_rev, orig=ps-t7.
    let stmt = "ps-t8 = ResourceFx";
    let sig = wuwa_mod_core::slot_fix::compute_stmt_sig(stmt);
    let content = format!(
        "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
; @wmf(rule=hiyuki_slot_fix,rev=1,orig=ps-t7,sig={sig})\n\
{stmt}\n"
    );

    let mut doc = IniCstDocument::parse(&content);
    let session = new_session(Path::new("."), OverlapPolicy::Ask);
    let outcome = apply(
        &mut doc,
        &rev2,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(outcome.modified);
    assert_eq!(outcome.upgraded, 1);
    assert_eq!(outcome.ambiguous, 0);

    let lines = component0_lines(&doc);
    assert_anchor_epoch(anchor_above(&lines, "ps-t9 = ResourceFx"), "ps-t7", 2, 0);
    assert!(!lines.iter().any(|l| l.trim().starts_with("ps-t8 =")));
}

#[tokio::test]
async fn outcome_equivalent_skips_prompt() {
    let (config, base_rule) = hiyuki().await;
    let rev2 = hiyuki_rev2(&base_rule);

    // Lone ps-t10 under rev=2 has candidate epochs [1, 2].
    // Both epochs map ps-t10 -> ps-t10 (outcome-equivalent).
    // Automatically selects highest epoch (2) without triggering ambiguity prompt.
    let content = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
ps-t10 = ResourceFx\n";

    let mut doc = IniCstDocument::parse(content);
    let session = new_session(Path::new("."), OverlapPolicy::Ask);
    let outcome = apply(
        &mut doc,
        &rev2,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(outcome.modified, "anchor must be back-filled");
    assert_eq!(outcome.ambiguous, 0, "outcome-equivalent must not prompt");
    assert!(!session.has_ambiguous());
    assert_eq!(outcome.pinned, 1);
    assert_eq!(outcome.shifted, 0);

    let lines = component0_lines(&doc);
    assert_anchor_epoch(anchor_above(&lines, "ps-t10 = ResourceFx"), "ps-t10", 2, 2);
    assert_no_inline_anchor(&doc.to_string());
}

#[tokio::test]
async fn mixed_epoch_conflict_interception() {
    let (config, base_rule) = hiyuki().await;
    let rev2 = hiyuki_rev2(&base_rule);

    // File contains ps-t6 (epoch 0 only) and ps-t8 (epoch 1 only).
    // Intersection of valid_epochs is empty.
    let content = "[TextureOverrideComponent0]\n\
hash = 91cff509\n\
ps-t6 = ResourceA\n\
ps-t8 = ResourceB\n";

    let mut doc = IniCstDocument::parse(content);
    let session = new_session(Path::new("."), OverlapPolicy::Ask);
    let outcome = apply(
        &mut doc,
        &rev2,
        &config,
        Path::new("Hiyuki.ini"),
        &HashSet::new(),
        &session,
    );
    assert!(!outcome.modified, "mixed epoch conflict must never be blindly modified");
    assert_eq!(outcome.ambiguous, 1);
    assert!(session.has_ambiguous());

    let items = session.ambiguous_snapshot();
    assert_eq!(items.len(), 1);
    assert!(items[0].candidate_epochs.is_empty());
    assert!(items[0].conflict_reason.is_some());
    assert_eq!(doc.to_string(), content, "file must remain pristine");
}
