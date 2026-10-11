// src-core/tests/stream_event_and_i18n_test.rs
// Verification of unified progress/feedback event streaming and shared i18n dictionary.

use std::sync::{Arc, Mutex, atomic::AtomicBool};

use wuwa_mod_core::{
    ModFixer,
    events::{FnEventSink, PipelineEvent, event_channel},
    localization::get_text_with_fallback,
};

#[test]
fn test_i18n_shared_dictionary_and_fallbacks() {
    // 1. Check built-in pipeline keys across multiple languages
    let zh_text = get_text_with_fallback("pipeline.all_done", "zh", "default");
    assert_eq!(zh_text, "所有文件处理完成...");

    let en_text = get_text_with_fallback("pipeline.all_done", "en", "default");
    assert_eq!(en_text, "All files processed...");

    let hant_text = get_text_with_fallback("pipeline.all_done", "zh-Hant", "default");
    assert_eq!(hant_text, "所有檔案處理完成...");

    let ja_text = get_text_with_fallback("pipeline.all_done", "ja", "default");
    assert_eq!(ja_text, "すべてのファイル処理が完了しました...");

    // 2. Check fallback for non-existent key
    let fallback_res = get_text_with_fallback("non.existent.key.xyz", "zh", "MyFallback");
    assert_eq!(fallback_res, "MyFallback");

    // 3. Test tr! macro with 3 arguments (key, zh, en)
    let tr_val = wuwa_mod_core::tr!(
        "pipeline.stage_preprocess",
        "资产预检与索引准备",
        "Asset Pre-check & Indexing"
    );
    assert!(!tr_val.is_empty());
}

#[tokio::test]
async fn test_pipeline_stream_events_lifecycle() {
    wuwa_mod_core::config_loader::init_config().await;
    let global_config = wuwa_mod_core::config_loader::config();

    // Create a temporary directory with a test mod ini
    let temp_dir = std::env::temp_dir().join(format!(
        "wwmi_event_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let ini_path = temp_dir.join("test_mod.ini");
    std::fs::write(&ini_path, "; dummy ini content\n").unwrap();

    let (sink, rx) = event_channel(128);
    let cancel_flag = Arc::new(AtomicBool::new(false));

    let fixer = ModFixer::with_event_sink(
        global_config.characters_ref(),
        false,
        false,
        false,
        false,
        0,
        sink,
        cancel_flag,
    );

    let summary = fixer.process_directory(&temp_dir);

    // Collect all emitted events from channel
    let mut received_events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        received_events.push(ev);
    }

    assert!(summary.total_files >= 1);
    assert_eq!(summary.skipped_count, 1);
    assert_eq!(summary.failure_count, 0);

    // Verify event sequence: Start -> FileStart -> FileSkipped -> Progress -> Finish
    let has_start = received_events
        .iter()
        .any(|e| matches!(e, PipelineEvent::Start { total, .. } if *total == 1));
    let has_file_start = received_events
        .iter()
        .any(|e| matches!(e, PipelineEvent::FileStart { .. }));
    let has_file_skipped = received_events
        .iter()
        .any(|e| matches!(e, PipelineEvent::FileSkipped { .. }));
    let has_progress = received_events.iter().any(|e| {
        matches!(
            e,
            PipelineEvent::Progress {
                current: 1,
                total: 1,
                ..
            }
        )
    });
    let has_finish = received_events
        .iter()
        .any(|e| matches!(e, PipelineEvent::Finish { success: true, .. }));

    assert!(has_start, "Pipeline must emit Start event");
    assert!(has_file_start, "Pipeline must emit FileStart event");
    assert!(has_file_skipped, "Pipeline must emit FileSkipped for empty mod");
    assert!(has_progress, "Pipeline must emit Progress event");
    assert!(has_finish, "Pipeline must emit Finish event");

    // Clean up temporary directory
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_pipeline_stream_events_cancelled() {
    wuwa_mod_core::config_loader::init_config().await;
    let global_config = wuwa_mod_core::config_loader::config();

    let temp_dir = std::env::temp_dir().join(format!(
        "wwmi_event_cancel_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("cancel_mod.ini"), "; cancel test\n").unwrap();

    let events: Arc<Mutex<Vec<PipelineEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let events_clone = events.clone();

    let sink = Arc::new(FnEventSink(move |ev: PipelineEvent| {
        events_clone.lock().unwrap().push(ev);
    }));

    let cancel_flag = Arc::new(AtomicBool::new(true)); // Pre-cancelled

    let fixer = ModFixer::with_event_sink(
        global_config.characters_ref(),
        false,
        false,
        false,
        false,
        0,
        sink,
        cancel_flag,
    );

    let summary = fixer.process_directory(&temp_dir);

    let list = events.lock().unwrap().clone();
    let has_cancelled = list.iter().any(|e| matches!(e, PipelineEvent::TaskCancelled { .. }));
    let has_finish = list
        .iter()
        .any(|e| matches!(e, PipelineEvent::Finish { success: false, .. }));

    assert!(
        has_cancelled,
        "Pipeline must emit TaskCancelled event when cancel_flag is true"
    );
    assert!(
        has_finish,
        "Pipeline must emit Finish with success=false when cancelled"
    );
    assert_eq!(summary.success_count, 0);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_pipeline_concurrent_stream_monotonicity() {
    wuwa_mod_core::config_loader::init_config().await;
    let global_config = wuwa_mod_core::config_loader::config();

    let temp_dir = std::env::temp_dir().join(format!(
        "wwmi_concurrent_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    // Create 12 ini files to trigger concurrent Rayon parallel execution
    let total_files = 12;
    for i in 0..total_files {
        let file_path = temp_dir.join(format!("test_mod_{}.ini", i));
        std::fs::write(&file_path, format!("; mod content index {}\n", i)).unwrap();
    }

    let progress_history: Arc<Mutex<Vec<(usize, f64)>>> = Arc::new(Mutex::new(Vec::new()));
    let progress_history_clone = progress_history.clone();

    let sink = Arc::new(FnEventSink(move |ev: PipelineEvent| {
        if let PipelineEvent::Progress { current, percent, .. } = ev {
            progress_history_clone.lock().unwrap().push((current, percent));
        }
    }));

    let cancel_flag = Arc::new(AtomicBool::new(false));
    let fixer = ModFixer::with_event_sink(
        global_config.characters_ref(),
        false,
        false,
        false,
        false,
        0,
        sink,
        cancel_flag,
    );

    let summary = fixer.process_directory(&temp_dir);
    assert_eq!(summary.total_files, total_files);

    let list = progress_history.lock().unwrap().clone();
    assert!(!list.is_empty(), "Progress events must be emitted");

    // Critical assertion: verify strictly non-decreasing progress (no back-jumping)
    let mut last_curr = 0;
    let mut last_pct = 0.0;
    for (curr, pct) in list {
        assert!(
            curr >= last_curr,
            "Progress current must be monotonic! Found curr: {} after last: {}",
            curr,
            last_curr
        );
        assert!(
            pct >= last_pct,
            "Progress percent must be monotonic! Found pct: {} after last: {}",
            pct,
            last_pct
        );
        last_curr = curr;
        last_pct = pct;
    }
    assert_eq!(last_curr, total_files, "Final progress current must reach total files");
    assert_eq!(last_pct, 100.0, "Final progress percent must reach 100.0%");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_pipeline_stream_events_character_reporting() {
    wuwa_mod_core::config_loader::init_config().await;
    let global_config = wuwa_mod_core::config_loader::config();

    let temp_dir = std::env::temp_dir().join(format!(
        "wwmi_char_report_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    // Find an old hash from RoverFemale config
    let rover_cfg = global_config
        .characters_ref()
        .get("RoverFemale")
        .expect("RoverFemale config must exist");
    let old_vb0 = &rover_cfg.main_hashes[0].old[0];

    // Create an ini file containing the old hash in a component section
    let ini_content = format!(
        "[TextureOverrideComponent0]\nhash = {}\nps-t0 = ResourceDiffuse\n",
        old_vb0
    );
    let ini_path = temp_dir.join("rover_test.ini");
    std::fs::write(&ini_path, ini_content).unwrap();

    let success_events: Arc<Mutex<Vec<PipelineEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let success_events_clone = success_events.clone();

    let sink = Arc::new(FnEventSink(move |ev: PipelineEvent| {
        if matches!(ev, PipelineEvent::FileSuccess { .. }) {
            success_events_clone.lock().unwrap().push(ev);
        }
    }));

    let cancel_flag = Arc::new(AtomicBool::new(false));
    let fixer = ModFixer::with_event_sink(
        global_config.characters_ref(),
        false,
        false,
        false,
        false,
        0,
        sink,
        cancel_flag,
    );

    let summary = fixer.process_directory(&temp_dir);
    assert_eq!(summary.success_count, 1);

    let evs = success_events.lock().unwrap().clone();
    assert_eq!(evs.len(), 1);
    if let PipelineEvent::FileSuccess { character, .. } = &evs[0] {
        assert!(
            character.is_some(),
            "FileSuccess must contain identified character name"
        );
        let char_name = character.as_ref().unwrap();
        assert!(
            char_name.contains("RoverFemale"),
            "Character must match RoverFemale, got: {}",
            char_name
        );
    } else {
        panic!("Expected FileSuccess event");
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}
