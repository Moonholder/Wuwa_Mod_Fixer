use std::{sync::atomic::Ordering, time::Duration};

use wuwa_mod_core::config_loader::{CONFIG_CHANGED, config, init_config};

#[tokio::test]
async fn test_config_yml_hot_reload() {
    // 1. Initialize configuration (starts the dev watcher thread)
    init_config().await;

    let cfg = config();
    assert!(!cfg.version_ref().current_version.is_empty());

    // Clear any pending flag
    CONFIG_CHANGED.store(false, Ordering::SeqCst);

    // 2. Locate config.yml in workspace
    let mut dir = std::env::current_dir().unwrap();
    let mut yml_path = None;
    loop {
        let p = dir.join("config.yml");
        if p.exists() {
            yml_path = Some(p);
            break;
        }
        if !dir.pop() {
            break;
        }
    }
    let yml_path = yml_path.expect("config.yml must exist in workspace root");

    // 3. Touch config.yml by appending a newline and stripping it back
    let content = std::fs::read_to_string(&yml_path).expect("read config.yml");
    std::thread::sleep(Duration::from_millis(50));
    std::fs::write(&yml_path, format!("{content}\n")).expect("touch config.yml");

    // 4. Wait for watcher to detect change, run compile_config.js, and trigger CONFIG_CHANGED
    let mut detected = false;
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(200));
        if CONFIG_CHANGED.load(Ordering::SeqCst) {
            detected = true;
            break;
        }
    }

    // Restore original content
    let _ = std::fs::write(&yml_path, content);

    assert!(
        detected,
        "Config watcher should detect config.yml modification and set CONFIG_CHANGED to true"
    );
}
