// src-tauri/src/main.rs
// Single-binary entry point: --cli flag → CLI mode, default → Tauri GUI

mod commands;
pub mod error;
pub mod lifecycle;
pub mod platform;
pub mod settings;

use tauri::Emitter;
use wuwa_mod_cli as cli;
use wuwa_mod_core as core;

fn main() {
    lifecycle::init_crash_handlers();

    let args = cli::parse_args();
    let is_cli = args.is_cli_mode() || std::env::args().any(|a| a == "--cli");
    let is_dev = cfg!(feature = "test-build") || cfg!(debug_assertions);

    // If on Windows and running in GUI mode, check WebView2 presence first
    #[cfg(target_os = "windows")]
    if !is_cli && !platform::is_webview2_installed() {
        lifecycle::handle_missing_webview2();
        return;
    }

    // Windows console handling:
    // - CLI mode: runs natively inside the invoking terminal.
    // - GUI mode: detach console immediately on startup.
    #[cfg(target_os = "windows")]
    if !is_cli {
        platform::detach_console();
    }

    init_logger(is_cli, is_dev);
    lifecycle::cleanup_update_files();

    if is_dev {
        log::info!("[DEV] Dev mode enabled - using local config only");
    }

    if is_cli {
        cli::run(args, is_dev);
    } else {
        run_gui_mode(is_dev);
    }
}

fn run_gui_mode(is_dev: bool) {
    // Load local config synchronously before GUI starts
    {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(core::config_loader::init_config());
    }

    if !platform::check_single_instance() {
        let raw_locale = core::localization::config::get_raw_locale();
        let title = core::localization::config::get_text_with_fallback(
            "app.instance_running_title",
            &raw_locale,
            "Application Already Running",
        );
        let message = core::localization::config::get_text_with_fallback(
            "app.instance_running_msg",
            &raw_locale,
            "Wuwa Mod Fixer is already running.",
        );
        platform::show_fatal_dialog(&title, &message);
        return;
    }

    let flag_path = lifecycle::get_gui_flag_path();
    if flag_path.exists() {
        let locale = core::localization::config::get_raw_locale().to_lowercase();
        let (title, message) = if locale.starts_with("zh-tw")
            || locale.starts_with("zh-hk")
            || locale.starts_with("zh-hant")
        {
            (
                "啟動診斷",
                "檢測到上一次界面未能成功加載。\n這通常是由於您的系統缺少 WebView2 執行階段或其損壞导致的。\n\n您是否要改用命令列 (CLI) 交互模式啟動？",
            )
        } else if locale.starts_with("zh") {
            (
                "启动诊断",
                "检测到上一次界面未能成功加载。\n这通常是由于您的系统缺少 WebView2 运行环境或其损坏导致的。\n\n您是否要改用命令行 (CLI) 交互模式启动？",
            )
        } else {
            (
                "Startup Diagnostic",
                "We detected that the graphical interface failed to load last time.\nThis is usually caused by a missing or damaged Microsoft WebView2 runtime.\n\nWould you like to run in command line (CLI) mode instead?",
            )
        };

        if platform::ask_yes_no(title, message) {
            let _ = std::fs::remove_file(&flag_path);
            platform::cleanup_single_instance();
            lifecycle::fallback_to_cli_silent();
            return;
        }
    } else {
        // mark startup
        let _ = std::fs::write(&flag_path, "");
    }

    log::info!("run_gui_mode: building tauri app...");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let app = tauri::Builder::default()
            .plugin(tauri_plugin_dialog::init())
            .plugin(tauri_plugin_shell::init())
            .plugin(tauri_plugin_opener::init())
            .manage(commands::fix::FixTaskState {
                cancel_flag: std::sync::Arc::new(std::sync::Mutex::new(None)),
            })
            .invoke_handler(commands::generate_handlers())
            .setup(move |app| {
                // On Linux, enable window decorations so window can be dragged and resized natively.
                #[cfg(target_os = "linux")]
                {
                    use tauri::Manager;
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.set_decorations(true);
                    }
                }

                let handle = app.handle().clone();

                // In Dev/Debug mode, start a lightweight thread to poll CONFIG_CHANGED
                // and broadcast a "config:reloaded" event to refresh the Vue UI on changes!
                let handle_dev = handle.clone();
                std::thread::spawn(move || {
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(300));
                        if core::config_loader::CONFIG_CHANGED.swap(false, std::sync::atomic::Ordering::SeqCst) {
                            let _ = handle_dev.emit("config:reloaded", ());
                            println!("[TAURI] Auto-reload signal captured! Emitted config:reloaded to Vue frontend.");
                        }
                    }
                });

                // Background: fetch remote config + check update
                if !is_dev {
                    tauri::async_runtime::spawn(async move {
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(8),
                            core::config_loader::force_reload_remote_config(),
                        )
                        .await;
                        let status = core::config_loader::check_update_status();
                        let _ = handle.emit("config:reloaded", ());
                        let _ = handle.emit("startup:done", status);
                    });
                } else {
                    let _ = handle.emit("startup:done", core::config_loader::check_update_status());
                }
                Ok(())
            })
            .build(tauri::generate_context!());

        match app {
            Ok(app) => {
                app.run(|_app_handle, event| match event {
                    tauri::RunEvent::Ready => {
                        let _ = std::fs::remove_file(lifecycle::get_gui_flag_path());
                    }
                    tauri::RunEvent::Exit => {
                        platform::cleanup_single_instance();
                    }
                    _ => {}
                });
                Ok(())
            }
            Err(e) => Err(e),
        }
    }));

    platform::cleanup_single_instance();

    match result {
        Ok(Ok(())) => {}
        Ok(Err(tauri_err)) => {
            let msg = tauri_err.to_string();
            lifecycle::fallback_to_cli(&msg);
        }
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("<unknown panic>");
            lifecycle::fallback_to_cli(msg);
        }
    }
}

// ── Logger ──────────────────────────────────────────────────────────────────

pub static GUI_LOG_TX: arc_swap::ArcSwapOption<tokio::sync::broadcast::Sender<String>> =
    arc_swap::ArcSwapOption::const_empty();

struct DualLogger {
    is_cli: bool,
}

impl log::Log for DualLogger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Debug
    }
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let msg = format!("[{}] {}", record.level(), record.args());
        if self.is_cli {
            eprintln!("{msg}");
        } else if let Some(tx) = &*GUI_LOG_TX.load() {
            let _ = tx.send(msg);
        }
    }
    fn flush(&self) {}
}

static LOGGER: std::sync::OnceLock<DualLogger> = std::sync::OnceLock::new();

fn init_logger(is_cli: bool, is_dev: bool) {
    let logger = LOGGER.get_or_init(|| DualLogger { is_cli });
    let max_level = if is_dev {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    log::set_logger(logger).map(|()| log::set_max_level(max_level)).ok();
}
