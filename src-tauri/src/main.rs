// src-tauri/src/main.rs
// Single-binary entry point: --cli flag → CLI mode, default → Tauri GUI

mod cli;
mod commands;
pub mod error;

use tauri::Emitter;
use wuwa_mod_core as core;
use once_cell::sync::Lazy;
use std::sync::Mutex;

fn main() {
    let args = cli::parse_args();
    let is_cli = std::env::args().any(|a| a == "--cli");
    let is_dev = std::env::args().any(|a| a == "--dev") || cfg!(debug_assertions);

    // Windows console handling:
    // - CLI mode: runs natively inside the invoking terminal (no hacks needed).
    // - GUI mode: detach console immediately on startup.
    #[cfg(target_os = "windows")]
    if !is_cli {
        detach_console();
        install_seh_handler();
    }

    init_logger(is_cli);
    init_panic_hook();
    cleanup_update_files();

    if is_dev {
        log::info!("[DEV] Dev mode enabled - using local config only");
    }

    if is_cli {
        run_cli_mode(args, is_dev);
    } else {
        run_gui_mode(is_dev);
    }
}

fn run_cli_mode(args: cli::CliArgs, is_dev: bool) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    if let Some(config_path) = &args.config {
        core::config_loader::set_config_override_path(config_path);
    }

    if args.path.is_some() && args.rollback {
        cli::run_direct_rollback(&args);
    } else {
        rt.block_on(core::config_loader::init_config());
        if args.path.is_some() {
            if !is_dev && args.online {
                let _ = rt.block_on(core::config_loader::force_reload_remote_config());
            }
            log::info!("Config: {}", core::config_loader::config().version_ref().current_version);
            cli::run_direct_fix(&args);
        } else {
            if !is_dev && cli::ask_load_remote() {
                let _ = rt.block_on(core::config_loader::force_reload_remote_config());
            }
            if !check_version_cli() { return; }
            cli::run_interactive(&rt);
        }
    }
}

fn run_gui_mode(is_dev: bool) {
    // Load local config synchronously before GUI starts
    {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(core::config_loader::init_config());
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tauri::Builder::default()
            .plugin(tauri_plugin_dialog::init())
            .plugin(tauri_plugin_shell::init())
            .plugin(tauri_plugin_opener::init())
            .invoke_handler(commands::generate_handlers())
            .setup(move |app| {
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
                        let _ = core::config_loader::force_reload_remote_config().await;
                        let status = core::config_loader::check_update_status();
                        let _ = handle.emit("config:reloaded", ());
                        let _ = handle.emit("startup:done", status);
                    });
                } else {
                    let _ = handle.emit("startup:done", core::config_loader::check_update_status());
                }
                Ok(())
            })
            .run(tauri::generate_context!())
            .expect("Tauri failed")
    }));

    if let Err(payload) = result {
        let msg = payload
            .downcast_ref::<String>().map(|s| s.as_str())
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("<unknown panic>");
        write_crash_log(&format!("PANIC: {msg}"));
        #[cfg(target_os = "windows")]
        show_fatal_dialog("Wuwa Mod Fixer - Fatal Error", &format!("Fatal error:\n{msg}\n\nSee crash_log.txt"));
    }
}

fn check_version_cli() -> bool {
    match core::config_loader::check_version() {
        Ok(msg) => { println!("{msg}"); true }
        Err(e)  => {
            eprintln!("{e}");
            println!("\nPress Enter to exit...");
            let _ = std::io::stdin().read_line(&mut String::new());
            false
        }
    }
}

// ── Logger ──────────────────────────────────────────────────────────────────


pub static GUI_LOG_TX: Lazy<Mutex<Option<tokio::sync::broadcast::Sender<String>>>> =
    Lazy::new(|| Mutex::new(None));

struct DualLogger { is_cli: bool }

impl log::Log for DualLogger {
    fn enabled(&self, m: &log::Metadata) -> bool { m.level() <= log::Level::Debug }
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) { return; }
        let msg = format!("[{}] {}", record.level(), record.args());
        eprintln!("{msg}");
        if !self.is_cli {
            if let Ok(guard) = GUI_LOG_TX.lock() {
                if let Some(ref tx) = *guard { let _ = tx.send(msg); }
            }
        }
    }
    fn flush(&self) {}
}

static LOGGER: std::sync::OnceLock<DualLogger> = std::sync::OnceLock::new();

fn init_logger(is_cli: bool) {
    let logger = LOGGER.get_or_init(|| DualLogger { is_cli });
    log::set_logger(logger)
        .map(|()| log::set_max_level(log::LevelFilter::Info))
        .ok();
}

fn init_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let msg = info.to_string();
        log::error!("{msg}");
        write_crash_log(&format!("PANIC: {msg}"));
    }));
}

// ── Windows helpers ──────────────────────────────────────────────────────────

fn write_crash_log(msg: &str) {
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let content = format!(
        "=== Wuwa Mod Fixer Crash ===\nTime: {ts}\nVersion: {}\n===\n{msg}\n",
        env!("CARGO_PKG_VERSION")
    );
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let _ = std::fs::write(dir.join("crash_log.txt"), &content);
        }
    }
}

#[cfg(target_os = "windows")]
fn detach_console() {
    use windows_sys::Win32::System::Console::FreeConsole;
    unsafe {
        FreeConsole();
    }
}

#[cfg(target_os = "windows")]
fn show_fatal_dialog(title: &str, body: &str) {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
    unsafe extern "system" {
        fn MessageBoxW(h: *mut std::ffi::c_void, text: *const u16, cap: *const u16, ty: u32) -> i32;
    }
    fn wide(s: &str) -> Vec<u16> { OsStr::new(s).encode_wide().chain([0]).collect() }
    unsafe { MessageBoxW(std::ptr::null_mut(), wide(body).as_ptr(), wide(title).as_ptr(), 0x10); }
}

#[cfg(target_os = "windows")]
fn install_seh_handler() {
    unsafe extern "system" {
        fn SetUnhandledExceptionFilter(
            h: Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> i32>
        ) -> Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> i32>;
    }
    unsafe extern "system" fn handler(_: *mut std::ffi::c_void) -> i32 {
        write_crash_log("NATIVE CRASH (SEH)");
        show_fatal_dialog("Wuwa Mod Fixer", "Native crash. See crash_log.txt");
        0
    }
    unsafe { SetUnhandledExceptionFilter(Some(handler)); }
}

fn cleanup_update_files() {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            // Clean up old exe file (moved/renamed during update)
            let old_exe = exe.with_extension("exe.old");
            if old_exe.exists() {
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    let _ = std::fs::remove_file(old_exe);
                });
            }
            // Clean up temporary update batch script
            let bat_path = exe_dir.join("_wuwa_update.bat");
            if bat_path.exists() {
                let _ = std::fs::remove_file(bat_path);
            }
        }
    }
}

