// src-tauri/src/main.rs
// Single-binary entry point: --cli flag → CLI mode, default → Tauri GUI

mod cli;
mod commands;
pub mod error;

use tauri::Emitter;
use wuwa_mod_core as core;
fn main() {
    init_panic_hook();
    let args = cli::parse_args();
    let is_cli = std::env::args().any(|a| a == "--cli");
    let is_dev = std::env::args().any(|a| a == "--dev") || cfg!(debug_assertions);

    // If on Windows and running in GUI mode, check WebView2 presence first
    #[cfg(target_os = "windows")]
    if !is_cli && !is_webview2_installed() {
        let (title, message, download_url) = get_webview2_missing_text();

        unsafe extern "system" {
            fn MessageBoxW(h: *mut std::ffi::c_void, text: *const u16, cap: *const u16, ty: u32) -> i32;
        }
        use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
        let wide = |s: &str| -> Vec<u16> { OsStr::new(s).encode_wide().chain([0]).collect() };

        let result = unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                wide(message).as_ptr(),
                wide(title).as_ptr(),
                0x34, // MB_YESNO | MB_ICONWARNING
            )
        };

        if result == 6 {
            // Yes (IDYES)
            if let Ok(current_exe) = std::env::current_exe() {
                use std::os::windows::process::CommandExt;
                let _ = std::process::Command::new("cmd")
                    .args(&["/c", "start", "Wuwa Mod Fixer CLI", current_exe.to_str().unwrap(), "--cli"])
                    .creation_flags(0x08000000) // CREATE_NO_WINDOW
                    .status();
            }
        } else if result == 7 {
            // No (IDNO)
            use std::os::windows::process::CommandExt;
            let _ = std::process::Command::new("cmd")
                .args(&["/c", "start", "", download_url])
                .creation_flags(0x08000000) // CREATE_NO_WINDOW
                .status();
        }
        return;
    }

    // Windows console handling:
    // - CLI mode: runs natively inside the invoking terminal (no hacks needed).
    // - GUI mode: detach console immediately on startup.
    #[cfg(target_os = "windows")]
    if !is_cli {
        detach_console();
        install_seh_handler();
    }

    init_logger(is_cli, is_dev);
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
            log::info!(
                "Config: {}",
                core::config_loader::config().version_ref().current_version
            );
            cli::run_direct_fix(&args);
        } else {
            if !is_dev && cli::ask_load_remote() {
                let _ = rt.block_on(core::config_loader::force_reload_remote_config());
            }
            if !check_version_cli() {
                return;
            }
            cli::run_interactive(&rt);
        }
    }
}

fn get_gui_flag_path() -> std::path::PathBuf {
    core::settings::settings_path().with_file_name("gui_launching.flag")
}

static SINGLE_INSTANCE_MUTEX: std::sync::Mutex<Option<usize>> = std::sync::Mutex::new(None);

#[cfg(target_os = "windows")]
fn check_single_instance() -> bool {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
    use windows_sys::Win32::System::Threading::CreateMutexW;

    let mutex_name: Vec<u16> = OsStr::new("Local\\WuwaModFixerSingleInstanceMutex")
        .encode_wide()
        .chain([0])
        .collect();

    unsafe {
        let handle = CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr());
        if handle.is_null() {
            return true;
        }
        let err = GetLastError();
        if err == ERROR_ALREADY_EXISTS {
            return false;
        }
        if let Ok(mut guard) = SINGLE_INSTANCE_MUTEX.lock() {
            *guard = Some(handle as usize);
        }
    }
    true
}

#[cfg(not(target_os = "windows"))]
fn check_single_instance() -> bool {
    true
}

fn cleanup_single_instance() {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        if let Ok(mut guard) = SINGLE_INSTANCE_MUTEX.lock() {
            if let Some(handle) = guard.take() {
                unsafe {
                    CloseHandle(handle as *mut std::ffi::c_void);
                }
            }
        }
    }
    let flag_path = get_gui_flag_path();
    let _ = std::fs::remove_file(flag_path);
}

fn run_gui_mode(is_dev: bool) {
    // Load local config synchronously before GUI starts
    {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(core::config_loader::init_config());
    }

    if !check_single_instance() {
        let locale = core::localization::config::get_raw_locale().to_lowercase();
        let (title, message) =
            if locale.starts_with("zh-tw") || locale.starts_with("zh-hk") || locale.starts_with("zh-hant") {
                ("程式已在運行中", "Wuwa Mod Fixer 已在運行中。")
            } else if locale.starts_with("zh") {
                ("程序已在运行中", "Wuwa Mod Fixer 已在运行中。")
            } else {
                ("Application Already Running", "Wuwa Mod Fixer is already running.")
            };
        show_fatal_dialog(title, message);
        return;
    }

    let flag_path = get_gui_flag_path();
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

        if ask_yes_no(title, message) {
            let _ = std::fs::remove_file(&flag_path);
            cleanup_single_instance();
            fallback_to_cli_silent();
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
                        let _ = std::fs::remove_file(get_gui_flag_path());
                    }
                    tauri::RunEvent::Exit => {
                        cleanup_single_instance();
                    }
                    _ => {}
                });
                Ok(())
            }
            Err(e) => Err(e),
        }
    }));

    cleanup_single_instance();

    match result {
        Ok(Ok(())) => {}
        Ok(Err(tauri_err)) => {
            let msg = tauri_err.to_string();
            fallback_to_cli(&msg);
        }
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("<unknown panic>");
            fallback_to_cli(msg);
        }
    }
}

fn check_version_cli() -> bool {
    match core::config_loader::check_version() {
        Ok(msg) => {
            println!("{msg}");
            true
        }
        Err(e) => {
            eprintln!("{e}");
            println!("\nPress Enter to exit...");
            let _ = std::io::stdin().read_line(&mut String::new());
            false
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
        eprintln!("{msg}");
        if !self.is_cli {
            if let Some(tx) = &*GUI_LOG_TX.load() {
                let _ = tx.send(msg);
            }
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
    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain([0]).collect()
    }
    unsafe {
        MessageBoxW(std::ptr::null_mut(), wide(body).as_ptr(), wide(title).as_ptr(), 0x10);
    }
}

#[cfg(not(target_os = "windows"))]
fn show_fatal_dialog(title: &str, body: &str) {
    eprintln!("[FATAL] {title}: {body}");
}

#[cfg(target_os = "windows")]
fn install_seh_handler() {
    unsafe extern "system" {
        fn SetUnhandledExceptionFilter(
            h: Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> i32>,
        ) -> Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> i32>;
    }
    unsafe extern "system" fn handler(_: *mut std::ffi::c_void) -> i32 {
        write_crash_log("NATIVE CRASH (SEH)");
        show_fatal_dialog("Wuwa Mod Fixer", "Native crash. See crash_log.txt");
        0
    }
    unsafe {
        SetUnhandledExceptionFilter(Some(handler));
    }
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

#[cfg(target_os = "windows")]
fn is_webview2_installed() -> bool {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
    };

    let subkeys = [
        r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
        r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
    ];

    let wide_key = |s: &str| -> Vec<u16> { OsStr::new(s).encode_wide().chain([0]).collect() };
    let value_name = wide_key("pv");

    // Check HKEY_LOCAL_MACHINE
    for subkey in &subkeys {
        let wide_subkey = wide_key(subkey);
        let mut hkey = std::ptr::null_mut();
        let res = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide_subkey.as_ptr(), 0, KEY_READ, &mut hkey) };
        if res == ERROR_SUCCESS {
            let mut val_type = 0;
            let mut cb_data = 0;
            let val_res = unsafe {
                RegQueryValueExW(
                    hkey,
                    value_name.as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    std::ptr::null_mut(),
                    &mut cb_data,
                )
            };
            unsafe { RegCloseKey(hkey) };
            if val_res == ERROR_SUCCESS && cb_data > 0 {
                return true;
            }
        }
    }

    // Check HKEY_CURRENT_USER
    let cu_subkey = r"Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    let wide_subkey = wide_key(cu_subkey);
    let mut hkey = std::ptr::null_mut();
    let res = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, wide_subkey.as_ptr(), 0, KEY_READ, &mut hkey) };
    if res == ERROR_SUCCESS {
        let mut val_type = 0;
        let mut cb_data = 0;
        let val_res = unsafe {
            RegQueryValueExW(
                hkey,
                value_name.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type,
                std::ptr::null_mut(),
                &mut cb_data,
            )
        };
        unsafe { RegCloseKey(hkey) };
        if val_res == ERROR_SUCCESS && cb_data > 0 {
            return true;
        }
    }

    false
}

#[cfg(target_os = "windows")]
fn get_webview2_missing_text() -> (&'static str, &'static str, &'static str) {
    let locale = core::localization::config::get_raw_locale().to_lowercase();
    if locale.starts_with("zh-tw") || locale.starts_with("zh-hk") || locale.starts_with("zh-hant") {
        (
            "缺少 WebView2 執行階段",
            "本程式需要安裝 Microsoft WebView2 執行階段才能執行圖形介面 (GUI)。\n\n您是否要改用命令列 (CLI) 模式啟動？\n\n- 按一下 [是]：在新主控台視窗中啟動 CLI 互動模式。\n- 按一下 [否]：在瀏覽器中開啟 WebView2 下載網頁。",
            "https://developer.microsoft.com/zh-tw/microsoft-edge/webview2/",
        )
    } else if locale.starts_with("zh") {
        (
            "缺少 WebView2 运行环境",
            "本程序需要安装 Microsoft WebView2 运行环境才能启动图形界面 (GUI)。\n\n您是否要降级并改用命令行 (CLI) 模式启动？\n\n- 点击 [是]：在新控制台窗口中启动 CLI 交互模式。\n- 点击 [否]：在浏览器中打开 WebView2 下载页面。",
            "https://developer.microsoft.com/zh-cn/microsoft-edge/webview2/",
        )
    } else if locale.starts_with("ja") {
        (
            "WebView2 ランタイムが見つかりません",
            "GUI版を実行するには Microsoft WebView2 ランタイムのインストールが必要です。\n\n代わりにコマンドライン (CLI) モードで起動しますか？\n\n- [はい] をクリック：新しいコンソールウィンドウで CLI モードを開始します。\n- [いいえ] をクリック：ブラウザで WebView2 のダウンロードページを開きます。",
            "https://developer.microsoft.com/ja-jp/microsoft-edge/webview2/",
        )
    } else if locale.starts_with("ko") {
        (
            "WebView2 런타임 누락됨",
            "GUI 버전을 실행하려면 Microsoft WebView2 런타임이 설치되어 있어야 합니다.\n\n대신 명령줄(CLI) 모드로 실행하시겠습니까?\n\n- [예] 클릭: 새 콘솔 창에서 CLI 대화형 모드를 시작합니다.\n- [아니오] 클릭: 브라우저에서 WebView2 다운로드 페이지를 엽니다.",
            "https://developer.microsoft.com/ko-kr/microsoft-edge/webview2/",
        )
    } else if locale.starts_with("uk") || locale.starts_with("ua") {
        (
            "Відсутній WebView2 Runtime",
            "Для запуску графічного інтерфейсу (GUI) необхідно встановити Microsoft WebView2 Runtime.\n\nБажаєте запустити програму в режимі командного рядка (CLI)?\n\n- Натисніть [Так], щоб запустити інтерактивний CLI режим у новому вікні консолі.\n- Натисніть [Ні], щоб відкрити сторінку завантаження WebView2 у браузері.",
            "https://developer.microsoft.com/uk-ua/microsoft-edge/webview2/",
        )
    } else {
        (
            "WebView2 Runtime Missing",
            "Microsoft WebView2 Runtime is not installed, which is required to run the GUI version.\n\nWould you like to run in command line (CLI) mode instead?\n\n- Click [Yes] to launch the CLI mode in a new console window.\n- Click [No] to open the WebView2 download page in your browser.",
            "https://developer.microsoft.com/en-us/microsoft-edge/webview2/",
        )
    }
}

#[cfg(target_os = "windows")]
fn ask_yes_no(title: &str, message: &str) -> bool {
    unsafe extern "system" {
        fn MessageBoxW(h: *mut std::ffi::c_void, text: *const u16, cap: *const u16, ty: u32) -> i32;
    }
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
    let wide = |s: &str| -> Vec<u16> { OsStr::new(s).encode_wide().chain([0]).collect() };
    let result = unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide(message).as_ptr(),
            wide(title).as_ptr(),
            0x34, // MB_YESNO | MB_ICONWARNING
        )
    };
    result == 6 // IDYES
}

#[cfg(not(target_os = "windows"))]
fn ask_yes_no(title: &str, message: &str) -> bool {
    eprintln!("[{title}] {message}");
    false
}

#[cfg(target_os = "windows")]
fn alloc_console_and_redirect() {
    use windows_sys::Win32::System::Console::AllocConsole;
    unsafe {
        if AllocConsole() != 0 {
            unsafe extern "C" {
                fn freopen(path: *const u8, mode: *const u8, stream: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
                fn __acrt_iob_func(index: u32) -> *mut std::ffi::c_void;
            }

            freopen(b"CONIN$\0".as_ptr(), b"r\0".as_ptr(), __acrt_iob_func(0));
            freopen(b"CONOUT$\0".as_ptr(), b"w\0".as_ptr(), __acrt_iob_func(1));
            freopen(b"CONOUT$\0".as_ptr(), b"w\0".as_ptr(), __acrt_iob_func(2));

            use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
            use windows_sys::Win32::Storage::FileSystem::{
                CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
            };
            use windows_sys::Win32::System::Console::{
                STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
            };

            let conout_name: Vec<u16> = OsStr::new("CONOUT$").encode_wide().chain([0]).collect();
            let conin_name: Vec<u16> = OsStr::new("CONIN$").encode_wide().chain([0]).collect();

            let generic_read_write = 0x80000000 | 0x40000000;
            let h_out = CreateFileW(
                conout_name.as_ptr(),
                generic_read_write,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
            let h_in = CreateFileW(
                conin_name.as_ptr(),
                generic_read_write,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );

            SetStdHandle(STD_OUTPUT_HANDLE, h_out);
            SetStdHandle(STD_ERROR_HANDLE, h_out);
            SetStdHandle(STD_INPUT_HANDLE, h_in);
        }
    }
}

fn fallback_to_cli_silent() {
    #[cfg(target_os = "windows")]
    alloc_console_and_redirect();

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    if check_version_cli() {
        cli::run_interactive(&rt);
    }
}

fn fallback_to_cli(reason: &str) {
    write_crash_log(&format!("GUI Fallback to CLI. Reason: {reason}"));

    let locale = core::localization::config::get_raw_locale().to_lowercase();
    let (title, message) = if locale.starts_with("zh-tw")
        || locale.starts_with("zh-hk")
        || locale.starts_with("zh-hant")
    {
        (
            "圖形介面啟動失敗",
            format!(
                "圖形介面 (GUI) 啟動失敗：\n{}\n\n程式將自動降級並以命令列 (CLI) 模式啟動。\n\n詳細錯誤資訊請參閱 crash_log.txt。",
                reason
            ),
        )
    } else if locale.starts_with("zh") {
        (
            "图形界面启动失败",
            format!(
                "图形界面 (GUI) 启动失败：\n{}\n\n程序将自动降级并以命令行 (CLI) 模式启动。\n\n详细错误信息请参阅 crash_log.txt。",
                reason
            ),
        )
    } else {
        (
            "GUI Startup Failed",
            format!(
                "Graphical interface (GUI) failed to start:\n{}\n\nThe application will automatically downgrade and launch in Command Line (CLI) mode.\n\nSee crash_log.txt for details.",
                reason
            ),
        )
    };

    show_fatal_dialog(&title, &message);
    fallback_to_cli_silent();
}
