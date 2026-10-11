// src-tauri/src/lifecycle.rs

use std::path::PathBuf;

use wuwa_mod_core as core;

use crate::platform;

pub fn get_gui_flag_path() -> PathBuf {
    core::settings::settings_path().with_file_name("gui_launching.flag")
}

pub fn write_crash_log(msg: &str) {
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

pub fn init_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let msg = info.to_string();
        log::error!("{msg}");
        write_crash_log(&format!("PANIC: {msg}"));
    }));
}

unsafe extern "system" fn seh_crash_handler(_: *mut std::ffi::c_void) -> i32 {
    write_crash_log("NATIVE CRASH (SEH)");
    platform::show_fatal_dialog("Wuwa Mod Fixer", "Native crash. See crash_log.txt");
    0
}

pub fn init_crash_handlers() {
    init_panic_hook();
    platform::install_seh_handler(seh_crash_handler);
}

pub fn cleanup_update_files() {
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

pub fn check_version_cli() -> bool {
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

pub fn fallback_to_cli_silent() {
    platform::alloc_console_and_redirect();

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    if check_version_cli() {
        wuwa_mod_cli::run_interactive(&rt);
    }
}

pub fn fallback_to_cli(reason: &str) {
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

    platform::show_fatal_dialog(&title, &message);
    fallback_to_cli_silent();
}

pub fn get_webview2_missing_text() -> (&'static str, &'static str, &'static str) {
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

pub fn handle_missing_webview2() {
    let (title, message, download_url) = get_webview2_missing_text();
    if platform::ask_yes_no(title, message) {
        // Yes: launch CLI mode
        if let Ok(current_exe) = std::env::current_exe() {
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                let _ = std::process::Command::new("cmd")
                    .args(&[
                        "/c",
                        "start",
                        "Wuwa Mod Fixer CLI",
                        current_exe.to_str().unwrap_or_default(),
                        "--cli",
                    ])
                    .creation_flags(0x08000000) // CREATE_NO_WINDOW
                    .status();
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = std::process::Command::new(current_exe).arg("--cli").status();
            }
        }
    } else {
        // No: open download page
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            let _ = std::process::Command::new("cmd")
                .args(&["/c", "start", "", download_url])
                .creation_flags(0x08000000) // CREATE_NO_WINDOW
                .status();
        }
    }
}
