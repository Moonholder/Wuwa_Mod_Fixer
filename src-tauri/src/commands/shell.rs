use tauri::AppHandle;
use wuwa_mod_core as core;
use chrono::Local;
use std::path::PathBuf;

#[tauri::command]
pub async fn pick_folder(app: AppHandle, default_path: Option<String>) -> Option<String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = std::sync::mpsc::channel();
    let mut dialog = app.dialog().file();
    if let Some(ref p) = default_path {
        if !p.is_empty() {
            dialog = dialog.set_directory(std::path::PathBuf::from(p));
        }
    }
    dialog.pick_folder(move |f| {
        let _ = tx.send(f);
    });
    rx.recv().ok().flatten().map(|p| p.to_string())
}

#[tauri::command]
pub fn open_url(app: AppHandle, url: String) {
    use tauri_plugin_opener::OpenerExt;
    let _ = app.opener().open_url(url, None::<String>);
}

use crate::error::AppError;

// Emulates the original Iced "Export Logs" feature
#[tauri::command]
pub async fn export_logs(app: AppHandle, log_body: String, mod_path: String, options_info: String) -> Result<String, AppError> {
    let now = Local::now();
    let cfg = core::config_loader::config();
    let version = &cfg.version_ref().current_version;
    
    let header = format!(
        "WuWa Mod Fixer v{}\nConfig Version: {}\nExport Time: {}\nMod Path: {}\n\
         Options: {}\n\
         =================================\n",
        env!("CARGO_PKG_VERSION"),
        version,
        now.format("%Y-%m-%d %H:%M:%S"),
        mod_path,
        options_info,
    );
    let content = format!("{}\n{}", header, log_body);
    let filename = format!("mod_fix_log_{}.txt", now.format("%Y%m%d_%H%M%S"));

    // Try exe dir first, fallback to Desktop, then current dir
    let path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(&filename)))
        .filter(|p| {
            p.parent().map_or(false, |d| {
                let probe = d.join(".wwmi_probe");
                std::fs::write(&probe, b"").map(|_| { let _ = std::fs::remove_file(&probe); }).is_ok()
            })
        })
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .map(|home| PathBuf::from(home).join("Desktop").join(&filename))
        })
        .unwrap_or_else(|| PathBuf::from(&filename));

    std::fs::write(&path, &content).map_err(|e| AppError::Io(e.to_string()))?;
    
    // Open the folder automatically
    if let Some(dir) = path.parent() {
        use tauri_plugin_opener::OpenerExt;
        let _ = app.opener().open_path(dir.to_string_lossy().to_string(), None::<String>);
    }
    
    Ok(path.display().to_string())
}
