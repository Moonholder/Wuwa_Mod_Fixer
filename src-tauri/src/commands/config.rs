use serde::Serialize;
use wuwa_mod_core as core;
use crate::error::AppError;

#[tauri::command]
pub async fn reload_remote_config() -> Result<String, AppError> {
    core::config_loader::force_reload_remote_config().await
        .map(|_| "Config updated".to_string())
        .map_err(|e| AppError::Network(e.to_string()))
}

// Emulates the original Iced "Refresh Config" feature
#[tauri::command]
pub async fn refresh_config() -> Result<ConfigMeta, AppError> {
    core::config_loader::force_reload_remote_config().await
        .map_err(|e| AppError::Network(e.to_string()))?;
    Ok(get_config_meta())
}

#[tauri::command]
pub fn get_update_status() -> core::config_loader::UpdateStatus {
    core::config_loader::check_update_status()
}

#[derive(Serialize)]
pub struct ConfigMeta {
    pub version: String,
    pub support_url_cn: String,
    pub support_url_intl: String,
    pub app_version: String,
}

#[tauri::command]
pub fn get_config_meta() -> ConfigMeta {
    let cfg = core::config_loader::config();
    let ver = cfg.version_ref();
    ConfigMeta {
        version: ver.current_version.clone(),
        support_url_cn: ver.support_url_cn.clone().unwrap_or_else(|| "https://support.jix.de5.net".into()),
        support_url_intl: ver.support_url_intl.clone().unwrap_or_else(|| "https://ko-fi.com/moonholder".into()),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// Returns the system-detected locale with region info (e.g. "zh-TW", "ja-JP", "ko-KR").
/// If the user has saved a language preference, returns that instead.
/// The frontend maps this to the closest supported locale.
#[tauri::command]
pub fn get_detected_locale() -> String {
    // If user has a saved preference, honour it
    if let Some(lang) = core::settings::load_settings().language {
        if !lang.is_empty() { return lang; }
    }
    // Return the raw OS locale (preserves region, e.g. "zh-TW")
    core::localization::config::get_raw_locale()
}

/// Returns true if the system locale indicates Chinese mainland
/// Used by the frontend to select the correct sponsor/support URL.
#[tauri::command]
pub fn is_chinese_mainland() -> bool {
    core::localization::config::is_chinese_mainland()
}

#[tauri::command]
pub fn get_intro_logs(lang: Option<String>) -> Vec<String> {
    // Use the provided lang or fallback to auto-detected
    let lang = lang.unwrap_or_else(|| core::localization::config::get_lang());
    vec![
        core::localization::config::get_text("title", &lang),
        core::localization::config::get_text("intro", &lang),
        core::localization::config::get_text("intro_note", &lang),
        core::localization::config::get_text("compatibility_note", &lang),
        core::localization::config::get_text("graphics_setting_note", &lang),
    ]
}

#[tauri::command]
pub fn get_os() -> String {
    std::env::consts::OS.to_string()
}

