use std::path::PathBuf;

#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
pub struct UserSettings {
    pub last_folder: Option<String>,
    pub light_theme: Option<bool>,
    pub window_width: Option<f32>,
    pub window_height: Option<f32>,
    pub window_x: Option<i32>,
    pub window_y: Option<i32>,
}

pub fn settings_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("settings.json")
}

pub fn load_settings() -> UserSettings {
    std::fs::read_to_string(settings_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_settings(settings: &UserSettings) {
    if let Ok(json) = serde_json::to_string_pretty(settings) {
        let _ = std::fs::write(settings_path(), json);
    }
}