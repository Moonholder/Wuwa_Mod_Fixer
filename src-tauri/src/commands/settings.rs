use crate::settings::{AppSettings, load_settings, save_settings as tauri_save};

#[tauri::command]
pub fn get_settings() -> AppSettings {
    load_settings()
}

#[tauri::command]
pub fn save_settings(settings: AppSettings) {
    tauri_save(&settings);
}
