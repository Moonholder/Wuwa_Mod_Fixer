use wuwa_mod_core::settings::{UserSettings, load_settings, save_settings as core_save};

#[tauri::command]
pub fn get_settings() -> UserSettings {
    load_settings()
}

#[tauri::command]
pub fn save_settings(settings: UserSettings) {
    core_save(&settings);
}
