use serde::{Deserialize, Serialize};
use wuwa_mod_core::settings::{self as core_settings, UserSettings as CoreUserSettings};

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct AppSettings {
    #[serde(flatten)]
    pub core: CoreUserSettings,
    pub light_theme: Option<bool>,
    pub window_width: Option<f64>,
    pub window_height: Option<f64>,
    pub window_x: Option<i32>,
    pub window_y: Option<i32>,
}

impl std::ops::Deref for AppSettings {
    type Target = CoreUserSettings;
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl std::ops::DerefMut for AppSettings {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core
    }
}

pub fn load_settings() -> AppSettings {
    std::fs::read_to_string(core_settings::settings_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_settings(settings: &AppSettings) {
    if let Ok(json) = serde_json::to_string_pretty(settings) {
        let _ = std::fs::write(core_settings::settings_path(), json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_serialization_roundtrip() {
        let json_input = r#"{
            "last_folder": "D:/mods",
            "proxy_node": "ghproxy",
            "language": "zh",
            "light_theme": true,
            "window_width": 1280.0,
            "window_height": 720.0,
            "window_x": 100,
            "window_y": 200,
            "unknown_future_field": "test"
        }"#;

        let app_settings: AppSettings = serde_json::from_str(json_input).unwrap();
        assert_eq!(app_settings.last_folder.as_deref(), Some("D:/mods"));
        assert_eq!(app_settings.light_theme, Some(true));
        assert_eq!(app_settings.window_width, Some(1280.0));
        assert_eq!(app_settings.window_x, Some(100));

        let reserialized = serde_json::to_string(&app_settings).unwrap();
        assert!(reserialized.contains("\"window_width\":1280.0") || reserialized.contains("\"window_width\": 1280.0"));
        assert!(reserialized.contains("\"light_theme\":true") || reserialized.contains("\"light_theme\": true"));
        assert!(
            reserialized.contains("\"unknown_future_field\":\"test\"")
                || reserialized.contains("\"unknown_future_field\": \"test\"")
        );
    }

    #[test]
    fn test_core_settings_preserves_gui_fields() {
        let json_input = r#"{
            "last_folder": "D:/mods",
            "light_theme": true,
            "window_width": 1280.0
        }"#;

        let mut core_settings: CoreUserSettings = serde_json::from_str(json_input).unwrap();
        core_settings.last_folder = Some("D:/new_mods".to_string());

        let reserialized = serde_json::to_string(&core_settings).unwrap();
        assert!(reserialized.contains("D:/new_mods"));
        assert!(reserialized.contains("light_theme"));
        assert!(reserialized.contains("1280.0"));
    }
}
