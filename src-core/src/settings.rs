// Persistent user settings management.

use std::{collections::BTreeMap, path::PathBuf};

#[derive(serde::Serialize, serde::Deserialize, Default, Clone, Debug)]
pub struct UserSettings {
    pub last_folder: Option<String>,
    /// Proxy node for GitHub downloads: "direct"|"ghproxy"|"mirror"|"gh-ddlc"|"kgithub"
    pub proxy_node: Option<String>,
    /// UI Language: "zh", "en", etc.
    pub language: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Returns the application data root directory.
pub fn app_data_dir() -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    let base_dir = if cfg!(target_os = "windows") {
        std::env::var("LOCALAPPDATA")
            .ok()
            .or_else(|| std::env::var("APPDATA").ok())
            .map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
    } else {
        std::env::var("XDG_DATA_HOME").ok().map(PathBuf::from).or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".local").join("share"))
        })
    };

    if let Some(mut dir) = base_dir {
        dir.push("com.moonholder.wuwa-mod-fixer");
        let _ = std::fs::create_dir_all(&dir);
        dir
    } else if let Some(dir) = exe_dir {
        dir
    } else {
        PathBuf::from(".")
    }
}

pub fn settings_path() -> PathBuf {
    let current_path = app_data_dir().join("settings.json");

    // Migrate legacy settings from roaming profile if present.
    if !current_path.exists() && cfg!(target_os = "windows") {
        if let Ok(roaming) = std::env::var("APPDATA") {
            let legacy_dir = PathBuf::from(roaming).join("WuwaModFixer");
            let legacy_file = legacy_dir.join("settings.json");
            if legacy_file.exists() {
                if let Ok(content) = std::fs::read_to_string(&legacy_file) {
                    if std::fs::write(&current_path, &content).is_ok() {
                        let _ = std::fs::remove_file(&legacy_file);
                        let _ = std::fs::remove_dir(&legacy_dir);
                    }
                }
            }
        }
    }

    current_path
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
