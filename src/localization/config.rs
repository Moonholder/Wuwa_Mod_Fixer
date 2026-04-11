use crate::config_loader;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize, Default, Clone)]
#[serde(transparent)]
pub struct LangItem {
    pub translations: HashMap<String, String>,
}

impl LangItem {
    pub fn get_translation(&self, lang: &str) -> &str {
        self.translations
            .get(lang)
            .or_else(|| self.translations.get("en"))
            .map(|s| s.as_str())
            .unwrap_or("")
    }
}

#[derive(Deserialize, Default)]
#[serde(transparent)]
pub struct LangPack {
    pub items: HashMap<String, LangItem>,
}

impl LangPack {
    pub fn get_text<'a>(&'a self, key: &'a str, lang: &str) -> &'a str {
        self.items
            .get(key)
            .map(|item| item.get_translation(lang))
            .unwrap_or(key)
    }
}

pub fn get_lang() -> &'static str {
    static LANG: Lazy<String> = Lazy::new(|| {
        let raw = sys_locale::get_locale().unwrap_or_else(|| "en-US".into());
        // Handle both BCP-47 ("zh-CN") and POSIX ("zh_CN") formats
        raw.split(|c| c == '-' || c == '_')
            .next()
            .unwrap_or("en")
            .to_lowercase()
    });
    LANG.as_str()
}

pub fn is_chinese_mainland() -> bool {
    let raw = sys_locale::get_locale().unwrap_or_default().to_uppercase();
    // Simplified Chinese usually implies Mainland China (CN) or Singapore (SG)
    // But Afdian is specifically for CN.
    raw.contains("CN") || raw == "ZH"
}

/// Always reads from the live CONFIG_PTR so translations update
/// when the remote config is loaded after startup.
pub fn get_pack() -> &'static LangPack {
    config_loader::lang()
}

