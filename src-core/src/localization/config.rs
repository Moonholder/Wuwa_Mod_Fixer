
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Default, Clone)]
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

#[derive(Serialize, Deserialize, Default, Clone)]
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

pub fn get_lang() -> String {
    if let Some(lang) = crate::settings::load_settings().language {
        if !lang.is_empty() { return lang; }
    }
    
    let raw = sys_locale::get_locale().unwrap_or_else(|| "en-US".into());
    raw.split(|c| c == '-' || c == '_')
        .next()
        .unwrap_or("en")
        .to_lowercase()
}

pub fn is_chinese_mainland() -> bool {
    let raw = sys_locale::get_locale().unwrap_or_default().to_uppercase();
    raw.contains("CN") || raw == "ZH"
}

/// Returns the raw system locale with region info preserved (e.g. "zh-TW", "ja-JP").
/// Unlike `get_lang()` which strips the region, this is useful for frontend locale mapping.
pub fn get_raw_locale() -> String {
    sys_locale::get_locale().unwrap_or_else(|| "en-US".into())
}

pub fn get_text(key: &str, lang: &str) -> String {
    crate::config_loader::config().lang_ref().get_text(key, lang).to_string()
}
