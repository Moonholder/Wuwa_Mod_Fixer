use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(transparent)]
pub struct LangItem {
    pub translations: HashMap<String, String>,
}

impl LangItem {
    pub fn get_translation(&self, lang: &str) -> &str {
        let norm = lang.to_ascii_lowercase();
        let is_zh = norm.starts_with("zh");
        self.translations
            .get(lang)
            .or_else(|| self.translations.get(&norm))
            .or_else(|| if is_zh { self.translations.get("zh") } else { None })
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
        if !lang.is_empty() {
            return lang;
        }
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
    get_text_with_fallback(key, lang, key)
}

/// Look up translated text for given key and language.
/// Order: 1) Dynamic configuration lang pack; 2) Built-in shared dictionary; 3) fallback string.
pub fn get_text_with_fallback(key: &str, lang: &str, fallback: &str) -> String {
    if let Some(cfg) = crate::config_loader::try_config() {
        let lang_pack = cfg.lang_ref();
        if let Some(item) = lang_pack.items.get(key) {
            let trans = item.get_translation(lang);
            if !trans.is_empty() && trans != key {
                return trans.to_string();
            }
        }
    }

    if let Some(builtin) = super::builtin::get_builtin_translation(key, lang) {
        return builtin.to_string();
    }

    fallback.to_string()
}

/// Look up text for the currently active system/user language.
pub fn get_text_for_current_lang(key: &str, fallback: &str) -> String {
    let lang = get_lang();
    get_text_with_fallback(key, &lang, fallback)
}

/// Shorthand to look up text using its key with automatic fallback to key.
pub fn text(key: &str) -> String {
    get_text_for_current_lang(key, key)
}
