use once_cell::sync::Lazy;
use serde::Deserialize;
use crate::config_loader;

static LANG_PACK: Lazy<LangPack> = Lazy::new(|| {
    serde_json::from_str(config_loader::lang()).expect("Failed to parse lang.json")
});

#[derive(Debug, Deserialize)]
pub struct LangPack {
    pub title: LangItem,
    pub intro: LangItem,
    pub intro_note: LangItem,
    pub compatibility_note: LangItem,
    pub graphics_setting_note: LangItem,
    pub graphics_quality_note: LangItem,
    pub texture_override_note: LangItem,
    pub found_old_mod: LangItem,
    pub texture_override_prompt: LangItem,
    pub match_character_prompt: LangItem,
    pub remapped_successfully: LangItem,
    pub process_file_start: LangItem,
    pub process_file_done: LangItem,
    pub backup_created: LangItem,
    pub backup_failed: LangItem,
    pub no_need_fix: LangItem,
    pub process_file_error: LangItem,
    pub process_folder_done: LangItem,
    pub input_folder_prompt: LangItem,
    pub start_processing: LangItem,
    pub all_done: LangItem,
    pub error_occurred: LangItem,
    pub error_prompt: LangItem,
}

#[derive(Debug, Deserialize)]
pub struct LangItem {
    pub zh: String,
    pub en: String,
}

pub fn get_lang() -> &'static str {
    static LANG: Lazy<String> = Lazy::new(|| {
        sys_locale::get_locale().unwrap_or_else(|| "en-US".into())
    });
    LANG.split('-').next().unwrap_or("en")
}

pub fn get_pack() -> &'static LangPack {
    &LANG_PACK
}