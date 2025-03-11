use crate::config_loader;
use config_loader::LangPack;
use once_cell::sync::Lazy;

static LANG_PACK: Lazy<&LangPack> = Lazy::new(|| config_loader::lang());

pub fn get_lang() -> &'static str {
    static LANG: Lazy<String> =
        Lazy::new(|| sys_locale::get_locale().unwrap_or_else(|| "en-US".into()));
    LANG.split('-').next().unwrap_or("en")
}

pub fn get_pack() -> &'static LangPack {
    &LANG_PACK
}
