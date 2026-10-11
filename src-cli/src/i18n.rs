// src-cli/src/i18n.rs
// CLI-specific localized messages (isolated from core and UI).

use sys_locale::get_locale;

pub fn is_chinese() -> bool {
    let loc = get_locale().unwrap_or_else(|| "en".to_string()).to_lowercase();
    loc.starts_with("zh")
}

pub fn tr<'a>(zh: &'a str, en: &'a str) -> &'a str {
    if is_chinese() { zh } else { en }
}
