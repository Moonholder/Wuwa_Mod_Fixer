pub mod builtin;
pub mod config;
pub mod macros;

pub use config::{
    get_lang, get_raw_locale, get_text, get_text_for_current_lang, get_text_with_fallback, is_chinese_mainland, text,
};
