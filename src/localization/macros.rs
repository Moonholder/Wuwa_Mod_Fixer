#[macro_export]
macro_rules! t {
    ($item:ident) => {{
        use $crate::localization::config::{get_lang, get_pack};
        match get_lang() {
            "zh" => &get_pack().$item.zh,
            _ => &get_pack().$item.en,
        }
    }};

    ($item:ident, $($key:ident = $value:expr),*) => {{
        use $crate::localization::config::{get_lang, get_pack};
        let mut template = match get_lang() {
            "zh" => get_pack().$item.zh.clone(),
            _ => get_pack().$item.en.clone(),
        };
        $(template = template.replace(concat!("{", stringify!($key), "}"), &$value.to_string());)*
        template
    }};
}
