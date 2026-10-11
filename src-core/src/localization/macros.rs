#[macro_export]
macro_rules! t {
    ($item:ident) => {{
        $crate::localization::config::get_text(stringify!($item), &$crate::localization::config::get_lang())
    }};

    ($item:ident, $($key:ident = $value:expr),*) => {{
        let mut template = $crate::localization::config::get_text(stringify!($item), &$crate::localization::config::get_lang());
        $(template = template.replace(concat!("{", stringify!($key), "}"), &$value.to_string());)*
        template
    }};
}

#[macro_export]
macro_rules! tr {
    ($key:literal, $zh:expr, $en:expr $(,)?) => {{
        let lang = $crate::localization::config::get_lang();
        let fallback = if lang.starts_with("zh") { $zh } else { $en };
        $crate::localization::config::get_text_with_fallback($key, &lang, fallback)
    }};

    ($zh:expr, $en:expr $(,)?) => {{
        if $crate::localization::config::get_lang().starts_with("zh") {
            $zh
        } else {
            $en
        }
    }};
}
