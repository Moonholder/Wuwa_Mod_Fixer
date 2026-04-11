#[macro_export]
macro_rules! t {
    ($item:ident) => {{
        $crate::localization::config::get_pack()
            .get_text(stringify!($item), $crate::localization::config::get_lang())
    }};

    ($item:ident, $($key:ident = $value:expr),*) => {{
        let mut template = $crate::localization::config::get_pack()
            .get_text(stringify!($item), $crate::localization::config::get_lang())
            .to_string();
        $(template = template.replace(concat!("{", stringify!($key), "}"), &$value.to_string());)*
        template
    }};
}

#[macro_export]
macro_rules! tr {
    ($zh:expr, $en:expr $(,)?) => {{
        if $crate::localization::config::get_lang() == "zh" {
            $zh
        } else {
            $en
        }
    }};
}
