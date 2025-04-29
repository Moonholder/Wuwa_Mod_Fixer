#[macro_export]
macro_rules! t {
    ($item:ident) => {{
        use $crate::localization::config::{get_lang, get_pack};
        get_pack().$item.get_translation(get_lang())
    }};

    ($item:ident, $($key:ident = $value:expr),*) => {{
        use $crate::localization::config::{get_lang, get_pack};
        let mut template = get_pack().$item.get_translation(get_lang()).to_string();
        $(template = template.replace(concat!("{", stringify!($key), "}"), &$value.to_string());)*
        template
    }};
}
