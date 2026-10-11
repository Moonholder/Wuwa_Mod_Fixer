// src-core/src/domain/sections/constants.rs

use crate::domain::cst::IniCstSection;

pub struct ConstantsSectionView<'a> {
    pub section: &'a mut IniCstSection,
}

impl<'a> ConstantsSectionView<'a> {
    pub fn new(section: &'a mut IniCstSection) -> Self {
        Self { section }
    }

    pub fn has_global(&self, name: &str) -> bool {
        let key = if name.starts_with("global ") {
            name.to_string()
        } else {
            format!("global {}", name)
        };
        self.section.has_key(&key)
    }

    pub fn set_global(&mut self, name: &str, value: &str) {
        let key = if name.starts_with("global ") {
            name.to_string()
        } else {
            format!("global {}", name)
        };
        self.section.set_key_value(&key, value, "");
    }

    pub fn prepend_global(&mut self, name: &str, value: &str) {
        let key = if name.starts_with("global ") {
            name.to_string()
        } else {
            format!("global {}", name)
        };
        self.section.prepend_key_value(&key, value, "");
    }
}
