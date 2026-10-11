// src-core/src/domain/sections/command_list.rs

use crate::domain::cst::IniCstSection;

pub struct CommandListSectionView<'a> {
    pub section: &'a mut IniCstSection,
}

impl<'a> CommandListSectionView<'a> {
    pub fn new(section: &'a mut IniCstSection) -> Self {
        Self { section }
    }

    pub fn check_texture_overrides(&self) -> Vec<String> {
        self.section.get_all_values("CheckTextureOverride")
    }

    pub fn ensure_check_texture_override(&mut self, slot_val: &str) -> bool {
        let existing = self.check_texture_overrides();
        if !existing.iter().any(|v| v.eq_ignore_ascii_case(slot_val)) {
            self.section.push_key_value_tight("CheckTextureOverride", slot_val, "");
            true
        } else {
            false
        }
    }
}
