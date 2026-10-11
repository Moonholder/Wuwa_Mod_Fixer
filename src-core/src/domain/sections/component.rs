// src-core/src/domain/sections/component.rs

use crate::{
    domain::cst::IniCstSection,
    utils::regex_patterns::{
        RE_HANDLING_SKIP, RE_MATCH_COUNT_LINE, RE_MATCH_FIRST_LINE, RE_RUN_CMD, RE_VG_COUNT, RE_VG_OFFSET,
    },
};

pub struct ComponentSectionView<'a> {
    pub section: &'a mut IniCstSection,
    pub component_id: u32,
}

impl<'a> ComponentSectionView<'a> {
    pub fn new(section: &'a mut IniCstSection, component_id: u32) -> Self {
        Self { section, component_id }
    }

    pub fn match_first_index(&self) -> Option<String> {
        self.section.get_value("match_first_index")
    }

    pub fn match_index_count(&self) -> Option<String> {
        self.section.get_value("match_index_count")
    }

    pub fn set_match_first_index(&mut self, val: &str) {
        let mut replaced = false;
        for line in &mut self.section.lines {
            if RE_MATCH_FIRST_LINE.is_match(line) {
                let indent: String = line
                    .chars()
                    .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                    .collect();
                *line = format!("{}match_first_index = {}", indent, val);
                replaced = true;
                break;
            }
        }
        if !replaced {
            self.section.set_key_value("match_first_index", val, "");
        }
    }

    pub fn set_match_index_count(&mut self, val: &str) {
        let mut replaced = false;
        for line in &mut self.section.lines {
            if RE_MATCH_COUNT_LINE.is_match(line) {
                let indent: String = line
                    .chars()
                    .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                    .collect();
                *line = format!("{}match_index_count = {}", indent, val);
                replaced = true;
                break;
            }
        }
        if !replaced {
            self.section.set_key_value("match_index_count", val, "");
        }
    }

    pub fn set_vg_offset_and_count(&mut self, offset: u16, count: u16) {
        let mut offset_replaced = false;
        let mut count_replaced = false;

        for line in &mut self.section.lines {
            if RE_VG_OFFSET.is_match(line) {
                let indent: String = line
                    .chars()
                    .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                    .collect();
                *line = format!("{}$\\WWMIv1\\vg_offset = {}", indent, offset);
                offset_replaced = true;
            } else if RE_VG_COUNT.is_match(line) {
                let indent: String = line
                    .chars()
                    .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                    .collect();
                *line = format!("{}$\\WWMIv1\\vg_count = {}", indent, count);
                count_replaced = true;
            }
        }

        if !offset_replaced {
            self.section
                .set_key_value("$\\WWMIv1\\vg_offset", &offset.to_string(), "");
        }
        if !count_replaced {
            self.section
                .set_key_value("$\\WWMIv1\\vg_count", &count.to_string(), "");
        }
    }

    /// Injects auxiliary fx texture assignment block and command list invocation.
    pub fn inject_rabbit_fx_block(&mut self, insert_content: &str) -> bool {
        let run_cmd = "run = Commandlist\\RabbitFX\\SetTextures";

        let mut insert_idx = self.section.lines.len();
        let mut append_run = false;

        if let Some(idx) = self.section.lines.iter().position(|l| RE_RUN_CMD.is_match(l)) {
            insert_idx = idx;
        } else {
            if let Some(idx) = self.section.lines.iter().position(|l| RE_HANDLING_SKIP.is_match(l)) {
                insert_idx = idx + 1;
            }
            append_run = true;
        }

        let base_indent = if insert_idx > 0 && insert_idx <= self.section.lines.len() {
            let ref_line = &self.section.lines[insert_idx - 1];
            ref_line
                .chars()
                .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                .collect()
        } else {
            String::new()
        };

        let min_indent = insert_content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                l.chars()
                    .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                    .count()
            })
            .min()
            .unwrap_or(0);

        let mut block: Vec<String> = insert_content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let stripped = if min_indent > 0 && l.len() >= min_indent {
                    &l[min_indent..]
                } else {
                    l.trim_start()
                };
                format!("{}{}", base_indent, stripped)
            })
            .collect();

        if append_run {
            block.push(format!("{}{}", base_indent, run_cmd));
        }

        self.section.lines.splice(insert_idx..insert_idx, block);
        true
    }

    /// Ensures runtime object detection flag is declared in component section.
    pub fn ensure_object_detected_flag(&mut self) -> bool {
        if !self.section.has_key("$object_detected") {
            let mut insert_idx = self.section.lines.len();
            for (i, line) in self.section.lines.iter().enumerate() {
                if line.contains("match_index_count") || line.contains("drawindexed") {
                    insert_idx = i + 1;
                    break;
                }
            }
            let indent = if insert_idx > 0 && insert_idx <= self.section.lines.len() {
                let ref_line = &self.section.lines[insert_idx - 1];
                let ind: String = ref_line
                    .chars()
                    .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                    .collect();
                if ind.is_empty() { "    ".to_string() } else { ind }
            } else {
                "    ".to_string()
            };
            self.section
                .lines
                .insert(insert_idx, format!("{}$object_detected = 1", indent));
            return true;
        }
        false
    }
}
