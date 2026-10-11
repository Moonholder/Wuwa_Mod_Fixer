// src-core/src/domain/sections/texture_override.rs

use crate::domain::{control_flow::ControlFlowBlock, cst::IniCstSection};

pub struct TextureOverrideSectionView<'a> {
    pub section: &'a mut IniCstSection,
}

impl<'a> TextureOverrideSectionView<'a> {
    pub fn new(section: &'a mut IniCstSection) -> Self {
        Self { section }
    }

    pub fn name(&self) -> &str {
        &self.section.name
    }

    pub fn hash(&self) -> Option<String> {
        self.section.get_value("hash")
    }

    pub fn set_hash(&mut self, hash: &str) {
        self.section.set_key_value("hash", hash, "");
    }

    pub fn match_priority(&self) -> Option<String> {
        self.section.get_value("match_priority")
    }

    pub fn set_match_priority(&mut self, priority: &str) {
        self.section.set_key_value("match_priority", priority, "");
    }

    pub fn set_this(&mut self, resource_name: &str) {
        self.section.set_key_value("this", resource_name, "");
    }

    pub fn set_object_detected_this(&mut self, resource_name: &str) {
        self.section.lines.retain(|l| {
            let trimmed = l.trim().to_lowercase();
            !trimmed.starts_with("if") && !trimmed.starts_with("endif") && !trimmed.starts_with("this")
        });
        self.section.lines.push("if $object_detected".to_string());
        self.section.lines.push(format!("    this = {}", resource_name));
        self.section.lines.push("endif".to_string());
    }

    /// Returns parsed control flow AST.
    pub fn control_flow(&self) -> ControlFlowBlock {
        self.section.to_control_flow()
    }

    /// Extracts body AST stripped of header metadata and raw comments.
    pub fn extract_body_ast(&self) -> ControlFlowBlock {
        let mut cf = self.control_flow();
        cf.strip_metadata_keys();
        cf.strip_raw_statements();
        cf
    }

    /// Updates override section in place, returning true if changes occurred.
    pub fn update_override(&mut self, hash: &str, priority: &str, body_ast: &ControlFlowBlock) -> bool {
        let current_hash = self.hash();
        let current_priority = self.match_priority();
        let current_body = self.extract_body_ast();

        let hash_changed = current_hash.as_deref() != Some(hash);
        let priority_changed = current_priority.as_deref() != Some(priority);
        let body_changed = current_body != *body_ast;

        if hash_changed || priority_changed || body_changed {
            self.set_hash(hash);
            self.set_match_priority(priority);
            let mut new_lines = vec![format!("hash = {}", hash), format!("match_priority = {}", priority)];
            new_lines.extend(body_ast.to_lines());
            self.section.lines = new_lines;
            true
        } else {
            false
        }
    }

    /// Constructs a newly derived override section.
    pub fn create_derived(name: &str, hash: &str, priority: &str, body_ast: &ControlFlowBlock) -> IniCstSection {
        let mut sec = IniCstSection::new(name);
        sec.lines.push(format!("hash = {}", hash));
        sec.lines.push(format!("match_priority = {}", priority));
        sec.lines.extend(body_ast.to_lines());
        sec
    }

    /// Applies control flow AST back to section body.
    pub fn apply_control_flow(&mut self, block: &ControlFlowBlock) {
        self.section.apply_control_flow(block);
    }

    /// Collects all referenced resource names within section.
    pub fn collect_referenced_resources(&self) -> Vec<String> {
        self.control_flow().collect_referenced_resources()
    }

    /// Recursively rewrites resource references across control flow blocks.
    pub fn rewrite_resources<F>(&mut self, mut transform: F)
    where
        F: FnMut(&str, &str) -> Option<String>,
    {
        let mut cf = self.control_flow();
        cf.transform_resource_bindings(&mut transform);
        self.apply_control_flow(&cf);
    }
}
