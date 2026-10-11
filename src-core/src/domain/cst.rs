// src-core/src/domain/cst.rs

use std::collections::HashSet;

use crate::{domain::control_flow::ControlFlowBlock, utils::ini_parser::parse_line_ref};

/// Concrete Syntax Tree representation of an INI section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IniCstSection {
    pub leading_lines: Vec<String>, // Leading comments and empty lines bound to section header
    pub name: String,               // Section header identifier
    pub header_comment: Option<String>, // Inline trailing comment on header line
    pub lines: Vec<String>,         // Raw body lines
}

impl IniCstSection {
    pub fn new(name: &str) -> Self {
        Self {
            leading_lines: Vec::new(),
            name: name.to_string(),
            header_comment: None,
            lines: Vec::new(),
        }
    }

    /// Checks whether the section contains the specified key (case-insensitive).
    pub fn has_key(&self, key: &str) -> bool {
        self.lines.iter().any(|line| {
            let (k, _, _) = parse_line_ref(line);
            if let Some(k_str) = k {
                k_str.eq_ignore_ascii_case(key)
            } else {
                false
            }
        })
    }

    /// Updates an existing key in place, preserving original indentation and comments.
    fn update_existing_key(&mut self, key: &str, value: &str) -> bool {
        for line in &mut self.lines {
            let (k, _, comment) = parse_line_ref(line);
            if let Some(k_str) = k {
                if k_str.eq_ignore_ascii_case(key) {
                    let original_indent: String = line
                        .chars()
                        .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                        .collect();

                    if let Some(comm) = comment {
                        *line = format!("{}{} = {} {}", original_indent, key, value, comm);
                    } else {
                        *line = format!("{}{} = {}", original_indent, key, value);
                    }
                    return true;
                }
            }
        }
        false
    }

    /// Sets a key-value pair, updating in place if present or appending if absent.
    pub fn set_key_value(&mut self, key: &str, value: &str, fallback_indent: &str) {
        if !self.update_existing_key(key, value) {
            self.push_line_tight(format!("{}{} = {}", fallback_indent, key, value));
        }
    }

    /// Prepends a key-value pair at the beginning of the section body.
    pub fn prepend_key_value(&mut self, key: &str, value: &str, fallback_indent: &str) {
        if !self.update_existing_key(key, value) {
            self.lines.insert(0, format!("{}{} = {}", fallback_indent, key, value));
        }
    }

    /// Inserts a line before any trailing whitespace in the section.
    pub fn push_line_tight(&mut self, line: String) {
        let mut insert_idx = self.lines.len();
        while insert_idx > 0 && self.lines[insert_idx - 1].trim().is_empty() {
            insert_idx -= 1;
        }
        self.lines.insert(insert_idx, line);
    }

    /// Appends a key-value pair without checking for existing keys.
    pub fn push_key_value_tight(&mut self, key: &str, value: &str, indent: &str) {
        self.push_line_tight(format!("{}{} = {}", indent, key, value));
    }

    /// Removes lines matching the specified key.
    pub fn remove_key(&mut self, key: &str) -> bool {
        let before_len = self.lines.len();
        self.lines.retain(|line| {
            let (k, _, _) = parse_line_ref(line);
            if let Some(k_str) = k {
                !k_str.eq_ignore_ascii_case(key)
            } else {
                true
            }
        });
        self.lines.len() != before_len
    }

    /// Returns a zero-allocation reference to the value of the specified key.
    pub fn get_value_ref<'a>(&'a self, key: &str) -> Option<&'a str> {
        for line in &self.lines {
            let (k, v, _) = parse_line_ref(line);
            if let (Some(k_str), Some(v_str)) = (k, v) {
                if k_str.eq_ignore_ascii_case(key) {
                    return Some(v_str);
                }
            }
        }
        None
    }

    /// Returns the value string of the specified key.
    pub fn get_value(&self, key: &str) -> Option<String> {
        self.get_value_ref(key).map(|s| s.to_string())
    }

    /// Collects all values associated with the specified key.
    pub fn get_all_values(&self, key: &str) -> Vec<String> {
        let mut values = Vec::new();
        for line in &self.lines {
            let (k, v, _) = parse_line_ref(line);
            if let (Some(k_str), Some(v_str)) = (k, v) {
                if k_str.eq_ignore_ascii_case(key) {
                    values.push(v_str.to_string());
                }
            }
        }
        values
    }

    /// Returns the unquoted value string of the specified key.
    pub fn get_unquoted_value(&self, key: &str) -> Option<String> {
        self.get_value_ref(key).map(|v| {
            let trimmed = v.trim();
            if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
                trimmed[1..trimmed.len() - 1].to_string()
            } else {
                trimmed.to_string()
            }
        })
    }

    /// Extracts control flow and transformed resource lines with original hierarchy preserved.
    pub fn extract_control_flow_and_resources<F>(
        &self,
        strip_object_detected: bool,
        mut transform_key_value: F,
    ) -> Vec<String>
    where
        F: FnMut(&str, &str, &str) -> Option<String>,
    {
        let mut result = Vec::new();
        for line in &self.lines {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with(';') {
                continue;
            }

            let first_word = trimmed.split_whitespace().next().unwrap_or("");
            let is_control_flow = ["if", "else", "elif", "endif"]
                .iter()
                .any(|&kw| first_word.eq_ignore_ascii_case(kw));

            if is_control_flow {
                result.push(line.clone());
            } else {
                let (k, v, _) = parse_line_ref(line);
                if let (Some(key_str), Some(val_str)) = (k, v) {
                    let indent: String = line
                        .chars()
                        .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                        .collect();

                    if let Some(transformed_line) = transform_key_value(&indent, key_str, val_str) {
                        result.push(transformed_line);
                    }
                }
            }
        }

        if strip_object_detected
            && result.len() >= 2
            && result[0].trim().to_lowercase().contains("$object_detected")
            && result[result.len() - 1].trim().eq_ignore_ascii_case("endif")
        {
            result.remove(0);
            result.pop();

            if let Some(first_remaining) = result.first() {
                let cut_prefix: String = first_remaining
                    .chars()
                    .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                    .collect();
                if !cut_prefix.is_empty() {
                    for line in &mut result {
                        if line.starts_with(&cut_prefix) {
                            *line = line[cut_prefix.len()..].to_string();
                        }
                    }
                }
            }
        }

        result
    }

    // ── Domain Predicates ────────────────────────────────────────────────────────

    /// Returns true if section represents a pure texture override (excludes component/shapekey).
    #[inline]
    pub fn is_texture_override(&self) -> bool {
        let lower = self.name.to_ascii_lowercase();
        lower.starts_with("textureoverride")
            && !lower.starts_with("textureoverridecomponent")
            && !lower.starts_with("textureoverrideshapekey")
    }

    /// Returns true if section represents a component draw call override.
    #[inline]
    pub fn is_component_section(&self) -> bool {
        self.name.to_ascii_lowercase().starts_with("textureoverridecomponent")
    }

    /// Extracts component index if section is a component override.
    pub fn component_id(&self) -> Option<u32> {
        let lower = self.name.to_ascii_lowercase();
        lower
            .strip_prefix("textureoverridecomponent")
            .and_then(|s| s.parse::<u32>().ok())
    }

    /// Returns true if section represents a shape key override.
    #[inline]
    pub fn is_shapekey_section(&self) -> bool {
        self.name.to_ascii_lowercase().starts_with("textureoverrideshapekey")
    }

    /// Checks whether section matches the specified texture hash.
    #[inline]
    pub fn matches_texture_hash(&self, target_hash: &str) -> bool {
        if !self.is_texture_override() {
            return false;
        }
        self.get_value_ref("hash")
            .map_or(false, |h| h.trim().eq_ignore_ascii_case(target_hash))
    }

    #[inline]
    pub fn as_resource_view_mut(&mut self) -> crate::domain::sections::ResourceSectionView<'_> {
        crate::domain::sections::ResourceSectionView::new(self)
    }

    #[inline]
    pub fn as_texture_override_view_mut(&mut self) -> crate::domain::sections::TextureOverrideSectionView<'_> {
        crate::domain::sections::TextureOverrideSectionView::new(self)
    }

    #[inline]
    pub fn as_component_view_mut(&mut self) -> crate::domain::sections::ComponentSectionView<'_> {
        let comp_id = self.component_id().unwrap_or(0);
        crate::domain::sections::ComponentSectionView::new(self, comp_id)
    }

    /// Checks whether section matches any hash in the provided set.
    #[inline]
    pub fn matches_any_texture_hash(&self, hashes: &HashSet<String>) -> bool {
        if !self.is_texture_override() {
            return false;
        }
        self.get_value_ref("hash")
            .map_or(false, |h| hashes.contains(&h.trim().to_ascii_lowercase()))
    }

    // ── AST Integration ────────────────────────────────────────────────────────

    /// Parses section lines into a control flow AST.
    pub fn to_control_flow(&self) -> ControlFlowBlock {
        ControlFlowBlock::parse(&self.lines)
    }

    /// Applies control flow AST back to section body lines.
    pub fn apply_control_flow(&mut self, block: &ControlFlowBlock) {
        self.lines = block.to_lines();
    }

    /// Collects all referenced resource names within section and control flow branches.
    #[inline]
    pub fn collect_referenced_resources(&self) -> Vec<String> {
        self.to_control_flow().collect_referenced_resources()
    }

    /// Recursively rewrites resource bindings across control flow branches.
    pub fn rewrite_resource_bindings<F>(&mut self, transform: F)
    where
        F: FnMut(&str, &str) -> Option<String>,
    {
        let mut cf = self.to_control_flow();
        cf.transform_resource_bindings(transform);
        self.apply_control_flow(&cf);
    }
}

/// High-fidelity Concrete Syntax Tree representation of an INI document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IniCstDocument {
    pub pre_lines: Vec<String>,
    pub sections: Vec<IniCstSection>,
    pub line_ending: String,
}

impl IniCstDocument {
    /// Splits leading comments bound to the subsequent section from preceding buffer lines.
    fn split_leading_lines(buf: &mut Vec<String>) -> Vec<String> {
        if buf.is_empty() {
            return Vec::new();
        }

        let mut idx = buf.len();
        let mut trailing_blank_count = 0;
        while idx > 0 && buf[idx - 1].trim().is_empty() {
            idx -= 1;
            trailing_blank_count += 1;
        }

        if idx == 0 {
            // Buffer contains only blank lines.
            return Vec::new();
        }

        let mut comment_count = 0;
        while idx > 0 && buf[idx - 1].trim_start().starts_with(';') {
            idx -= 1;
            comment_count += 1;
        }

        if comment_count == 0 {
            // No comment lines detected.
            return Vec::new();
        }

        let comment_start_idx = idx;

        // Preserves trailing comments of preceding section when separated from header by blanks:
        // code -> comment -> blank -> [Next]
        if trailing_blank_count > 0 && comment_start_idx > 0 {
            let prev_line = &buf[comment_start_idx - 1];
            if !prev_line.trim().is_empty() {
                return Vec::new();
            }
        }

        // Extract leading comments belonging to the next section.
        let leading = buf.drain(comment_start_idx..).collect::<Vec<_>>();

        // Strip remaining trailing blank lines.
        while buf.last().map_or(false, |l| l.trim().is_empty()) {
            buf.pop();
        }

        leading
    }

    pub fn parse(content: &str) -> Self {
        let line_ending = if content.contains("\r\n") { "\r\n" } else { "\n" };
        let mut pre_lines = Vec::new();
        let mut sections = Vec::new();
        let mut current_section: Option<IniCstSection> = None;

        for line in content.split('\n') {
            let mut line_str = line.to_string();
            if line_str.ends_with('\r') {
                line_str.pop();
            }

            let mut in_quotes = false;
            let mut escaped = false;
            let mut comment_idx = None;

            for (idx, c) in line_str.char_indices() {
                if escaped {
                    escaped = false;
                    continue;
                }
                if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_quotes = !in_quotes;
                } else if !in_quotes && c == ';' {
                    comment_idx = Some(idx);
                    break;
                }
            }

            let clean_line = if let Some(idx) = comment_idx {
                &line_str[..idx]
            } else {
                &line_str
            };
            let trimmed = clean_line.trim();

            if trimmed.starts_with('[') {
                let mut name_part = &trimmed[1..];
                if name_part.ends_with(']') {
                    name_part = &name_part[..name_part.len() - 1];
                }
                let name = name_part.trim();

                if !name.is_empty() {
                    let leading_lines = if let Some(sec) = &mut current_section {
                        Self::split_leading_lines(&mut sec.lines)
                    } else {
                        Self::split_leading_lines(&mut pre_lines)
                    };

                    if let Some(sec) = current_section.take() {
                        sections.push(sec);
                    }
                    let mut sec = IniCstSection::new(name);
                    sec.leading_lines = leading_lines;
                    if let Some(idx) = comment_idx {
                        sec.header_comment = Some(line_str[idx..].to_string());
                    }
                    current_section = Some(sec);
                    continue;
                }
            }

            if let Some(sec) = &mut current_section {
                sec.lines.push(line_str);
            } else {
                pre_lines.push(line_str);
            }
        }

        if let Some(sec) = current_section {
            sections.push(sec);
        }

        Self {
            pre_lines,
            sections,
            line_ending: line_ending.to_string(),
        }
    }

    /// Serializes document back to formatted INI string with original formatting preserved.
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        for line in &self.pre_lines {
            out.push_str(line);
            out.push_str(&self.line_ending);
        }
        for (i, sec) in self.sections.iter().enumerate() {
            if i > 0 || !self.pre_lines.is_empty() {
                if !out.is_empty() && !out.ends_with(&format!("{}{}", self.line_ending, self.line_ending)) {
                    if out.ends_with(&self.line_ending) {
                        out.push_str(&self.line_ending);
                    } else {
                        out.push_str(&self.line_ending);
                        out.push_str(&self.line_ending);
                    }
                }
            }

            for line in &sec.leading_lines {
                out.push_str(line);
                out.push_str(&self.line_ending);
            }

            if let Some(ref comm) = sec.header_comment {
                out.push_str(&format!("[{}]{}{}", sec.name, comm, self.line_ending));
            } else {
                out.push_str(&format!("[{}]{}", sec.name, self.line_ending));
            }

            for line in &sec.lines {
                out.push_str(line);
                out.push_str(&self.line_ending);
            }
        }
        if !out.is_empty() && out.ends_with(&self.line_ending) {
            out.truncate(out.len() - self.line_ending.len());
        }
        out
    }

    pub fn get_section(&self, name: &str) -> Option<&IniCstSection> {
        self.sections.iter().find(|s| s.name.eq_ignore_ascii_case(name))
    }

    pub fn get_section_mut(&mut self, name: &str) -> Option<&mut IniCstSection> {
        self.sections.iter_mut().find(|s| s.name.eq_ignore_ascii_case(name))
    }

    pub fn has_section(&self, name: &str) -> bool {
        self.get_section(name).is_some()
    }

    pub fn remove_section(&mut self, name: &str) -> bool {
        let before_len = self.sections.len();
        self.sections.retain(|s| !s.name.eq_ignore_ascii_case(name));
        self.sections.len() != before_len
    }

    pub fn add_section(&mut self, name: &str) -> &mut IniCstSection {
        if let Some(idx) = self.sections.iter().position(|s| s.name.eq_ignore_ascii_case(name)) {
            &mut self.sections[idx]
        } else {
            let sec = IniCstSection::new(name);
            if name.eq_ignore_ascii_case("Constants") {
                self.sections.insert(0, sec);
                &mut self.sections[0]
            } else {
                let idx = self.sections.len();
                self.sections.push(sec);
                &mut self.sections[idx]
            }
        }
    }

    pub fn insert_section_after(&mut self, target_name: &str, new_section: IniCstSection) -> bool {
        if let Some(pos) = self
            .sections
            .iter()
            .position(|s| s.name.eq_ignore_ascii_case(target_name))
        {
            self.sections.insert(pos + 1, new_section);
            true
        } else {
            false
        }
    }

    /// Rewrites section body while preserving section header and leading comments.
    pub fn rewrite_section_content(&mut self, section_name: &str, new_content: &str) -> bool {
        if let Some(target) = self.get_section_mut(section_name) {
            let mut dummy_doc = if new_content.trim_start().starts_with('[') {
                Self::parse(new_content)
            } else {
                Self::parse(&format!("[{}]\n{}", section_name, new_content))
            };
            if let Some(mut sec) = dummy_doc.sections.pop() {
                if sec.leading_lines.is_empty() {
                    sec.leading_lines = std::mem::take(&mut target.leading_lines);
                }
                if *target != sec {
                    *target = sec;
                    return true;
                }
            }
        }
        false
    }

    pub fn iter_texture_overrides(&self) -> impl Iterator<Item = &IniCstSection> {
        self.sections.iter().filter(|s| s.is_texture_override())
    }

    pub fn iter_texture_overrides_mut(&mut self) -> impl Iterator<Item = &mut IniCstSection> {
        self.sections.iter_mut().filter(|s| s.is_texture_override())
    }

    pub fn find_texture_override_by_hash(&self, hash: &str) -> Option<&IniCstSection> {
        let hash_lower = hash.to_lowercase();
        let matching: Vec<_> = self
            .iter_texture_overrides()
            .filter(|s| s.matches_texture_hash(&hash_lower))
            .collect();
        if matching.is_empty() {
            return None;
        }
        // Prefer section with active resource bindings over auxiliary detection sections.
        if let Some(sec) = matching.iter().find(|s| !s.collect_referenced_resources().is_empty()) {
            return Some(*sec);
        }
        Some(matching[0])
    }

    pub fn find_texture_override_by_hashes(&self, hashes: &HashSet<String>) -> Option<&IniCstSection> {
        self.iter_texture_overrides()
            .find(|s| s.matches_any_texture_hash(hashes))
    }

    /// Returns a typed view for the [Constants] section.
    pub fn as_constants_mut(&mut self) -> Option<crate::domain::sections::ConstantsSectionView<'_>> {
        self.get_section_mut("Constants")
            .map(crate::domain::sections::ConstantsSectionView::new)
    }

    /// Returns or creates a typed view for the [Constants] section.
    pub fn ensure_constants(&mut self) -> crate::domain::sections::ConstantsSectionView<'_> {
        let sec = self.add_section("Constants");
        crate::domain::sections::ConstantsSectionView::new(sec)
    }

    /// Returns a typed view for the specified [CommandList] section.
    pub fn as_command_list_mut(&mut self, name: &str) -> Option<crate::domain::sections::CommandListSectionView<'_>> {
        self.get_section_mut(name)
            .map(crate::domain::sections::CommandListSectionView::new)
    }

    /// Returns or creates a typed view for the specified [CommandList] section.
    pub fn ensure_command_list(&mut self, name: &str) -> crate::domain::sections::CommandListSectionView<'_> {
        let sec = self.add_section(name);
        crate::domain::sections::CommandListSectionView::new(sec)
    }

    /// Returns a typed view for the specified component override section.
    pub fn as_component_mut(&mut self, component_id: u32) -> Option<crate::domain::sections::ComponentSectionView<'_>> {
        let sec_name = format!("TextureOverrideComponent{}", component_id);
        self.get_section_mut(&sec_name)
            .map(|s| crate::domain::sections::ComponentSectionView::new(s, component_id))
    }

    /// Returns a typed view for the specified [Resource] section.
    pub fn as_resource_mut(&mut self, name: &str) -> Option<crate::domain::sections::ResourceSectionView<'_>> {
        self.get_section_mut(name)
            .map(crate::domain::sections::ResourceSectionView::new)
    }

    /// Returns or creates a typed view for the specified [Resource] section.
    pub fn ensure_resource(&mut self, name: &str) -> crate::domain::sections::ResourceSectionView<'_> {
        let sec = self.add_section(name);
        crate::domain::sections::ResourceSectionView::new(sec)
    }

    /// Returns a typed view for the specified [TextureOverride] section.
    pub fn as_texture_override_mut(
        &mut self,
        name: &str,
    ) -> Option<crate::domain::sections::TextureOverrideSectionView<'_>> {
        self.get_section_mut(name)
            .map(crate::domain::sections::TextureOverrideSectionView::new)
    }

    /// Returns or creates a typed view for the specified [TextureOverride] section.
    pub fn ensure_texture_override(&mut self, name: &str) -> crate::domain::sections::TextureOverrideSectionView<'_> {
        let sec = self.add_section(name);
        crate::domain::sections::TextureOverrideSectionView::new(sec)
    }

    /// Extracts resource buffer paths and strides matching the buffer type.
    pub fn collect_resource_buffers(
        &self,
        buf_type: crate::collector::BufferType,
        ini_path: &std::path::Path,
    ) -> Vec<(std::path::PathBuf, Option<usize>)> {
        let mut results = Vec::new();
        let base_dir = ini_path.parent().unwrap_or_else(|| std::path::Path::new("."));

        let is_target_sec = |name: &str| -> bool {
            let lower = name.to_lowercase();
            if lower.contains("override")
                || lower.ends_with("rw")
                || lower.ends_with("rw]")
                || lower == "resourceblendbuffernostride"
            {
                return false;
            }

            match buf_type {
                crate::collector::BufferType::Blend => lower.starts_with("resourceblendbuffer"),
                crate::collector::BufferType::TexCoord => lower.starts_with("resourcetexcoordbuffer"),
                crate::collector::BufferType::Position => lower.starts_with("resourcepositionbuffer"),
                crate::collector::BufferType::Index => lower.starts_with("resourceindexbuffer"),
                crate::collector::BufferType::BlendRemapForward => lower.starts_with("resourceblendremapforwardbuffer"),
                crate::collector::BufferType::Color => lower.starts_with("resourcecolorbuffer"),
                crate::collector::BufferType::ShapeKeyOffset => lower.starts_with("resourceshapekeyoffsetbuffer"),
                crate::collector::BufferType::ShapeKeyVertexId => lower.starts_with("resourceshapekeyvertexidbuffer"),
                crate::collector::BufferType::ShapeKeyVertexOffset => {
                    lower.starts_with("resourceshapekeyvertexoffsetbuffer")
                }
            }
        };

        for sec in &self.sections {
            if is_target_sec(&sec.name) {
                if let Some(filename) = sec.get_unquoted_value("filename") {
                    let stride = sec.get_value("stride").and_then(|s| s.parse().ok());
                    let path = base_dir.join(filename);
                    results.push((path, stride));
                }
            }
        }
        results
    }

    /// Collects draw indexed ranges across component override sections.
    pub fn collect_component_indices(&self) -> std::collections::HashMap<u8, (usize, usize)> {
        let mut comp_map = std::collections::HashMap::new();

        for sec in &self.sections {
            if let Some(comp_id) = sec.component_id() {
                let mut min_offset = usize::MAX;
                let mut max_end_offset = 0;

                for line in &sec.lines {
                    if let Some(pos) = line.find("drawindexed") {
                        if let Some(eq_pos) = line[pos..].find('=') {
                            let val_str = &line[pos + eq_pos + 1..];
                            let parts: Vec<&str> = val_str.split(',').collect();
                            if parts.len() >= 2 {
                                if let (Ok(count), Ok(offset)) =
                                    (parts[0].trim().parse::<usize>(), parts[1].trim().parse::<usize>())
                                {
                                    min_offset = min_offset.min(offset);
                                    max_end_offset = max_end_offset.max(offset + count);
                                }
                            }
                        }
                    }
                }

                if min_offset != usize::MAX {
                    comp_map.insert(comp_id as u8, (max_end_offset - min_offset, min_offset));
                }
            }
        }
        comp_map
    }

    /// Collects vertex group offsets across component override sections.
    pub fn collect_vg_offsets(&self) -> std::collections::HashMap<u8, u16> {
        let mut offsets = std::collections::HashMap::new();
        for sec in &self.sections {
            if let Some(comp_id) = sec.component_id() {
                if let Some(val_str) = sec.get_unquoted_value("vg_offset") {
                    if let Ok(offset_val) = val_str.trim().parse::<u16>() {
                        offsets.insert(comp_id as u8, offset_val);
                    }
                }
            }
        }
        offsets
    }

    /// Replaces values for the specified key across lines while preserving indentation and comments.
    pub fn replace_key_values<F>(&mut self, target_key: &str, mut replacer: F) -> bool
    where
        F: FnMut(&str) -> Option<String>,
    {
        let mut modified = false;

        let mut replace_line = |line: &mut String| -> bool {
            let trimmed_start = line.trim_start();
            let is_comment = trimmed_start.starts_with(';');

            let (clean_line, comment_prefix) = if is_comment {
                let prefix: String = line.chars().take_while(|&c| c.is_whitespace() || c == ';').collect();
                (&line[prefix.len()..], Some(prefix))
            } else {
                (line.as_str(), None)
            };

            let (k, v, comment) = crate::utils::ini_parser::parse_line(clean_line);
            if let (Some(key), Some(val)) = (k, v) {
                if key.eq_ignore_ascii_case(target_key) {
                    if let Some(new_val) = replacer(val.trim()) {
                        if let Some(ref prefix) = comment_prefix {
                            if let Some(comm) = comment {
                                *line = format!("{}{} = {} {}", prefix, key, new_val, comm);
                            } else {
                                *line = format!("{}{} = {}", prefix, key, new_val);
                            }
                        } else {
                            let indent: String = line
                                .chars()
                                .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                                .collect();

                            if let Some(comm) = comment {
                                *line = format!("{}{} = {} {}", indent, key, new_val, comm);
                            } else {
                                *line = format!("{}{} = {}", indent, key, new_val);
                            }
                        }
                        return true;
                    }
                }
            }
            false
        };

        for line in &mut self.pre_lines {
            if replace_line(line) {
                modified = true;
            }
        }

        for section in &mut self.sections {
            for line in &mut section.leading_lines {
                if replace_line(line) {
                    modified = true;
                }
            }
            for line in &mut section.lines {
                if replace_line(line) {
                    modified = true;
                }
            }
        }

        modified
    }

    /// Appends new sections if not already present in document.
    pub fn push_sections_if_missing(&mut self, new_sections: Vec<IniCstSection>) -> bool {
        let mut inserted = false;
        for sec in new_sections {
            if !self.has_section(&sec.name) {
                self.sections.push(sec);
                inserted = true;
            }
        }
        inserted
    }

    /// Inserts new sections at index if not already present in document.
    pub fn insert_sections_if_missing(&mut self, mut at_index: usize, new_sections: Vec<IniCstSection>) -> bool {
        let mut inserted = false;
        for sec in new_sections {
            if !self.has_section(&sec.name) {
                if at_index > self.sections.len() {
                    at_index = self.sections.len();
                }
                self.sections.insert(at_index, sec);
                at_index += 1;
                inserted = true;
            }
        }
        inserted
    }

    /// Finds section indices matching the predicate.
    pub fn find_section_indices<F>(&self, mut predicate: F) -> Vec<usize>
    where
        F: FnMut(&IniCstSection) -> bool,
    {
        self.sections
            .iter()
            .enumerate()
            .filter(|(_, sec)| predicate(sec))
            .map(|(idx, _)| idx)
            .collect()
    }

    /// Iterates mutable typed views over resource sections.
    pub fn iter_resources_mut(&mut self) -> impl Iterator<Item = crate::domain::sections::ResourceSectionView<'_>> {
        self.sections
            .iter_mut()
            .filter(|s| s.name.to_ascii_lowercase().starts_with("resource"))
            .map(crate::domain::sections::ResourceSectionView::new)
    }

    /// Iterates mutable typed views over component sections.
    pub fn iter_components_mut(&mut self) -> impl Iterator<Item = crate::domain::sections::ComponentSectionView<'_>> {
        self.sections.iter_mut().filter(|s| s.is_component_section()).map(|s| {
            let id = s.component_id().unwrap_or(0);
            crate::domain::sections::ComponentSectionView::new(s, id)
        })
    }

    /// Applies a mutating closure across all document lines.
    pub fn transform_all_lines<F>(&mut self, mut f: F) -> bool
    where
        F: FnMut(&mut String) -> bool,
    {
        let mut modified = false;
        for line in &mut self.pre_lines {
            if f(line) {
                modified = true;
            }
        }
        for sec in &mut self.sections {
            for line in &mut sec.leading_lines {
                if f(line) {
                    modified = true;
                }
            }
            for line in &mut sec.lines {
                if f(line) {
                    modified = true;
                }
            }
        }
        modified
    }

    /// Inserts sections immediately after the specified anchor section.
    pub fn insert_sections_after(&mut self, anchor_name: &str, new_sections: Vec<IniCstSection>) -> bool {
        if let Some(anchor_idx) = self
            .sections
            .iter()
            .position(|s| s.name.eq_ignore_ascii_case(anchor_name))
        {
            let mut insert_cursor = anchor_idx + 1;
            let mut inserted = false;
            for sec in new_sections {
                if !self.has_section(&sec.name) {
                    self.sections.insert(insert_cursor, sec);
                    insert_cursor += 1;
                    inserted = true;
                }
            }
            inserted
        } else {
            false
        }
    }
}
