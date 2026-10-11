// src-core/src/domain/control_flow.rs

use crate::utils::ini_parser::parse_line_ref;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Statement {
    KeyValue {
        indent: String,
        key: String,
        value: String,
        comment: Option<String>,
    },
    Raw {
        raw: String,
    },
    IfBlock {
        branches: Vec<ConditionBranch>,
        else_branch: Option<Vec<Statement>>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConditionBranch {
    pub indent: String,
    pub keyword: String,   // "if" | "elif" | "else if"
    pub condition: String, // "$object_detected", "$swapvar == 1", etc.
    pub body: Vec<Statement>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControlFlowBlock {
    pub statements: Vec<Statement>,
}

impl ControlFlowBlock {
    /// Parses structured control flow statements from raw section lines.
    pub fn parse(lines: &[String]) -> Self {
        let mut idx = 0;
        let statements = Self::parse_statements(lines, &mut idx, 0);
        Self { statements }
    }

    fn parse_statements(lines: &[String], idx: &mut usize, depth: usize) -> Vec<Statement> {
        let mut stmts = Vec::new();

        while *idx < lines.len() {
            let line = &lines[*idx];
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with(';') {
                stmts.push(Statement::Raw { raw: line.clone() });
                *idx += 1;
                continue;
            }

            let first_word = trimmed.split_whitespace().next().unwrap_or("");
            let first_word_lower = first_word.to_ascii_lowercase();

            if first_word_lower == "endif" {
                if depth > 0 {
                    *idx += 1;
                    return stmts;
                } else {
                    stmts.push(Statement::Raw { raw: line.clone() });
                    *idx += 1;
                    continue;
                }
            }

            if (first_word_lower == "elif" || first_word_lower == "else") && depth > 0 {
                // Handled by outer branch parsing.
                return stmts;
            }

            if first_word_lower == "if" {
                let indent: String = line
                    .chars()
                    .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                    .collect();
                let cond_str = trimmed[2..].trim().to_string();
                *idx += 1;

                let mut branches = Vec::new();
                let first_body = Self::parse_statements(lines, idx, depth + 1);
                branches.push(ConditionBranch {
                    indent: indent.clone(),
                    keyword: "if".to_string(),
                    condition: cond_str,
                    body: first_body,
                });

                let mut else_branch = None;

                while *idx < lines.len() {
                    let next_line = &lines[*idx];
                    let next_trimmed = next_line.trim();
                    let next_word = next_trimmed
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_ascii_lowercase();

                    if next_word == "elif"
                        || (next_word == "else" && next_trimmed.to_ascii_lowercase().starts_with("else if"))
                    {
                        let b_indent: String = next_line
                            .chars()
                            .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                            .collect();
                        let cond = if next_word == "elif" {
                            next_trimmed[4..].trim().to_string()
                        } else {
                            next_trimmed[7..].trim().to_string()
                        };
                        *idx += 1;
                        let b_body = Self::parse_statements(lines, idx, depth + 1);
                        branches.push(ConditionBranch {
                            indent: b_indent,
                            keyword: if next_word == "elif" {
                                "elif".to_string()
                            } else {
                                "else if".to_string()
                            },
                            condition: cond,
                            body: b_body,
                        });
                    } else if next_word == "else" {
                        *idx += 1;
                        let e_body = Self::parse_statements(lines, idx, depth + 1);
                        else_branch = Some(e_body);
                    } else if next_word == "endif" {
                        *idx += 1;
                        break;
                    } else {
                        break;
                    }
                }

                stmts.push(Statement::IfBlock { branches, else_branch });
                continue;
            }

            let (k, v, comm) = parse_line_ref(line);
            if let (Some(k_str), Some(v_str)) = (k, v) {
                let indent: String = line
                    .chars()
                    .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                    .collect();
                stmts.push(Statement::KeyValue {
                    indent,
                    key: k_str.to_string(),
                    value: v_str.to_string(),
                    comment: comm.map(|c| c.to_string()),
                });
            } else {
                stmts.push(Statement::Raw { raw: line.clone() });
            }
            *idx += 1;
        }

        stmts
    }

    /// Serializes statements back to INI line representations.
    pub fn to_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        Self::render_statements(&self.statements, &mut lines);
        lines
    }

    /// Serializes statements using the given base indentation.
    pub fn to_lines_with_base_indent(&self, base_indent: &str) -> Vec<String> {
        let raw_lines = self.to_lines();
        if raw_lines.is_empty() {
            return Vec::new();
        }

        let min_indent = raw_lines
            .iter()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                l.chars()
                    .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                    .count()
            })
            .min()
            .unwrap_or(0);

        raw_lines
            .into_iter()
            .map(|l| {
                if l.trim().is_empty() {
                    String::new()
                } else {
                    let stripped = if min_indent > 0 && l.len() >= min_indent {
                        &l[min_indent..]
                    } else {
                        l.trim_start()
                    };
                    format!("{}{}", base_indent, stripped)
                }
            })
            .collect()
    }

    fn render_statements(stmts: &[Statement], lines: &mut Vec<String>) {
        for stmt in stmts {
            match stmt {
                Statement::Raw { raw } => {
                    lines.push(raw.clone());
                }
                Statement::KeyValue {
                    indent,
                    key,
                    value,
                    comment,
                } => {
                    if let Some(c) = comment {
                        lines.push(format!("{}{} = {} {}", indent, key, value, c));
                    } else {
                        lines.push(format!("{}{} = {}", indent, key, value));
                    }
                }
                Statement::IfBlock { branches, else_branch } => {
                    let mut fallback_indent = "    ";
                    for branch in branches {
                        fallback_indent = &branch.indent;
                        lines.push(format!("{}{} {}", branch.indent, branch.keyword, branch.condition));
                        Self::render_statements(&branch.body, lines);
                    }
                    if let Some(else_stmts) = else_branch {
                        lines.push(format!("{}else", fallback_indent));
                        Self::render_statements(else_stmts, lines);
                    }
                    lines.push(format!("{}endif", fallback_indent));
                }
            }
        }
    }

    /// Recursively transforms resource assignment values across statements.
    pub fn transform_resource_bindings<F>(&mut self, mut transform: F)
    where
        F: FnMut(&str, &str) -> Option<String>,
    {
        Self::transform_statements_mut(&mut self.statements, &mut transform);
    }

    fn transform_statements_mut<F>(stmts: &mut [Statement], transform: &mut F)
    where
        F: FnMut(&str, &str) -> Option<String>,
    {
        for stmt in stmts {
            match stmt {
                Statement::KeyValue { key, value, .. } => {
                    if let Some(new_val) = transform(key, value) {
                        *value = new_val;
                    }
                }
                Statement::IfBlock { branches, else_branch } => {
                    for b in branches {
                        Self::transform_statements_mut(&mut b.body, transform);
                    }
                    if let Some(e) = else_branch {
                        Self::transform_statements_mut(e, transform);
                    }
                }
                _ => {}
            }
        }
    }

    /// Removes section metadata keys such as hash and match_priority.
    pub fn strip_metadata_keys(&mut self) {
        Self::filter_statements_mut(&mut self.statements, &|stmt| match stmt {
            Statement::KeyValue { key, .. } => {
                let k = key.to_ascii_lowercase();
                k != "hash" && k != "match_priority"
            }
            _ => true,
        });
    }

    /// Removes unparsed raw lines and standalone comments.
    pub fn strip_raw_statements(&mut self) {
        Self::filter_statements_mut(&mut self.statements, &|stmt| !matches!(stmt, Statement::Raw { .. }));
    }

    /// Retains only resource binding statements and enclosing control flow blocks.
    pub fn retain_resource_bindings_only(&mut self) {
        Self::filter_statements_mut(&mut self.statements, &|stmt| match stmt {
            Statement::KeyValue { key, .. } => {
                let k = key.to_ascii_lowercase();
                k == "this" || k.starts_with("ps-t") || k.starts_with("resource")
            }
            Statement::IfBlock { .. } => true,
            Statement::Raw { .. } => false,
        });
    }

    fn filter_statements_mut<F>(stmts: &mut Vec<Statement>, predicate: &F)
    where
        F: Fn(&Statement) -> bool,
    {
        stmts.retain_mut(|stmt| {
            if !predicate(stmt) {
                return false;
            }
            if let Statement::IfBlock { branches, else_branch } = stmt {
                for b in branches.iter_mut() {
                    Self::filter_statements_mut(&mut b.body, predicate);
                }
                if let Some(e) = else_branch.as_mut() {
                    Self::filter_statements_mut(e, predicate);
                }
                // Prune empty conditional blocks.
                let has_any_body = branches.iter().any(|b| !b.body.is_empty())
                    || else_branch.as_ref().map_or(false, |e| !e.is_empty());
                has_any_body
            } else {
                true
            }
        });
    }

    /// Recursively renames target keys across all branches.
    pub fn rename_key(&mut self, from_key: &str, to_key: &str) {
        Self::rename_key_internal(&mut self.statements, from_key, to_key);
    }

    fn rename_key_internal(stmts: &mut [Statement], from_key: &str, to_key: &str) {
        for stmt in stmts {
            match stmt {
                Statement::KeyValue { key, .. } => {
                    if key.eq_ignore_ascii_case(from_key) {
                        *key = to_key.to_string();
                    }
                }
                Statement::IfBlock { branches, else_branch } => {
                    for b in branches {
                        Self::rename_key_internal(&mut b.body, from_key, to_key);
                    }
                    if let Some(e) = else_branch {
                        Self::rename_key_internal(e, from_key, to_key);
                    }
                }
                _ => {}
            }
        }
    }

    /// Collects all referenced resource identifiers from assignment statements.
    pub fn collect_referenced_resources(&self) -> Vec<String> {
        let mut resources = Vec::new();
        Self::collect_resources_internal(&self.statements, &mut resources);
        resources
    }

    fn collect_resources_internal(stmts: &[Statement], out: &mut Vec<String>) {
        for stmt in stmts {
            match stmt {
                Statement::KeyValue { key, value, .. } => {
                    let k_lower = key.to_ascii_lowercase();
                    if k_lower == "this" || k_lower.starts_with("ps-t") || k_lower.contains("rabbitfx") {
                        let clean = value.trim().replace('"', "");
                        let res_name = clean.strip_prefix("ref ").unwrap_or(&clean).trim();
                        let first_token = res_name.split_whitespace().next().unwrap_or(res_name);
                        let lower = first_token.to_ascii_lowercase();
                        if !lower.is_empty() && lower != "null" && lower != "none" {
                            if !out.iter().any(|r| r.eq_ignore_ascii_case(first_token)) {
                                out.push(first_token.to_string());
                            }
                        }
                    }
                }
                Statement::IfBlock { branches, else_branch } => {
                    for b in branches {
                        Self::collect_resources_internal(&b.body, out);
                    }
                    if let Some(e) = else_branch {
                        Self::collect_resources_internal(e, out);
                    }
                }
                _ => {}
            }
        }
    }

    /// Recursively strips outer runtime presence guards from conditional statements.
    pub fn strip_outer_object_detected(&mut self) -> bool {
        Self::strip_object_detected_recursive(&mut self.statements)
    }

    fn strip_object_detected_recursive(stmts: &mut Vec<Statement>) -> bool {
        let mut any_stripped = false;
        let mut i = 0;
        while i < stmts.len() {
            let is_target = match &stmts[i] {
                Statement::IfBlock { branches, else_branch } => {
                    if branches.len() == 1 && else_branch.is_none() {
                        let cond = branches[0].condition.to_ascii_lowercase();
                        let cond_trimmed = cond.trim();
                        cond_trimmed == "$object_detected"
                            || cond_trimmed == "$object_detected == 1"
                            || cond_trimmed == "$object_detected != 0"
                    } else {
                        false
                    }
                }
                _ => false,
            };

            if is_target {
                if let Statement::IfBlock { mut branches, .. } = stmts.remove(i) {
                    let mut inner = branches.remove(0).body;
                    Self::strip_object_detected_recursive(&mut inner);
                    let inner_len = inner.len();
                    for (offset, stmt) in inner.into_iter().enumerate() {
                        stmts.insert(i + offset, stmt);
                    }
                    i += inner_len;
                    any_stripped = true;
                    continue;
                }
            }

            if let Statement::IfBlock { branches, else_branch } = &mut stmts[i] {
                for b in branches {
                    // Strip compound presence condition guards.
                    let cond = b.condition.trim();
                    let cond_lower = cond.to_ascii_lowercase();
                    if let Some(_rest) = cond_lower.strip_prefix("$object_detected &&") {
                        let prefix_len = "$object_detected &&".len();
                        b.condition = cond[prefix_len..].trim().to_string();
                        any_stripped = true;
                    } else if let Some(_rest) = cond_lower.strip_prefix("$object_detected == 1 &&") {
                        let prefix_len = "$object_detected == 1 &&".len();
                        b.condition = cond[prefix_len..].trim().to_string();
                        any_stripped = true;
                    } else if let Some(idx) = cond_lower.rfind("&& $object_detected") {
                        if cond_lower[idx..].trim() == "&& $object_detected"
                            || cond_lower[idx..].trim() == "&& $object_detected == 1"
                        {
                            b.condition = cond[..idx].trim().to_string();
                            any_stripped = true;
                        }
                    }

                    if Self::strip_object_detected_recursive(&mut b.body) {
                        any_stripped = true;
                    }
                }
                if let Some(e) = else_branch {
                    if Self::strip_object_detected_recursive(e) {
                        any_stripped = true;
                    }
                }
            }
            i += 1;
        }
        any_stripped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_flow_roundtrip_complex() {
        let lines: Vec<String> = vec![
            "hash = c3375aee".to_string(),
            "match_priority = 0".to_string(),
            "if $object_detected".to_string(),
            "    if $siwa == 0".to_string(),
            "        this = ResourceTexture27".to_string(),
            "    elif $siwa == 1".to_string(),
            "        this = ResourceTexture27.1".to_string(),
            "    else".to_string(),
            "        this = ResourceTexture27.default".to_string(),
            "    endif".to_string(),
            "endif".to_string(),
        ];

        let block = ControlFlowBlock::parse(&lines);
        let res = block.collect_referenced_resources();
        assert_eq!(
            res,
            vec!["ResourceTexture27", "ResourceTexture27.1", "ResourceTexture27.default"]
        );

        let rendered = block.to_lines();
        assert_eq!(rendered, lines);
    }

    #[test]
    fn test_strip_outer_object_detected() {
        let lines = vec![
            "if $object_detected".to_string(),
            "    this = ResourceCustomTex".to_string(),
            "endif".to_string(),
        ];

        let mut block = ControlFlowBlock::parse(&lines);
        let stripped = block.strip_outer_object_detected();
        assert!(stripped);
        assert_eq!(block.to_lines(), vec!["    this = ResourceCustomTex".to_string()]);
    }

    #[test]
    fn test_transform_resource_bindings_nested() {
        let lines = vec![
            "if $object_detected".to_string(),
            "    if $key_press == 1".to_string(),
            "        this = ResourceOldA ; inline comment".to_string(),
            "    else".to_string(),
            "        this = ref ResourceOldB".to_string(),
            "    endif".to_string(),
            "endif".to_string(),
        ];

        let mut block = ControlFlowBlock::parse(&lines);
        block.transform_resource_bindings(|key, val| {
            if key == "this" {
                if val.contains("ResourceOldA") {
                    Some("ResourceNewA".to_string())
                } else if val.contains("ResourceOldB") {
                    Some("ResourceNewB".to_string())
                } else {
                    None
                }
            } else {
                None
            }
        });

        let rendered = block.to_lines();
        assert_eq!(
            rendered,
            vec![
                "if $object_detected".to_string(),
                "    if $key_press == 1".to_string(),
                "        this = ResourceNewA ; inline comment".to_string(),
                "    else".to_string(),
                "        this = ResourceNewB".to_string(),
                "    endif".to_string(),
                "endif".to_string(),
            ]
        );
    }

    #[test]
    fn test_to_lines_with_base_indent() {
        let lines = vec![
            "if $object_detected".to_string(),
            "    if $hair == 1".to_string(),
            "        this = ResourceTextureHair1".to_string(),
            "    else".to_string(),
            "        this = ResourceTextureHair2".to_string(),
            "    endif".to_string(),
            "endif".to_string(),
        ];

        let mut block = ControlFlowBlock::parse(&lines);
        block.strip_outer_object_detected();
        let formatted = block.to_lines_with_base_indent("        ");
        assert_eq!(
            formatted,
            vec![
                "        if $hair == 1".to_string(),
                "            this = ResourceTextureHair1".to_string(),
                "        else".to_string(),
                "            this = ResourceTextureHair2".to_string(),
                "        endif".to_string(),
            ]
        );
    }
}
