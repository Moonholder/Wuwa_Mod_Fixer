// src-core/src/utils/ini_parser.rs

#[derive(Clone, Debug)]
pub struct IniSection {
    pub name: String,                   // 节名，不含中括号，例如"Constants"
    pub header_comment: Option<String>, // 保留节声明行的行尾注释，例如 " ; 全局配置"
    pub lines: Vec<String>,             // 节体内的原始行列表，包含注释 and 空行
}

impl IniSection {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            header_comment: None,
            lines: Vec::new(),
        }
    }

    /// 判断当前 Section 内是否存在指定的 Key（不区分大小写）
    pub fn has_key(&self, key: &str) -> bool {
        self.lines.iter().any(|line| {
            let (k, _, _) = parse_line(line);
            if let Some(k_str) = k {
                k_str.eq_ignore_ascii_case(key)
            } else {
                false
            }
        })
    }

    /// 内部辅助函数：寻找已有 Key 并更新，同时自动继承并保留原行的前导缩进
    fn update_existing_key(&mut self, key: &str, value: &str) -> bool {
        for line in &mut self.lines {
            let (k, _, comment) = parse_line(line);
            if let Some(k_str) = k {
                if k_str.eq_ignore_ascii_case(key) {
                    // 动态提取原行原本的缩进（前导空白字符）
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

    /// 设置键值对。若已存在，则更新值并保留原行缩进；若不存在，则在末尾追加并应用备用缩进
    pub fn set_key_value(&mut self, key: &str, value: &str, fallback_indent: &str) {
        if !self.update_existing_key(key, value) {
            self.lines.push(format!("{}{} = {}", fallback_indent, key, value));
        }
    }

    /// 前置插入键值对。若已存在，则更新值并保留原行缩进；若不存在，则在头部插入并应用备用缩进
    pub fn prepend_key_value(&mut self, key: &str, value: &str, fallback_indent: &str) {
        if !self.update_existing_key(key, value) {
            self.lines.insert(0, format!("{}{} = {}", fallback_indent, key, value));
        }
    }

    /// 移除指定的 Key，成功移除返回 true
    pub fn remove_key(&mut self, key: &str) -> bool {
        let before_len = self.lines.len();
        self.lines.retain(|line| {
            let (k, _, _) = parse_line(line);
            if let Some(k_str) = k {
                !k_str.eq_ignore_ascii_case(key)
            } else {
                true
            }
        });
        self.lines.len() != before_len
    }

    /// 获取指定的原始 Value（不去除可能存在的双引号）
    pub fn get_value(&self, key: &str) -> Option<String> {
        for line in &self.lines {
            let (k, v, _) = parse_line(line);
            if let (Some(k_str), Some(v_str)) = (k, v) {
                if k_str.eq_ignore_ascii_case(key) {
                    return Some(v_str);
                }
            }
        }
        None
    }

    /// 获取指定的 key 对应的所有 value 列表
    pub fn get_all_values(&self, key: &str) -> Vec<String> {
        let mut values = Vec::new();
        for line in &self.lines {
            let (k, v, _) = parse_line(line);
            if let (Some(k_str), Some(v_str)) = (k, v) {
                if k_str.eq_ignore_ascii_case(key) {
                    values.push(v_str);
                }
            }
        }
        values
    }

    /// 提取当前 Section 中所有的控制流行（if/else/elif/endif等）、注释行以及经由 transform 闭包转换后的资源映射行，
    /// 保留原有的代码前导缩进与层级结构。
    pub fn extract_control_flow_and_resources<F>(&self, mut transform_key_value: F) -> Vec<String>
    where
        F: FnMut(&str, &str, &str) -> Option<String>,
    {
        let mut result = Vec::new();
        for line in &self.lines {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with(';') {
                continue;
            }

            let lower_trimmed = trimmed.to_lowercase();
            let first_word = lower_trimmed.split_whitespace().next().unwrap_or("");

            let is_control_flow = matches!(first_word, "if" | "else" | "elif" | "endif");

            if is_control_flow {
                result.push(line.clone());
            } else {
                let (k, v, _) = parse_line(line);
                if let (Some(key_str), Some(val_str)) = (k, v) {
                    let indent: String = line
                        .chars()
                        .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                        .collect();

                    if let Some(transformed_line) = transform_key_value(&indent, &key_str, &val_str) {
                        result.push(transformed_line);
                    }
                }
            }
        }
        result
    }

    /// 获取去除了双引号包裹的 Value
    pub fn get_unquoted_value(&self, key: &str) -> Option<String> {
        self.get_value(key).map(|v| {
            let trimmed = v.trim();
            if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
                trimmed[1..trimmed.len() - 1].to_string()
            } else {
                trimmed.to_string()
            }
        })
    }
}

#[derive(Clone, Debug)]
pub struct IniDocument {
    pub pre_lines: Vec<String>, // 第一个节出现之前的头部行（如全局注释）
    pub sections: Vec<IniSection>,
    pub line_ending: String,
}

impl IniDocument {
    pub fn parse(content: &str) -> Self {
        let line_ending = if content.contains("\r\n") { "\r\n" } else { "\n" };
        let mut pre_lines = Vec::new();
        let mut sections = Vec::new();
        let mut current_section: Option<IniSection> = None;

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

            // Section 标题行识别
            if trimmed.starts_with('[') {
                let mut name_part = &trimmed[1..];
                if name_part.ends_with(']') {
                    name_part = &name_part[..name_part.len() - 1];
                }
                let name = name_part.trim();

                if !name.is_empty() {
                    if let Some(sec) = current_section.take() {
                        sections.push(sec);
                    }
                    let mut sec = IniSection::new(name);
                    // 保留 Section 标题声明行的原始注释
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

    /// 转换为 INI 文本，保持其原有注释和排版结构
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

    pub fn get_section(&self, name: &str) -> Option<&IniSection> {
        self.sections.iter().find(|s| s.name.eq_ignore_ascii_case(name))
    }

    pub fn get_section_mut(&mut self, name: &str) -> Option<&mut IniSection> {
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

    pub fn add_section(&mut self, name: &str) -> &mut IniSection {
        if let Some(idx) = self.sections.iter().position(|s| s.name.eq_ignore_ascii_case(name)) {
            &mut self.sections[idx]
        } else {
            let sec = IniSection::new(name);
            if name.eq_ignore_ascii_case("Constants") {
                self.sections.insert(0, sec);
                &mut self.sections[0]
            } else {
                self.sections.push(sec);
                self.sections.last_mut().unwrap()
            }
        }
    }

    pub fn insert_section_after(&mut self, target_name: &str, new_section: IniSection) -> bool {
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

    pub fn get_value(&self, section: &str, key: &str) -> Option<String> {
        self.get_section(section).and_then(|s| s.get_value(key))
    }

    pub fn set_value(&mut self, section: &str, key: &str, value: &str, indent: &str) {
        self.add_section(section).set_key_value(key, value, indent);
    }
}

pub fn parse_line(line: &str) -> (Option<String>, Option<String>, Option<String>) {
    let trimmed_fast = line.trim_start();

    if trimmed_fast.is_empty() {
        return (None, None, None);
    }
    if trimmed_fast.starts_with(';') {
        return (None, None, Some(line.to_string()));
    }

    let mut in_quotes = false;
    let mut escaped = false;
    let mut comment_idx = None;
    let mut equal_idx = None;

    for (idx, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
        } else if c == '"' {
            in_quotes = !in_quotes;
        } else if !in_quotes {
            if c == ';' {
                comment_idx = Some(idx);
                break;
            } else if c == '=' && equal_idx.is_none() {
                equal_idx = Some(idx);
            }
        }
    }

    let (content_part, comment_part) = if let Some(c_idx) = comment_idx {
        (&line[..c_idx], Some(line[c_idx..].to_string()))
    } else {
        (line, None)
    };

    let trimmed_content = content_part.trim();
    if trimmed_content.starts_with(';') || trimmed_content.is_empty() {
        return (None, None, comment_part);
    }

    if let Some(eq_idx) = equal_idx {
        if eq_idx < content_part.len() {
            let key = line[..eq_idx].trim().to_string();
            let end_idx = comment_idx.unwrap_or(line.len());
            let val = line[eq_idx + 1..end_idx].trim().to_string();
            return (Some(key), Some(val), comment_part);
        }
    }

    (None, None, comment_part)
}
