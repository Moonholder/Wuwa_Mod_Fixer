// src-core/src/utils/ini_parser.rs

pub use crate::domain::{
    control_flow::{ConditionBranch, ControlFlowBlock, Statement},
    cst::{IniCstDocument as IniDocument, IniCstSection as IniSection},
};

/// Zero-allocation line parser returning optional slices for key, value, and comment.
#[inline(always)]
pub fn parse_line_ref<'a>(line: &'a str) -> (Option<&'a str>, Option<&'a str>, Option<&'a str>) {
    let trimmed_fast = line.trim_start();

    if trimmed_fast.is_empty() {
        return (None, None, None);
    }
    if trimmed_fast.starts_with(';') {
        return (None, None, Some(line));
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

    let content_part = if let Some(c_idx) = comment_idx {
        &line[..c_idx]
    } else {
        line
    };

    let comment_part = comment_idx.map(|c_idx| &line[c_idx..]);

    let trimmed_content = content_part.trim();
    if trimmed_content.starts_with(';') || trimmed_content.is_empty() {
        return (None, None, comment_part);
    }

    if let Some(eq_idx) = equal_idx {
        if eq_idx < content_part.len() {
            let key = line[..eq_idx].trim();
            let end_idx = comment_idx.unwrap_or(line.len());
            let val = line[eq_idx + 1..end_idx].trim();
            return (Some(key), Some(val), comment_part);
        }
    }

    (None, None, comment_part)
}

pub fn parse_line(line: &str) -> (Option<String>, Option<String>, Option<String>) {
    let (k, v, c) = parse_line_ref(line);
    (
        k.map(|s| s.to_string()),
        v.map(|s| s.to_string()),
        c.map(|s| s.to_string()),
    )
}
