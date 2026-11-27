// src-core/src/slot_fix/statement.rs

use std::sync::LazyLock;
use regex::Regex;

/// `ps-t6 = ResourceFx`, `ps-t6 = ref ResourceFx`, `post ps-t7 = null`
static RE_SLOT_BIND: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(\s*(?:post\s+)?)((?:ps|vs|cs)-t\d+)(\s*=)").unwrap());
/// `if ps-t6 == 120`, `elif ps-t6 != 0`, `else if ps-t6 >= 3`
static RE_SLOT_COND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(\s*(?:else\s+if|elif|if)\s+)((?:ps|vs|cs)-t\d+)(\s*(?:==|!=|>=|<=|>|<))").unwrap()
});

/// A recognized slot reference inside a single statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotStatement {
    /// Lowercased slot identifier, e.g. `ps-t7`.
    pub slot: String,
    /// Byte span of the slot token inside the parsed statement.
    pub start: usize,
    pub end: usize,
}

impl SlotStatement {
    pub fn rewrite(&self, statement: &str, replacement: &str) -> String {
        let mut out = String::with_capacity(statement.len() + 4);
        out.push_str(&statement[..self.start]);
        out.push_str(replacement);
        out.push_str(&statement[self.end..]);
        out
    }
}

/// True for `checktextureoverride = ps-tN` / `check_texture_override = ps-tN`.
pub fn is_override_trigger_line(code: &str) -> bool {
    let lower = code.trim_start().to_ascii_lowercase();
    lower.starts_with("checktextureoverride") || lower.starts_with("check_texture_override")
}

/// Recognizes the statements this engine is allowed to rewrite.
pub fn parse_slot_statement(code: &str) -> Option<SlotStatement> {
    if is_override_trigger_line(code) {
        return None;
    }
    let trimmed = code.trim_end();

    for re in [&*RE_SLOT_BIND, &*RE_SLOT_COND] {
        let Some(caps) = re.captures(trimmed) else {
            continue;
        };
        let Some(m) = caps.get(2) else { continue };
        return Some(SlotStatement {
            slot: m.as_str().to_ascii_lowercase(),
            start: m.start(),
            end: m.end(),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_supported_statement_forms() {
        let cases = [
            ("ps-t6 = ResourceFx", "ps-t6"),
            ("ps-t9 = ResourceMask", "ps-t9"),
            ("ps-t6 = ref ResourceFx", "ps-t6"),
            ("post ps-t7 = null", "ps-t7"),
            ("if ps-t6 == 120", "ps-t6"),
            ("    elif ps-t9 != 0", "ps-t9"),
            ("else if ps-t6 >= 3", "ps-t6"),
        ];
        for (code, expected) in cases {
            let stmt = parse_slot_statement(code).unwrap_or_else(|| panic!("failed to parse: {code}"));
            assert_eq!(stmt.slot, expected, "statement: {code}");
        }
    }

    #[test]
    fn override_trigger_lines_are_never_treated_as_slot_statements() {
        assert!(parse_slot_statement("checktextureoverride = ps-t9").is_none());
        assert!(parse_slot_statement("CheckTextureOverride = ps-t0").is_none());
        assert!(parse_slot_statement("  check_texture_override = ps-t7").is_none());
    }

    #[test]
    fn ignores_unrelated_lines() {
        assert!(parse_slot_statement("hash = 91cff509").is_none());
        assert!(parse_slot_statement("filename = Textures/foo.dds").is_none());
        assert!(parse_slot_statement("ps-t0 = ResourceTexture0").is_some());
    }
}
