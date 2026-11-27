// src-core/src/slot_fix/anchor.rs

use serde::{Deserialize, Serialize};

/// Marker that identifies one of our anchor comments.
pub const WMF_ANCHOR_MARKER: &str = "@wmf(";

/// Parsed `; @wmf(...)` anchor payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WmfAnchor {
    pub rule_id: String,
    pub rev: u32,
    #[serde(default)]
    pub base_rev: u32,
    /// The slot this statement had before the first time this tool touched it.
    pub orig_slot: String,
    pub sig: String,
}

/// Computes the fingerprint of a statement line.
///
/// All whitespace is removed and everything is lowercased, so cosmetic
/// re-indentation never invalidates an anchor, while any semantic edit made by
/// the user does.
pub fn compute_stmt_sig(code: &str) -> String {
    let norm: String = code
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let crc = crc32fast::hash(norm.as_bytes());
    format!("{:08x}", crc)
}

/// Returns the leading whitespace of a line (never includes `\r` / `\n`).
pub fn indent_of(line: &str) -> &str {
    &line[..line.len() - line.trim_start().len()]
}

/// Parses a standalone `; @wmf(...)` anchor line.
///
/// Returns `None` for anything that is not exclusively our anchor comment, so a
/// normal comment, a blank line or a statement can never be mistaken for one.
pub fn parse_wmf_anchor_line(raw_line: &str) -> Option<WmfAnchor> {
    let trimmed = raw_line.trim();
    if !trimmed.starts_with(';') {
        return None;
    }
    let marker_idx = trimmed.find(WMF_ANCHOR_MARKER)?;
    if !trimmed[1..marker_idx].trim().is_empty() {
        return None;
    }
    let inner = trimmed[marker_idx + WMF_ANCHOR_MARKER.len()..].trim_end();
    let inner = inner.strip_suffix(')')?;
    // Anything else after the closing parenthesis would mean a second statement.
    if inner.contains(')') {
        return None;
    }

    let mut rule_id = None;
    let mut rev = None;
    let mut base_rev = None;
    let mut orig_slot = None;
    let mut sig = None;

    for kv in inner.split(',') {
        if let Some((k, v)) = kv.split_once('=') {
            match k.trim() {
                "rule" => rule_id = Some(v.trim().to_string()),
                "rev" => rev = v.trim().parse::<u32>().ok(),
                "base_rev" => base_rev = v.trim().parse::<u32>().ok(),
                "orig" => orig_slot = Some(v.trim().to_ascii_lowercase()),
                "sig" => sig = Some(v.trim().to_ascii_lowercase()),
                _ => {}
            }
        }
    }

    match (rule_id, rev, orig_slot, sig) {
        (Some(rule_id), Some(rev), Some(orig_slot), Some(sig)) => Some(WmfAnchor {
            rule_id,
            rev,
            base_rev: base_rev.unwrap_or(0),
            orig_slot,
            sig,
        }),
        _ => None,
    }
}

/// Renders the standalone anchor comment line for a statement.
///
/// `indent` must be the statement's own leading whitespace.
pub fn format_wmf_anchor_line(indent: &str, anchor: &WmfAnchor) -> String {
    format!(
        "{indent}; {WMF_ANCHOR_MARKER}rule={},rev={},base_rev={},orig={},sig={})",
        anchor.rule_id, anchor.rev, anchor.base_rev, anchor.orig_slot, anchor.sig
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_roundtrip_on_preceding_line() {
        let code = "    ps-t7 = ResourceFx";
        let sig = compute_stmt_sig(code);
        let anchor_line = format_wmf_anchor_line(
            indent_of(code),
            &WmfAnchor {
                rule_id: "r".into(),
                rev: 2,
                base_rev: 1,
                orig_slot: "ps-t6".into(),
                sig: sig.clone(),
            },
        );
        assert_eq!(anchor_line, format!("    ; @wmf(rule=r,rev=2,base_rev=1,orig=ps-t6,sig={sig})"));
        let parsed = parse_wmf_anchor_line(&anchor_line).unwrap();
        assert_eq!(parsed.rule_id, "r");
        assert_eq!(parsed.rev, 2);
        assert_eq!(parsed.base_rev, 1);
        assert_eq!(parsed.orig_slot, "ps-t6");
        assert_eq!(parsed.sig, sig);
        assert_eq!(indent_of(&anchor_line), indent_of(code), "indent must be mirrored");
    }

    #[test]
    fn anchor_backward_compat_defaults_base_rev_to_zero() {
        let raw = "; @wmf(rule=r,rev=1,orig=ps-t6,sig=12345678)";
        let parsed = parse_wmf_anchor_line(raw).unwrap();
        assert_eq!(parsed.rule_id, "r");
        assert_eq!(parsed.rev, 1);
        assert_eq!(parsed.base_rev, 0);
        assert_eq!(parsed.orig_slot, "ps-t6");
        assert_eq!(parsed.sig, "12345678");
    }

    #[test]
    fn anchor_parser_rejects_non_anchor_lines() {
        assert!(parse_wmf_anchor_line("; a normal comment").is_none());
        assert!(parse_wmf_anchor_line("; note: @wmf(rule=r,rev=1,orig=ps-t6,sig=12345678)").is_none());
        assert!(parse_wmf_anchor_line("ps-t7 = ResourceFx").is_none());
        assert!(parse_wmf_anchor_line("; @wmf(rule=r,rev=1,orig=ps-t6)").is_none());
        assert!(parse_wmf_anchor_line("  ").is_none());
    }

    #[test]
    fn sig_ignores_whitespace_and_case() {
        assert_eq!(
            compute_stmt_sig("ps-t7 = ResourceFx"),
            compute_stmt_sig("    PS-T7=ResourceFx   ")
        );
    }
}
