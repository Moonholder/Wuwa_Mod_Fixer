// src-core/src/fixers/rule_replace.rs

use log::info;

use crate::{
    config_loader::{Replacement, ReplacementRule},
    domain::pipeline::{PipelineFixer, PipelineStage},
    errors::FixerError,
    fixers::traits::FixerContext,
    utils::ini_parser::parse_line,
};

pub struct RuleReplaceFixer;

impl PipelineFixer for RuleReplaceFixer {
    fn name(&self) -> &'static str {
        "RuleReplaceFixer"
    }

    fn stage(&self) -> PipelineStage {
        PipelineStage::MeshGated
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let mut all_rules = Vec::new();

        // Map standalone checksum configurations into unconditional replacement rules
        // (empty `old` matches any existing value) to leverage the general replacement pipeline.
        if let Some(checksum) = &ctx.config.checksum {
            all_rules.push(ReplacementRule {
                line_prefix: r"$\WWMIv1\shapekey_checksum".to_string(),
                replacements: vec![Replacement {
                    old: vec![],
                    new: checksum.clone(),
                }],
            });
            all_rules.push(ReplacementRule {
                line_prefix: "shapekey_checksum".to_string(),
                replacements: vec![Replacement {
                    old: vec![],
                    new: checksum.clone(),
                }],
            });
        }

        // Append general replacement rules configured in config.rules.
        if let Some(rules) = &ctx.config.rules {
            all_rules.extend(rules.clone());
        }

        if all_rules.is_empty() {
            return Ok(false);
        }

        let modified = Self::apply_replacement_rules(ctx, &all_rules);

        if modified {
            ctx.mark_ini_modified();
        }

        Ok(modified)
    }
}

impl RuleReplaceFixer {
    /// Applies configured replacement rules, matching key-value pairs and tracking single-use consumption state.
    fn apply_replacement_rules(ctx: &mut FixerContext, rules: &[ReplacementRule]) -> bool {
        let mut modified = false;
        let mut consumed: Vec<Vec<bool>> = rules.iter().map(|r| vec![false; r.replacements.len()]).collect();
        let mut global_line_num = 0;

        for section in &mut ctx.ini_mut().sections {
            for line in &mut section.lines {
                global_line_num += 1;
                let (k, v, _) = parse_line(line);

                if let (Some(key_str), Some(val_str)) = (k, v) {
                    let key_trimmed = key_str.trim();

                    let matched_indices: Vec<usize> = rules
                        .iter()
                        .enumerate()
                        .filter(|(_, r)| r.line_prefix.eq_ignore_ascii_case(key_trimmed))
                        .map(|(idx, _)| idx)
                        .collect();

                    for &rule_idx in &matched_indices {
                        let rule = &rules[rule_idx];
                        let raw_value = val_str.trim();

                        if !raw_value.is_empty() {
                            let matched_replacement = rule
                                .replacements
                                .iter()
                                .enumerate()
                                .filter(|(i, repl)| {
                                    // Wildcard rules are not locked by single-use consumption.
                                    repl.old.is_empty() || !consumed[rule_idx][*i]
                                })
                                .find_map(|(i, repl)| {
                                    // Wildcard rule: empty `old` unconditionally updates the current value to `new`.
                                    if repl.old.is_empty() {
                                        if raw_value == repl.new.as_str() {
                                            return Some((i, None, repl));
                                        } else {
                                            return Some((i, Some(raw_value), repl));
                                        }
                                    }

                                    if let Some(old_val) = repl.old.iter().find(|old_val| old_val.as_str() == raw_value)
                                    {
                                        return Some((i, Some(old_val.as_str()), repl));
                                    }
                                    if raw_value == repl.new.as_str() {
                                        return Some((i, None, repl));
                                    }
                                    None
                                });

                            if let Some((repl_idx, matched_old, replacement)) = matched_replacement {
                                if let Some(old_val) = matched_old {
                                    if let Some(eq_idx) = line.find('=') {
                                        if let Some(val_offset) = line[eq_idx + 1..].find(old_val) {
                                            let val_idx = eq_idx + 1 + val_offset;

                                            let mut new_line = String::with_capacity(line.len());
                                            new_line.push_str(&line[..val_idx]);
                                            new_line.push_str(&replacement.new);
                                            new_line.push_str(&line[val_idx + old_val.len()..]);
                                            *line = new_line;

                                            info!("[L{}] {} -> {}", global_line_num, old_val, replacement.new);
                                            modified = true;
                                        }
                                    }
                                }

                                if !rule.replacements[repl_idx].old.is_empty() {
                                    consumed[rule_idx][repl_idx] = true;
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
        modified
    }
}
