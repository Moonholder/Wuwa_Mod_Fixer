// src-core/src/fixers/text_replace/rule_replace.rs

use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use crate::utils::ini_parser::parse_line;
use crate::utils::regex_patterns::RE_CHECKSUM;
use log::info;

pub struct RuleReplaceFixer;

impl Fixer for RuleReplaceFixer {
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let mut modified = false;

        if let Some(checksum) = &ctx.config.checksum {
            for section in &mut ctx.ini.sections {
                for line in &mut section.lines {
                    if RE_CHECKSUM.is_match(line) {
                        let replaced = RE_CHECKSUM.replace(line, format!("checksum = {}", checksum).as_str());
                        if replaced != *line {
                            *line = replaced.to_string();
                            modified = true;
                        }
                    }
                }
            }
        }

        if let Some(rules) = &ctx.config.rules {
            if !rules.is_empty() {
                let mut consumed: Vec<Vec<bool>> = rules.iter().map(|r| vec![false; r.replacements.len()]).collect();

                let mut global_line_num = 0;
                for section in &mut ctx.ini.sections {
                    for line in &mut section.lines {
                        global_line_num += 1;
                        let mut line_replaced = false;

                        let (k, v, _) = parse_line(line);

                        if let (Some(key_str), Some(val_str)) = (k, v) {
                            let key_trimmed = key_str.trim();

                            let matched_indices: Vec<usize> = rules
                                .iter()
                                .enumerate()
                                .filter(|(_, r)| r.line_prefix == key_trimmed)
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
                                        .filter(|(i, _)| !consumed[rule_idx][*i])
                                        .find_map(|(i, repl)| {
                                            if let Some(old_val) =
                                                repl.old.iter().find(|old_val| old_val.as_str() == raw_value)
                                            {
                                                return Some((i, Some(old_val), repl));
                                            }
                                            if raw_value == repl.new.as_str() {
                                                return Some((i, None, repl));
                                            }
                                            None
                                        });

                                    if let Some((repl_idx, matched_old, replacement)) = matched_replacement {
                                        if let Some(old_val) = matched_old {
                                            if let Some(eq_idx) = line.find('=') {
                                                if let Some(val_offset) = line[eq_idx + 1..].find(raw_value) {
                                                    let val_idx = eq_idx + 1 + val_offset;

                                                    let mut new_line = String::with_capacity(line.len());
                                                    new_line.push_str(&line[..val_idx]);
                                                    new_line.push_str(&replacement.new);
                                                    new_line.push_str(&line[val_idx + old_val.len()..]);
                                                    *line = new_line;

                                                    info!("[L{}] {} -> {}", global_line_num, old_val, replacement.new);
                                                    modified = true;
                                                    line_replaced = true;
                                                }
                                            }
                                        }

                                        consumed[rule_idx][repl_idx] = true;

                                        if line_replaced {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(modified)
    }
}
