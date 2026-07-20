// src-core/src/fixers/text_replace/hash_replace.rs

use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use crate::utils::ini_parser::parse_line;
use log::info;
use std::collections::HashMap;

pub struct HashReplaceFixer;

impl Fixer for HashReplaceFixer {
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let mut modified = false;

        let mut replace_map: HashMap<String, String> = HashMap::new();
        for hr in &ctx.config.main_hashes {
            for old in &hr.old {
                if old != &hr.new {
                    replace_map.insert(old.to_lowercase(), hr.new.clone());
                }
            }
        }
        for (new_hash, texture_node) in &ctx.config.textures {
            for old in &texture_node.replace {
                if old != new_hash {
                    replace_map.insert(old.to_lowercase(), new_hash.clone());
                }
            }
        }

        if replace_map.is_empty() {
            return Ok(false);
        }

        let replace_line = |line: &mut String| -> bool {
            let is_comment = line.trim_start().starts_with(';');

            let (clean_line, comment_prefix) = if is_comment {
                let prefix: String = line.chars().take_while(|&c| c.is_whitespace() || c == ';').collect();
                (&line[prefix.len()..], Some(prefix))
            } else {
                (line.as_str(), None)
            };

            let (k, v, comment) = parse_line(clean_line);

            if let (Some(key), Some(val)) = (k, v) {
                if key.eq_ignore_ascii_case("hash") {
                    if let Some(new_hash) = replace_map.get(&val.to_lowercase()) {
                        if let Some(ref prefix) = comment_prefix {
                            if let Some(comm) = comment {
                                *line = format!("{}hash = {} {}", prefix, new_hash, comm);
                            } else {
                                *line = format!("{}hash = {}", prefix, new_hash);
                            }
                        } else {
                            let indent: String = line
                                .chars()
                                .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                                .collect();

                            if let Some(comm) = comment {
                                *line = format!("{}hash = {} {}", indent, new_hash, comm);
                            } else {
                                *line = format!("{}hash = {}", indent, new_hash);
                            }
                        }
                        info!("{} -> {}", val, new_hash);
                        return true;
                    }
                }
            }
            false
        };

        for line in &mut ctx.ini.pre_lines {
            if replace_line(line) {
                modified = true;
            }
        }

        for section in &mut ctx.ini.sections {
            for line in &mut section.lines {
                if replace_line(line) {
                    modified = true;
                }
            }
        }

        Ok(modified)
    }
}
