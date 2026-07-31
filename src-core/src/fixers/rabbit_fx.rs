use std::collections::HashMap;

use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use crate::utils::regex_patterns::*;
use log::info;
use regex::Regex;

pub struct RabbitFxFixer;

const MAT_TYPE_MAP: &[(&str, &str)] = &[
    ("D", "Diffuse"),
    ("N", "Normalmap"),
    ("L", "Lightmap"),
    ("M", "Materialmap"),
    ("C", "Cutoutmap"),
    ("S", "Specialmap"),
];

impl Fixer for RabbitFxFixer {
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        if !ctx.enable_stable_texture {
            return Ok(false);
        }
        let mut modified = false;

        // Legacy replacement (ps-t17 -> GlowMap, ps-t18 -> FXMap)
        modified |= self.replace_legacy_rabbit_fx_resources(ctx);

        let mut comp_map: HashMap<char, String> = HashMap::new();

        for (hash, texture_node) in &ctx.config.textures {
            let meta = match &texture_node.meta {
                Some(m) => m,
                None => continue,
            };

            let mat_type = match Self::resolve_mat_type(&meta.type_) {
                Some(t) => t,
                None => continue,
            };

            for &comp_id in &meta.id {
                let comp_char = match std::char::from_digit(comp_id, 10) {
                    Some(c) => c,
                    None => continue,
                };

                self.try_inject_resource(ctx, hash, mat_type, comp_char, &mut comp_map);
            }
        }

        for (comp_no, insert_data) in comp_map {
            modified |= self.insert_into_component(ctx, comp_no, &insert_data);
        }

        Ok(modified)
    }
}

impl RabbitFxFixer {
    fn resolve_mat_type(type_code: &str) -> Option<&'static str> {
        MAT_TYPE_MAP
            .iter()
            .find(|(code, _)| *code == type_code)
            .map(|(_, name)| *name)
    }

    fn has_rabbitfx_resource(lines: &[String], mat_type: &str) -> bool {
        let pattern = format!(r"(?i)Resource\\RabbitFX\\{}\s*=", regex::escape(mat_type));
        let re = Regex::new(&pattern).unwrap();
        lines.iter().any(|l| re.is_match(l))
    }

    fn try_inject_resource(
        &self,
        ctx: &FixerContext,
        hash: &str,
        mat_type: &str,
        comp_char: char,
        comp_map: &mut HashMap<char, String>,
    ) {
        let target_section_name = format!("TextureOverrideComponent{}", comp_char);
        let sec = match ctx.ini.get_section(&target_section_name) {
            Some(s) => s,
            None => return,
        };

        if Self::has_rabbitfx_resource(&sec.lines, mat_type) {
            return;
        }

        let texture_sec = match ctx.ini.sections.iter().find(|s| {
            s.name.starts_with("TextureOverride")
                && !s.name.starts_with("TextureOverrideComponent")
                && !s.name.starts_with("TextureOverrideShapeKey")
                && s.get_value("hash").map_or(false, |h| h.eq_ignore_ascii_case(hash))
        }) {
            Some(s) => s,
            None => return,
        };

        let condition_lines = texture_sec.extract_control_flow_and_resources(|indent, key, val| {
            if key.eq_ignore_ascii_case("this") {
                let clean_res_name = val.trim().replace('"', "");
                if let Some(resource_name) = clean_res_name.split_whitespace().next() {
                    return Some(format!(
                        "{}Resource\\RabbitFX\\{} = ref {}",
                        indent, mat_type, resource_name
                    ));
                }
            }
            None
        });

        if !condition_lines.is_empty() {
            let block_str = condition_lines.join("\n");
            let entry = comp_map.entry(comp_char).or_default();
            if !entry.is_empty() && !entry.ends_with('\n') {
                entry.push('\n');
            }
            entry.push_str(&block_str);
            entry.push('\n');
        }
    }

    /// Replace legacy rabbit fx resources
    fn replace_legacy_rabbit_fx_resources(&self, ctx: &mut FixerContext) -> bool {
        let mut modified = false;
        for section in &mut ctx.ini.sections {
            for line in &mut section.lines {
                if RE_T17.is_match(line) {
                    let replaced = RE_T17.replace(line, "${1}Resource\\RabbitFX\\GlowMap = ref ${2}");
                    *line = replaced.to_string();
                    modified = true;
                }
                if RE_T18.is_match(line) {
                    let replaced = RE_T18.replace(line, "${1}Resource\\RabbitFX\\FXMap = ref ${2}");
                    *line = replaced.to_string();
                    modified = true;
                }
            }
        }
        if modified {
            info!("RabbitFX legacy resources updated.");
        }
        modified
    }

    /// 将收集到的资源引用块插入到目标 Component section
    fn insert_into_component(&self, ctx: &mut FixerContext, component_no: char, insert_content: &str) -> bool {
        let target_section_name = format!("TextureOverrideComponent{}", component_no);
        let run_cmd = "run = Commandlist\\RabbitFX\\SetTextures";

        let sec = match ctx.ini.get_section_mut(&target_section_name) {
            Some(s) => s,
            None => return false,
        };

        let mut insert_idx = sec.lines.len();
        let mut append_run = false;

        // Find run = Commandlist\RabbitFX\SetTextures
        if let Some(idx) = sec.lines.iter().position(|l| RE_RUN_CMD.is_match(l)) {
            insert_idx = idx;
        } else {
            // If not found, insert after handling = skip and append run command
            if let Some(idx) = sec.lines.iter().position(|l| RE_HANDLING_SKIP.is_match(l)) {
                insert_idx = idx + 1;
            }
            append_run = true;
        }

        let base_indent = Self::detect_indent(&sec.lines, insert_idx);

        let mut block: Vec<String> = insert_content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| format!("{}{}", base_indent, line))
            .collect();

        if append_run {
            block.push(format!("{}{}", base_indent, run_cmd));
        }

        sec.lines.splice(insert_idx..insert_idx, block);
        info!("RabbitFX Update: Component {}, inserted logic block.", component_no);
        true
    }

    fn detect_indent(lines: &[String], insert_idx: usize) -> String {
        const DEFAULT_INDENT: &str = "        ";
        if insert_idx == 0 || insert_idx > lines.len() {
            return DEFAULT_INDENT.to_string();
        }
        let ref_line = &lines[insert_idx - 1];
        let ind: String = ref_line
            .chars()
            .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
            .collect();
        if ind.is_empty() {
            DEFAULT_INDENT.to_string()
        } else {
            ind
        }
    }
}
