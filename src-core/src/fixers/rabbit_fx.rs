use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use crate::utils::regex_patterns::*;
use log::info;

pub struct RabbitFxFixer;

impl Fixer for RabbitFxFixer {
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        if !ctx.enable_stable_texture {
            return Ok(false);
        }
        let mut modified = false;

        // Legacy replacement (ps-t17 -> GlowMap, ps-t18 -> FXMap)
        modified |= self.replace_legacy_rabbit_fx_resources(ctx);

        let mut comp_map: std::collections::HashMap<char, String> = std::collections::HashMap::new();

        for (hash, texture_node) in &ctx.config.textures {
            if let Some(meta) = &texture_node.meta {
                let comp_char = std::char::from_digit(meta.id, 10).unwrap_or('?');
                if comp_char == '?' {
                    continue;
                }

                let mat_type = match meta.type_.as_str() {
                    "D" => "Diffuse",
                    "N" => "Normalmap",
                    "L" => "Lightmap",
                    "M" => "Materialmap",
                    "C" => "Cutoutmap",
                    "S" => "Specialmap",

                    _ => continue,
                };

                let target_section_name = format!("TextureOverrideComponent{}", comp_char);
                if let Some(sec) = ctx.ini.get_section(&target_section_name) {
                    let has_resource = match mat_type {
                        "Diffuse" => sec.lines.iter().any(|l| RE_RABBITFX_DIFFUSE.is_match(l)),
                        "Normalmap" => sec.lines.iter().any(|l| RE_RABBITFX_NORMALMAP.is_match(l)),
                        "Lightmap" => sec.lines.iter().any(|l| RE_RABBITFX_LIGHTMAP.is_match(l)),
                        "Materialmap" => sec.lines.iter().any(|l| RE_RABBITFX_MATERIALMAP.is_match(l)),
                        "Cutoutmap" => sec.lines.iter().any(|l| RE_RABBITFX_CUTOUTMAP.is_match(l)),
                        "Specialmap" => sec.lines.iter().any(|l| RE_RABBITFX_SPECIALMAP.is_match(l)),
                        _ => false,
                    };

                    if has_resource {
                        continue; // Already injected
                    }

                    // Look for the `hash = ...` inside `TextureOverride...` section matching this hash.
                    if let Some(texture_sec) = ctx.ini.sections.iter().find(|s| {
                        s.name.starts_with("TextureOverride")
                            && !s.name.starts_with("TextureOverrideComponent")
                            && !s.name.starts_with("TextureOverrideShapeKey")
                            && s.get_value("hash").map_or(false, |h| h.eq_ignore_ascii_case(hash))
                    }) {
                        // Extract conditions while preserving relative hierarchy and indentations
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
                }
            }
        }

        for (comp_no, insert_data) in comp_map {
            modified |= self.insert_into_component(ctx, comp_no, &insert_data);
        }

        Ok(modified)
    }
}

impl RabbitFxFixer {
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

    fn insert_into_component(&self, ctx: &mut FixerContext, component_no: char, insert_content: &str) -> bool {
        let target_section_name = format!("TextureOverrideComponent{}", component_no);
        let run_cmd = "run = Commandlist\\RabbitFX\\SetTextures";

        if let Some(sec) = ctx.ini.get_section_mut(&target_section_name) {
            let mut insert_idx = sec.lines.len();
            let mut append_run = false;

            // Find run = Commandlist\RabbitFX\SetTextures
            if let Some(idx) = sec.lines.iter().position(|l| RE_RUN_CMD.is_match(l)) {
                insert_idx = idx;
            } else {
                // Find handling = skip
                if let Some(idx) = sec.lines.iter().position(|l| RE_HANDLING_SKIP.is_match(l)) {
                    insert_idx = idx + 1;
                }
                append_run = true;
            }

            let base_indent = if insert_idx > 0 && insert_idx <= sec.lines.len() {
                let ref_line = &sec.lines[insert_idx - 1];
                let ind: String = ref_line
                    .chars()
                    .take_while(|c| c.is_whitespace() && *c != '\r' && *c != '\n')
                    .collect();
                if ind.is_empty() { "        ".to_string() } else { ind }
            } else {
                "        ".to_string()
            };

            let mut block = Vec::new();
            for line in insert_content.lines() {
                if !line.trim().is_empty() {
                    block.push(format!("{}{}", base_indent, line));
                }
            }
            if append_run {
                block.push(format!("{}{}", base_indent, run_cmd));
            }

            // Insert block into sec.lines at insert_idx
            sec.lines.splice(insert_idx..insert_idx, block);
            info!("RabbitFX Update: Component {}, inserted logic block.", component_no);
            return true;
        }

        false
    }
}
