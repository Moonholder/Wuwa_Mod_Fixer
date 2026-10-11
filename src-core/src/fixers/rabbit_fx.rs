use std::collections::HashMap;

use log::info;

use crate::{
    domain::pipeline::{PipelineFixer, PipelineStage},
    errors::FixerError,
    fixers::traits::FixerContext,
    utils::regex_patterns::*,
};

pub struct RabbitFxFixer;

const MAT_TYPE_MAP: &[(&str, &str)] = &[
    ("D", "Diffuse"),
    ("N", "Normalmap"),
    ("L", "Lightmap"),
    ("M", "Materialmap"),
    ("C", "Cutoutmap"),
    ("S", "Specialmap"),
];

impl PipelineFixer for RabbitFxFixer {
    fn name(&self) -> &'static str {
        "RabbitFxFixer"
    }

    fn stage(&self) -> PipelineStage {
        PipelineStage::MeshGated
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        if !ctx.mod_ctx.enable_stable_texture {
            return Ok(false);
        }
        let mut modified = false;

        // Legacy replacement (ps-t17 -> GlowMap, ps-t18 -> FXMap)
        modified |= self.replace_legacy_rabbit_fx_resources(ctx);

        let mut comp_map: HashMap<u32, String> = HashMap::new();

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
                self.try_inject_resource(ctx, hash, mat_type, comp_id, &mut comp_map);
            }
        }

        for (comp_id, insert_data) in comp_map {
            if let Some(mut comp_view) = ctx.ini_mut().as_component_mut(comp_id) {
                if comp_view.inject_rabbit_fx_block(&insert_data) {
                    info!("RabbitFX Update: Component {}, inserted logic block.", comp_id);
                    modified = true;
                }
            }
        }

        if modified {
            ctx.mark_ini_modified();
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
        let target_prefix = format!("resource\\rabbitfx\\{}", mat_type.to_lowercase());
        lines.iter().any(|l| {
            let trimmed = l.trim().to_lowercase();
            if let Some(rest) = trimmed.strip_prefix(&target_prefix) {
                rest.trim_start().starts_with('=')
            } else {
                false
            }
        })
    }

    fn try_inject_resource(
        &self,
        ctx: &FixerContext,
        hash: &str,
        mat_type: &str,
        comp_id: u32,
        comp_map: &mut HashMap<u32, String>,
    ) {
        let target_section_name = format!("TextureOverrideComponent{}", comp_id);
        let sec = match ctx.ini().get_section(&target_section_name) {
            Some(s) => s,
            None => return,
        };

        if Self::has_rabbitfx_resource(&sec.lines, mat_type) {
            return;
        }

        let texture_sec = match ctx.ini().find_texture_override_by_hash(hash) {
            Some(s) => s,
            None => return,
        };

        let mut cf = texture_sec.to_control_flow();
        cf.retain_resource_bindings_only();
        cf.strip_outer_object_detected();
        cf.transform_resource_bindings(|key, val| {
            if key.eq_ignore_ascii_case("this") {
                let clean = val.trim().replace('"', "");
                let res_name = clean.strip_prefix("ref ").unwrap_or(&clean).trim();
                Some(format!("ref {}", res_name))
            } else {
                None
            }
        });

        // Rename key directly on AST to target resource reference path.
        cf.rename_key("this", &format!("Resource\\RabbitFX\\{}", mat_type));

        let condition_lines = cf.to_lines();
        if !condition_lines.is_empty() && Self::has_rabbitfx_resource(&condition_lines, mat_type) {
            let block_str = condition_lines.join("\n");
            let entry = comp_map.entry(comp_id).or_default();
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
        for section in &mut ctx.ini_mut().sections {
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
}
