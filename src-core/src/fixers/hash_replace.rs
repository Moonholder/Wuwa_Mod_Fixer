// src-core/src/fixers/hash_replace.rs

use std::collections::HashMap;

use log::info;

use crate::{
    domain::pipeline::{PipelineFixer, PipelineStage},
    errors::FixerError,
    fixers::traits::FixerContext,
};

pub struct HashReplaceFixer;

impl PipelineFixer for HashReplaceFixer {
    fn name(&self) -> &'static str {
        "HashReplaceFixer"
    }

    fn stage(&self) -> PipelineStage {
        PipelineStage::PreProcess
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
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

        // Snapshot the per-section `hash` values so that the slots rewritten here
        // can be reported as "co-mutated" to the slot-fix Level 2 short-circuit.
        // A component whose `vb0` was just migrated from an old to a new hash is
        // 100% an un-fixed old component, which lets a lone `ps-t7` be resolved
        // without any guessing.
        let before: Vec<String> = ctx
            .ini()
            .sections
            .iter()
            .map(|sec| sec.get_value("hash").unwrap_or_default())
            .collect();

        let modified = ctx.ini_mut().replace_key_values("hash", |val| {
            replace_map.get(&val.to_lowercase()).map(|new_hash| {
                info!("{} -> {}", val, new_hash);
                new_hash.clone()
            })
        });

        if modified {
            let mut co_mutated = Vec::new();
            for (idx, sec) in ctx.mod_ctx.ini.sections.iter().enumerate() {
                let after = sec.get_value("hash").unwrap_or_default();
                if before.get(idx).map(|b| b != &after).unwrap_or(false) {
                    co_mutated.push(sec.name.clone());
                }
            }
            for name in co_mutated {
                ctx.mod_ctx.co_mutated_sections.insert(name);
            }
            ctx.mark_ini_modified();
        }

        Ok(modified)
    }
}
