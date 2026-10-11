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

        let modified = ctx.ini_mut().replace_key_values("hash", |val| {
            replace_map.get(&val.to_lowercase()).map(|new_hash| {
                info!("{} -> {}", val, new_hash);
                new_hash.clone()
            })
        });

        if modified {
            ctx.mark_ini_modified();
        }

        Ok(modified)
    }
}
