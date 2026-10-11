// src-core/src/fixers/resource_override.rs

use std::collections::HashSet;

use log::info;

use crate::{
    domain::pipeline::{PipelineFixer, PipelineStage},
    errors::FixerError,
    fixers::traits::FixerContext,
};

pub struct ResourceOverrideFixer;

impl PipelineFixer for ResourceOverrideFixer {
    fn name(&self) -> &'static str {
        "ResourceOverrideFixer"
    }

    fn stage(&self) -> PipelineStage {
        PipelineStage::PostProcess
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let mut required_slots = HashSet::new();

        for (hash_key, node) in &ctx.config.textures {
            let in_original = ctx.original_hashes().contains(&hash_key.to_lowercase())
                || node
                    .replace
                    .iter()
                    .any(|h| ctx.original_hashes().contains(&h.to_lowercase()));

            let in_ini = ctx.ini().iter_texture_overrides().any(|sec| {
                sec.matches_texture_hash(hash_key) || node.replace.iter().any(|r| sec.matches_texture_hash(r))
            });

            if in_original || in_ini {
                if let Some(meta) = &node.meta {
                    if let Some(slots) = &meta.slot {
                        for &slot in slots {
                            required_slots.insert(slot);
                        }
                    }
                }
            }
        }

        if required_slots.is_empty() {
            return Ok(false);
        }

        let mut sorted_slots: Vec<u32> = required_slots.into_iter().collect();
        sorted_slots.sort_unstable();

        let mut modified = false;
        let mut cmd_view = ctx.ini_mut().ensure_command_list("CommandListTriggerResourceOverrides");

        for slot in sorted_slots {
            let val = format!("ps-t{}", slot);
            if cmd_view.ensure_check_texture_override(&val) {
                modified = true;
                info!("{}", crate::t!(resource_override_added, val = val));
            }
        }

        if modified {
            ctx.mark_ini_modified();
        }

        Ok(modified)
    }
}
