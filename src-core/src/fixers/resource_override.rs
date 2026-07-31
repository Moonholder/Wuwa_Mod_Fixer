// src-core/src/fixers/resource_override.rs

use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use log::info;
use std::collections::HashSet;

pub struct ResourceOverrideFixer;

impl Fixer for ResourceOverrideFixer {
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let mut required_slots = HashSet::new();

        for (hash_key, node) in &ctx.config.textures {
            let is_involved = ctx.original_hashes.contains(&hash_key.to_lowercase())
                || node
                    .replace
                    .iter()
                    .any(|h| ctx.original_hashes.contains(&h.to_lowercase()));

            if is_involved {
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

        let target_section = "CommandListTriggerResourceOverrides";

        let section = ctx.ini.add_section(target_section);
        let mut modified = false;

        let mut sorted_slots: Vec<u32> = required_slots.into_iter().collect();
        sorted_slots.sort_unstable();

        for slot in sorted_slots {
            let val = format!("ps-t{}", slot);

            let existing_values = section.get_all_values("CheckTextureOverride");
            let mut found = false;
            for v in existing_values {
                if v.eq_ignore_ascii_case(&val) {
                    found = true;
                    break;
                }
            }

            if !found {
                section.push_key_value_tight("CheckTextureOverride", &val, "");
                modified = true;
                info!("{}", crate::t!(resource_override_added, val = val));
            }
        }

        Ok(modified)
    }
}
