// src-core/src/fixers/slot_fix/pipeline.rs

use crate::{
    domain::pipeline::{PipelineFixer, PipelineStage},
    errors::FixerError,
    fixers::traits::FixerContext,
};

use super::engine::apply_to_document;

pub struct SlotFixFixer;

impl PipelineFixer for SlotFixFixer {
    fn name(&self) -> &'static str {
        "SlotFixFixer"
    }

    fn stage(&self) -> PipelineStage {
        // Step 2 of the documented pipeline sits between Step 1 (hash replacement)
        // and the mesh-gated specialisation fixers, which is exactly where the
        // pre-process group is ordered in `FixerPipeline::production`.
        PipelineStage::PreProcess
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let Some(rule) = &ctx.config.slot_fix else {
            return Ok(false);
        };
        let config = ctx.config;

        let outcome = {
            let co_mutated = &ctx.mod_ctx.co_mutated_sections;
            let file_path = &ctx.mod_ctx.file_path;
            let session = &ctx.mod_ctx.slot_session;
            let ini = &mut ctx.mod_ctx.ini;
            apply_to_document(ini, rule, config, co_mutated, file_path, session)
        };

        if outcome.shifted > 0 || outcome.pinned > 0 || outcome.upgraded > 0 {
            let message = crate::tr!(
                format!(
                    "槽位修复 [{}]: 移位 {} 行, 补齐锚点 {} 行, 规则升级 {} 行",
                    rule.rule_id, outcome.shifted, outcome.pinned, outcome.upgraded
                ),
                format!(
                    "Slot fix [{}]: {} shifted, {} pinned, {} upgraded",
                    rule.rule_id, outcome.shifted, outcome.pinned, outcome.upgraded
                ),
            );
            log::info!("{}", message);
        }

        if outcome.modified {
            ctx.mark_ini_modified();
        }

        Ok(outcome.modified)
    }
}
