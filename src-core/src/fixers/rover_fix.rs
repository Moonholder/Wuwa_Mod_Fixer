// src-core/src/fixers/rover_fix.rs
// Backward compatibility module forwarding RoverFixer to HairFixer.

use crate::{
    domain::pipeline::{PipelineFixer, PipelineStage},
    errors::FixerError,
    fixers::{hair_fix::HairFixer, traits::FixerContext},
};

pub struct RoverFixer;

impl PipelineFixer for RoverFixer {
    fn name(&self) -> &'static str {
        "RoverFixer"
    }

    fn stage(&self) -> PipelineStage {
        PipelineStage::MeshGated
    }

    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        HairFixer.run(ctx)
    }
}
