// src-core/src/domain/mod.rs

pub mod context;
pub mod control_flow;
pub mod cst;
pub mod pipeline;
pub mod sections;

pub use context::ModContext;
pub use control_flow::{ConditionBranch, ControlFlowBlock, Statement};
pub use cst::{IniCstDocument, IniCstSection};
pub use pipeline::{FixerPipeline, FixerPipelineBuilder, PipelineFixer, PipelineStage};
pub use sections::*;
