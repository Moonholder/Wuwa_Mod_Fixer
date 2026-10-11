// src-core/src/domain/pipeline.rs

use std::{
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};

use crate::{
    config_loader::CharacterConfig,
    domain::{context::ModContext, cst::IniCstDocument},
    errors::FixerError,
    fixers::traits::FixerContext,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PipelineStage {
    PreProcess = 1,
    FeatureAdapt = 2,
    MeshGated = 3,
    PostProcess = 4,
}

impl std::fmt::Display for PipelineStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PreProcess => write!(f, "PreProcess"),
            Self::FeatureAdapt => write!(f, "FeatureAdapt"),
            Self::MeshGated => write!(f, "MeshGated"),
            Self::PostProcess => write!(f, "PostProcess"),
        }
    }
}

pub trait PipelineFixer: Send + Sync {
    fn name(&self) -> &'static str;
    fn stage(&self) -> PipelineStage;
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError>;
}

#[derive(Debug, Clone, Default)]
pub struct PipelineExecutionResult {
    pub modified: bool,
    pub matched_characters: Vec<String>,
}

pub static PROF_FIXERS: std::sync::Mutex<Option<std::collections::HashMap<&'static str, (AtomicU64, AtomicU64)>>> =
    std::sync::Mutex::new(None);

pub fn init_prof() {
    let mut map = std::collections::HashMap::new();
    let names = [
        "HashReplaceFixer",
        "RuleReplaceFixer",
        "VertexRemapFixer",
        "Rendering33Fixer",
        "StrideFixer",
        "AeroFixer",
        "ShapeKeyFixer",
        "HairFixer",
        "RoverFixer",
        "MaterialmapFixer",
        "materialmap::read_dds",
        "materialmap::backup",
        "materialmap::export_jpeg",
        "RabbitFxFixer",
        "CutoutMaskFixer",
        "ResourceOverrideFixer",
        "DeriveRedirectFixer",
        "ModContext::new",
        "check_mesh_character_match",
        "commit",
        "find_potential_characters",
    ];
    for name in names {
        map.insert(name, (AtomicU64::new(0), AtomicU64::new(0)));
    }
    if let Ok(mut guard) = PROF_FIXERS.lock() {
        *guard = Some(map);
    }
}

pub fn print_prof() {
    if let Ok(guard) = PROF_FIXERS.lock() {
        if let Some(ref map) = *guard {
            log::debug!("\n================== TIMING BREAKDOWN ==================");
            let mut list: Vec<_> = map.iter().collect();
            list.sort_by_key(|(_, (us, _))| std::cmp::Reverse(us.load(Ordering::Relaxed)));
            for (name, (us, count)) in list {
                let total_us = us.load(Ordering::Relaxed);
                let cnt = count.load(Ordering::Relaxed);
                let ms = total_us as f64 / 1000.0;
                if total_us > 0 || cnt > 0 {
                    log::debug!(
                        "{:30} | total: {:10.2} ms | calls: {:5} | avg: {:8.2} us",
                        name,
                        ms,
                        cnt,
                        if cnt > 0 { total_us as f64 / cnt as f64 } else { 0.0 }
                    );
                }
            }
            log::debug!("======================================================\n");
        }
    }
}

pub fn record_prof(name: &'static str, us: u64) {
    if let Ok(guard) = PROF_FIXERS.lock() {
        if let Some(ref map) = *guard {
            if let Some((total_us, count)) = map.get(name) {
                total_us.fetch_add(us, Ordering::Relaxed);
                count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub struct FixerPipeline {
    preprocess_fixers: Vec<Box<dyn PipelineFixer>>,
    feature_fixers: Vec<Box<dyn PipelineFixer>>,
    mesh_fixers: Vec<Box<dyn PipelineFixer>>,
    postprocess_fixers: Vec<Box<dyn PipelineFixer>>,
}

impl FixerPipeline {
    pub fn new() -> Self {
        Self {
            preprocess_fixers: Vec::new(),
            feature_fixers: Vec::new(),
            mesh_fixers: Vec::new(),
            postprocess_fixers: Vec::new(),
        }
    }

    pub fn from_fixers(fixers: Vec<Box<dyn PipelineFixer>>) -> Self {
        let mut preprocess_fixers = Vec::new();
        let mut feature_fixers = Vec::new();
        let mut mesh_fixers = Vec::new();
        let mut postprocess_fixers = Vec::new();

        for fixer in fixers {
            match fixer.stage() {
                PipelineStage::PreProcess => preprocess_fixers.push(fixer),
                PipelineStage::FeatureAdapt => feature_fixers.push(fixer),
                PipelineStage::MeshGated => mesh_fixers.push(fixer),
                PipelineStage::PostProcess => postprocess_fixers.push(fixer),
            }
        }

        Self {
            preprocess_fixers,
            feature_fixers,
            mesh_fixers,
            postprocess_fixers,
        }
    }

    pub fn production() -> Self {
        use crate::fixers::{
            aero_fix::AeroFixer, cutout_mask::CutoutMaskFixer, hair_fix::HairFixer, hash_replace::HashReplaceFixer,
            materialmap::MaterialmapFixer, rabbit_fx::RabbitFxFixer, rendering_3_3::Rendering33Fixer,
            resource_override::ResourceOverrideFixer, rule_replace::RuleReplaceFixer, shapekey::ShapeKeyFixer,
            stride::StrideFixer, vertex_remap::VertexRemapFixer,
        };

        Self::from_fixers(vec![
            // Phase 1: PreProcess (unconditional hash replacement)
            Box::new(HashReplaceFixer),
            // Phase 2: FeatureAdapt (texture-fingerprint adaptation)
            Box::new(MaterialmapFixer),
            // Phase 3: MeshGated (strictly topological character mesh fixes)
            Box::new(RuleReplaceFixer),
            Box::new(VertexRemapFixer),
            Box::new(Rendering33Fixer),
            Box::new(StrideFixer),
            Box::new(AeroFixer),
            Box::new(ShapeKeyFixer),
            Box::new(HairFixer),
            Box::new(RabbitFxFixer),
            Box::new(CutoutMaskFixer),
            // Phase 4: PostProcess (resource slots)
            Box::new(ResourceOverrideFixer),
        ])
    }

    pub fn builder() -> FixerPipelineBuilder {
        FixerPipelineBuilder::new()
    }

    /// Orchestrates end-to-end multi-phase fixer pipeline execution
    pub fn execute(
        &self,
        mod_ctx: &mut ModContext,
        configs: &HashMap<String, CharacterConfig>,
        potential_chars: &[String],
        enable_texture_override: bool,
    ) -> Result<PipelineExecutionResult, FixerError> {
        let mut overall_modified = false;
        let mut matched_characters = Vec::new();

        // 1. PreProcess: Unconditional hash replacements across all potential characters
        for char_name in potential_chars {
            if let Some(config) = configs.get(char_name) {
                let mut ctx = FixerContext::new(mod_ctx, config, char_name);
                for fixer in &self.preprocess_fixers {
                    let t0 = std::time::Instant::now();
                    let res = fixer.run(&mut ctx)?;
                    record_prof(fixer.name(), t0.elapsed().as_micros() as u64);
                    if res {
                        overall_modified = true;
                    }
                }
            }
        }

        // 2. FeatureAdapt: Texture/feature-based adaptations (not gated by mesh matching)
        for char_name in potential_chars {
            if let Some(config) = configs.get(char_name) {
                let mut ctx = FixerContext::new(mod_ctx, config, char_name);
                for fixer in &self.feature_fixers {
                    let t0 = std::time::Instant::now();
                    let res = fixer.run(&mut ctx)?;
                    record_prof(fixer.name(), t0.elapsed().as_micros() as u64);
                    if res {
                        overall_modified = true;
                    }
                }
            }
        }

        // 3. MeshGated: Strictly gated by character main mesh verification
        for char_name in potential_chars {
            let Some(config) = configs.get(char_name) else {
                continue;
            };

            let t_cm = std::time::Instant::now();
            let is_match = self.check_mesh_match(&mod_ctx.ini, char_name, config);
            record_prof("check_mesh_character_match", t_cm.elapsed().as_micros() as u64);

            if is_match {
                matched_characters.push(char_name.clone());
                log::info!("{}", crate::t!(match_character_prompt, character = char_name));

                let mut ctx = FixerContext::new(mod_ctx, config, char_name);
                for fixer in &self.mesh_fixers {
                    let t0 = std::time::Instant::now();
                    let res = fixer.run(&mut ctx)?;
                    record_prof(fixer.name(), t0.elapsed().as_micros() as u64);
                    if res {
                        overall_modified = true;
                    }
                }
            }
        }

        // 4. PostProcess: Global multi-character aggregation & resource slot declarations
        let active_chars = if !matched_characters.is_empty() {
            &matched_characters[..]
        } else {
            potential_chars
        };

        // Multi-character derive redirects
        let cfg = crate::config_loader::config();
        let settings = cfg.settings_ref();
        let mut derive_configs = Vec::new();
        for char_name in active_chars {
            if enable_texture_override || settings.state_texture_removers.contains(char_name) {
                if let Some(c) = configs.get(char_name) {
                    derive_configs.push(c);
                }
            }
        }
        if !derive_configs.is_empty() {
            let t_dr = std::time::Instant::now();
            if crate::fixers::derive_redirect::DeriveRedirectFixer::run_multi(&mut mod_ctx.ini, &derive_configs)? {
                mod_ctx.mark_modified();
                overall_modified = true;
            }
            record_prof("DeriveRedirectFixer", t_dr.elapsed().as_micros() as u64);
        }

        // Individual post-process fixers
        for char_name in active_chars {
            if let Some(c) = configs.get(char_name) {
                let mut ctx = FixerContext::new(mod_ctx, c, char_name);
                for fixer in &self.postprocess_fixers {
                    let t0 = std::time::Instant::now();
                    let res = fixer.run(&mut ctx)?;
                    record_prof(fixer.name(), t0.elapsed().as_micros() as u64);
                    if res {
                        overall_modified = true;
                    }
                }
            }
        }

        Ok(PipelineExecutionResult {
            modified: overall_modified,
            matched_characters,
        })
    }

    /// Check if the INI contains mesh components for the given character
    pub fn check_mesh_match(&self, ini: &IniCstDocument, char_name: &str, config: &CharacterConfig) -> bool {
        let mut vb0_hashes = HashSet::new();
        let mut sk_hashes = HashSet::new();

        if let Some(vb0) = config.main_hashes.first() {
            for h in vb0.old.iter().chain(std::iter::once(&vb0.new)) {
                vb0_hashes.insert(h.to_lowercase());
            }
        }

        let global_cfg = crate::config_loader::config();
        let check_shape_key = global_cfg
            .settings_ref()
            .early_characters
            .iter()
            .any(|c| c == char_name);
        if check_shape_key {
            if let Some(sk) = config.main_hashes.get(1) {
                for h in sk.old.iter().chain(std::iter::once(&sk.new)) {
                    sk_hashes.insert(h.to_lowercase());
                }
            }
        }

        if vb0_hashes.is_empty() && sk_hashes.is_empty() {
            return false;
        }

        for sec in &ini.sections {
            let sec_name_lower = sec.name.to_lowercase();
            let is_component_like = sec_name_lower.contains("component")
                || (sec_name_lower.starts_with("textureoverride")
                    && (sec.get_value("match_first_index").is_some() || sec.get_value("drawindexed").is_some()));
            let is_shape_key_like = check_shape_key && sec_name_lower.contains("shapekey");
            if is_component_like || is_shape_key_like {
                if let Some(h) = sec.get_value("hash") {
                    let hash_lower = h.trim().to_lowercase();
                    if is_component_like && vb0_hashes.contains(&hash_lower) {
                        return true;
                    }
                    if is_shape_key_like && sk_hashes.contains(&hash_lower) {
                        log::info!("{}", crate::t!(found_old_mod));
                        return true;
                    }
                }
            }
        }

        false
    }

    pub fn execute_stage(&self, stage: PipelineStage, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let fixers = match stage {
            PipelineStage::PreProcess => &self.preprocess_fixers,
            PipelineStage::FeatureAdapt => &self.feature_fixers,
            PipelineStage::MeshGated => &self.mesh_fixers,
            PipelineStage::PostProcess => &self.postprocess_fixers,
        };
        let mut modified = false;
        for fixer in fixers {
            let t0 = std::time::Instant::now();
            let res = fixer.run(ctx)?;
            record_prof(fixer.name(), t0.elapsed().as_micros() as u64);
            if res {
                modified = true;
            }
        }
        Ok(modified)
    }

    pub fn execute_mesh_stages(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        self.execute_stage(PipelineStage::MeshGated, ctx)
    }

    pub fn execute_all(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        let mut modified = false;
        for fixer in self
            .preprocess_fixers
            .iter()
            .chain(&self.feature_fixers)
            .chain(&self.mesh_fixers)
            .chain(&self.postprocess_fixers)
        {
            if fixer.run(ctx)? {
                modified = true;
            }
        }
        Ok(modified)
    }
}

pub struct FixerPipelineBuilder {
    fixers: Vec<Box<dyn PipelineFixer>>,
}

impl FixerPipelineBuilder {
    pub fn new() -> Self {
        Self { fixers: Vec::new() }
    }

    pub fn add<F: PipelineFixer + 'static>(mut self, fixer: F) -> Self {
        self.fixers.push(Box::new(fixer));
        self
    }

    pub fn build(self) -> FixerPipeline {
        FixerPipeline::from_fixers(self.fixers)
    }
}
