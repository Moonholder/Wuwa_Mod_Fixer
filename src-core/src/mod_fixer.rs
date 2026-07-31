use log::{debug, error, info};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use walkdir::WalkDir;

use crate::ProgressReporter;
use crate::config_loader::CharacterConfig;
use crate::errors::FixerError;
use crate::fixers::traits::{Fixer, FixerContext};
use crate::t;
use crate::utils::ini_parser::IniDocument;
use crate::utils::regex_patterns::RE_HASH;

// Import all fixers
use crate::fixers::aero_fix::AeroFixer;
use crate::fixers::derive_redirect::DeriveRedirectFixer;
use crate::fixers::hash_replace::HashReplaceFixer;
use crate::fixers::rabbit_fx::RabbitFxFixer;
use crate::fixers::rendering_3_3::Rendering33Fixer;
use crate::fixers::resource_override::ResourceOverrideFixer;
use crate::fixers::rover_fix::RoverFixer;
use crate::fixers::rule_replace::RuleReplaceFixer;
use crate::fixers::shapekey::ShapeKeyFixer;
use crate::fixers::stride::StrideFixer;
use crate::fixers::vertex_remap::VertexRemapFixer;

// Characters that require shape-key matching logic
static EARLY_CHARACTERS: &[&str] = &[
    "RoverFemale",
    "RoverMale",
    "Yangyang",
    "Baizhi",
    "Chixia",
    "Jianxin",
    "Danjin",
    "Lingyang",
    "Encore",
    "Sanhua",
    "Verina",
    "Taoqi",
    "Calcharo",
    "Yuanwu",
    "Mortefi",
    "Aalto",
    "Jiyan",
    "Yinlin",
    "Jinhsi",
    "Changli",
];

pub struct ModFixer {
    configs: HashMap<String, CharacterConfig>,
    pub enable_texture_override: bool,
    pub enable_stable_texture: bool,
    pub enable_fix_aemeath_mech: bool,
    pub enable_rendering33_fix: bool,
    pub aero_fix_mode: u8,
    progress: Arc<dyn ProgressReporter>,
    cancel_flag: Arc<AtomicBool>,
}

impl ModFixer {
    pub fn new(
        configs: &HashMap<String, CharacterConfig>,
        enable_texture_override: bool,
        enable_stable_texture: bool,
        enable_fix_aemeath_mech: bool,
        enable_rendering33_fix: bool,
        aero_fix_mode: u8,
        progress: Arc<dyn ProgressReporter>,
        cancel_flag: Arc<AtomicBool>,
    ) -> Self {
        Self {
            configs: configs.clone(),
            enable_texture_override,
            enable_stable_texture,
            enable_fix_aemeath_mech,
            enable_rendering33_fix,
            aero_fix_mode,
            progress,
            cancel_flag,
        }
    }

    pub fn process_directory(&self, dir: &Path) {
        let walker = WalkDir::new(dir).follow_links(true).into_iter();
        let target_files: Vec<_> = walker
            .filter_map(|e| e.ok())
            .filter(|e| self.is_target_file(e.path()))
            .map(|e| e.path().to_path_buf())
            .collect();

        self.progress.set_total(target_files.len());

        let mut success = 0;
        let mut skipped = 0;
        let mut errors = 0;

        for path in target_files {
            if self.cancel_flag.load(Ordering::Relaxed) {
                info!("{}", t!(operation_cancelled));
                break;
            }

            match self.process_file(&path) {
                Ok(true) => {
                    success += 1;
                }
                Ok(false) => {
                    skipped += 1;
                }
                Err(e) => {
                    error!(
                        "{}",
                        t!(
                            process_file_error,
                            file_path = path.display(),
                            exception = e.to_string()
                        )
                    );
                    errors += 1;
                }
            }
            info!("---------------------------------------------");
            self.progress.increment();
        }

        info!(
            "{}",
            t!(
                process_folder_done,
                folder_path = dir.display(),
                success_count = success,
                failure_count = skipped + errors
            )
        );
    }

    fn is_target_file(&self, path: &Path) -> bool {
        let exclude = ["desktop", "ntuser", "disabled_backup", "disabled"];
        if let Some(file_name) = path.file_name() {
            if let Some(name_str) = file_name.to_str() {
                let name = name_str.to_lowercase();
                return path.extension().map_or(false, |e| e == "ini") && !exclude.iter().any(|kw| name.contains(kw));
            }
        }
        false
    }

    fn process_file(&self, path: &Path) -> Result<bool, FixerError> {
        let content = std::fs::read_to_string(path)?;

        let mut original_hashes = HashSet::new();
        for cap in RE_HASH.captures_iter(&content) {
            original_hashes.insert(cap[1].to_lowercase());
        }

        let potential_chars = self.find_potential_characters(&original_hashes);
        if potential_chars.is_empty() {
            debug!("Skipping {} - No matching potential characters found.", path.display());
            return Ok(false);
        }

        let mut ini = IniDocument::parse(&content);

        crate::utils::fs_utils::check_write_permission(path.parent().unwrap())?;

        let mut backed_up = HashSet::new();
        let mut ini_modified = false;

        for char_name in &potential_chars {
            let config = self.configs.get(char_name).unwrap();
            let mut ctx = FixerContext {
                file_path: path,
                ini: &mut ini,
                config,
                char_name,
                backed_up: &mut backed_up,
                original_content: &content,
                original_hashes: &original_hashes,
                enable_stable_texture: self.enable_stable_texture,
                enable_fix_aemeath_mech: self.enable_fix_aemeath_mech,
                enable_rendering33_fix: self.enable_rendering33_fix,
                aero_fix_mode: self.aero_fix_mode,
                enable_texture_override: self.enable_texture_override,
            };

            // Hash Replace (always runs for potential matched character)
            if HashReplaceFixer.run(&mut ctx)? {
                ini_modified = true;
            }

            // Conditional mesh-specific fixers
            if self.check_mesh_character_match(ctx.ini, char_name, config) {
                info!("{}", t!(match_character_prompt, character = char_name));

                let pipeline: &[&dyn Fixer] = &[
                    &RuleReplaceFixer,
                    &VertexRemapFixer,
                    &Rendering33Fixer,
                    &StrideFixer,
                    &AeroFixer,
                    &ShapeKeyFixer,
                    &RoverFixer,
                    &RabbitFxFixer,
                    &ResourceOverrideFixer,
                ];

                for fixer in pipeline {
                    if fixer.run(&mut ctx)? {
                        ini_modified = true;
                    }
                }
            }
        }

        // Derive Redirect (runs once outside the loop to aggregate all valid configs)
        let cfg = crate::config_loader::config();
        let settings = cfg.settings_ref();

        let mut derive_configs = Vec::new();
        for char_name in &potential_chars {
            if self.enable_texture_override || settings.state_texture_removers.contains(char_name) {
                if let Some(config) = self.configs.get(char_name) {
                    derive_configs.push(config);
                }
            }
        }

        if !derive_configs.is_empty() {
            if DeriveRedirectFixer::run_multi(&mut ini, &derive_configs)? {
                ini_modified = true;
            }
        }

        if ini_modified {
            crate::utils::fs_utils::create_backup_once(path, &mut backed_up)?;
            std::fs::write(path, ini.to_string())?;
            info!("{}", t!(process_file_done, file_path = path.display()));
            Ok(true)
        } else {
            if !backed_up.is_empty() {
                info!("{}", t!(no_need_fix));
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    fn find_potential_characters(&self, file_hashes: &HashSet<String>) -> Vec<String> {
        let mut matched_chars = HashSet::new();
        for (char_name, config) in &self.configs {
            let mut all_target_hashes = HashSet::new();
            for hr in &config.main_hashes {
                all_target_hashes.extend(hr.old.iter().map(|h| h.to_lowercase()));
                all_target_hashes.insert(hr.new.to_lowercase());
            }
            for (hash, node) in &config.textures {
                all_target_hashes.insert(hash.to_lowercase());
                all_target_hashes.extend(node.replace.iter().map(|h| h.to_lowercase()));
            }

            for hash in file_hashes {
                if all_target_hashes.contains(hash) {
                    matched_chars.insert(char_name.clone());
                }
            }
        }

        let mut result: Vec<String> = matched_chars.into_iter().collect();
        result.sort();
        result
    }

    fn check_mesh_character_match(&self, ini: &IniDocument, char_name: &str, config: &CharacterConfig) -> bool {
        let mut vb0_hashes = HashSet::new();
        let mut sk_hashes = HashSet::new();

        if let Some(vb0) = config.main_hashes.first() {
            for h in vb0.old.iter().chain(std::iter::once(&vb0.new)) {
                vb0_hashes.insert(h.to_lowercase());
            }
        }

        let check_shape_key = EARLY_CHARACTERS.contains(&char_name);
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
            let is_component = sec_name_lower.starts_with("textureoverridecomponent");
            let is_shape_key = check_shape_key && sec_name_lower.starts_with("textureoverrideshapekey");
            if is_component || is_shape_key {
                if let Some(h) = sec.get_value("hash") {
                    let hash_lower = h.trim().to_lowercase();
                    if is_component && vb0_hashes.contains(&hash_lower) {
                        return true;
                    }
                    if is_shape_key && sk_hashes.contains(&hash_lower) {
                        info!("{}", t!(found_old_mod));
                        return true;
                    }
                }
            }
        }

        false
    }
}
