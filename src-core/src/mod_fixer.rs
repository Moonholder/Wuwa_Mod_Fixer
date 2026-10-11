use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use log::{debug, error, info};
use rayon::prelude::*;
use walkdir::WalkDir;

use crate::{
    ProgressReporter,
    config_loader::CharacterConfig,
    domain::pipeline::FixerPipeline,
    errors::FixerError,
    events::{EventSink, FixSummary, LegacyProgressAdapter, PipelineEvent},
    t,
    utils::regex_patterns::RE_HASH,
};

#[derive(Debug, Clone, Default)]
pub struct ProcessFileOutcome {
    pub modified: bool,
    pub matched_characters: Vec<String>,
}

pub struct ModFixer {
    configs: HashMap<String, CharacterConfig>,
    hash_to_characters: HashMap<String, Vec<String>>,
    pipeline: FixerPipeline,
    pub enable_texture_override: bool,
    pub enable_stable_texture: bool,
    pub enable_fix_aemeath_mech: bool,
    pub enable_rendering33_fix: bool,
    pub aero_fix_mode: u8,
    event_sink: Arc<dyn EventSink>,
    cancel_flag: Arc<AtomicBool>,
}

impl ModFixer {
    /// Backward-compatible constructor: wraps a legacy ProgressReporter into an EventSink
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
        Self::with_event_sink(
            configs,
            enable_texture_override,
            enable_stable_texture,
            enable_fix_aemeath_mech,
            enable_rendering33_fix,
            aero_fix_mode,
            Arc::new(LegacyProgressAdapter::new(progress)),
            cancel_flag,
        )
    }

    /// Modern constructor: accepts an abstract unified EventSink stream
    pub fn with_event_sink(
        configs: &HashMap<String, CharacterConfig>,
        enable_texture_override: bool,
        enable_stable_texture: bool,
        enable_fix_aemeath_mech: bool,
        enable_rendering33_fix: bool,
        aero_fix_mode: u8,
        event_sink: Arc<dyn EventSink>,
        cancel_flag: Arc<AtomicBool>,
    ) -> Self {
        let mut hash_to_characters: HashMap<String, Vec<String>> = HashMap::new();

        for (char_name, config) in configs {
            for hr in &config.main_hashes {
                for old in &hr.old {
                    hash_to_characters
                        .entry(old.to_lowercase())
                        .or_default()
                        .push(char_name.clone());
                }
                hash_to_characters
                    .entry(hr.new.to_lowercase())
                    .or_default()
                    .push(char_name.clone());
            }
            for (hash, node) in &config.textures {
                hash_to_characters
                    .entry(hash.to_lowercase())
                    .or_default()
                    .push(char_name.clone());
                for rep in &node.replace {
                    hash_to_characters
                        .entry(rep.to_lowercase())
                        .or_default()
                        .push(char_name.clone());
                }
            }
        }
        for list in hash_to_characters.values_mut() {
            list.sort_unstable();
            list.dedup();
        }

        Self {
            configs: configs.clone(),
            hash_to_characters,
            pipeline: FixerPipeline::production(),
            enable_texture_override,
            enable_stable_texture,
            enable_fix_aemeath_mech,
            enable_rendering33_fix,
            aero_fix_mode,
            event_sink,
            cancel_flag,
        }
    }

    pub fn process_directory(&self, dir: &Path) -> FixSummary {
        let start_time = std::time::Instant::now();
        let walker = WalkDir::new(dir).follow_links(true).into_iter();
        let target_files: Vec<_> = walker
            .filter_map(|e| e.ok())
            .filter(|e| self.is_target_file(e.path()))
            .map(|e| e.path().to_path_buf())
            .collect();

        let total = target_files.len();
        let session_time = chrono::Local::now().format("%Y-%m-%d %H-%M-%S").to_string();

        self.event_sink.emit(PipelineEvent::Start {
            mode: "fix".to_string(),
            total,
            session_time: Some(session_time.clone()),
        });

        self.event_sink.emit(PipelineEvent::Stage {
            stage: crate::domain::pipeline::PipelineStage::PreProcess,
            description: crate::localization::get_text_with_fallback(
                "pipeline.stage_preprocess",
                &crate::localization::config::get_lang(),
                "阶段 1/4: 结构预处理与哈希替换",
            ),
        });

        let success = std::sync::atomic::AtomicUsize::new(0);
        let skipped = std::sync::atomic::AtomicUsize::new(0);
        let errors = std::sync::atomic::AtomicUsize::new(0);
        let started = std::sync::atomic::AtomicUsize::new(0);
        let emit_lock = std::sync::Mutex::new(0usize);

        target_files.into_par_iter().for_each(|path| {
            if self.cancel_flag.load(Ordering::Relaxed) {
                return;
            }

            let start_idx = started.fetch_add(1, Ordering::Relaxed) + 1;
            let start_percent = if total > 0 {
                (start_idx as f64 / total as f64 * 1000.0).round() / 10.0
            } else {
                100.0
            };

            self.event_sink.emit(PipelineEvent::FileStart {
                path: path.display().to_string(),
                current: start_idx,
                total,
                percent: start_percent,
            });

            let file_result = self.process_file_outcome(&path, Some(&session_time));

            // Acquire sequenced emit lock to ensure strictly monotonic progress across threads
            let mut guard = emit_lock.lock().unwrap_or_else(|e| e.into_inner());
            let done_idx = *guard + 1;
            *guard = done_idx;
            let done_percent = if total > 0 {
                (done_idx as f64 / total as f64 * 1000.0).round() / 10.0
            } else {
                100.0
            };

            match file_result {
                Ok(outcome) if outcome.modified => {
                    success.fetch_add(1, Ordering::Relaxed);
                    let char_str = if outcome.matched_characters.is_empty() {
                        None
                    } else {
                        Some(outcome.matched_characters.join(", "))
                    };
                    self.event_sink.emit(PipelineEvent::FileSuccess {
                        path: path.display().to_string(),
                        character: char_str,
                        current: done_idx,
                        total,
                        percent: done_percent,
                    });
                }
                Ok(_) => {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    self.event_sink.emit(PipelineEvent::FileSkipped {
                        path: path.display().to_string(),
                        reason: crate::localization::get_text_with_fallback(
                            "pipeline.file_skipped_no_match",
                            &crate::localization::config::get_lang(),
                            "无需修复或未匹配到目标角色",
                        ),
                        reason_key: Some("pipeline.file_skipped_no_match".to_string()),
                        current: done_idx,
                        total,
                        percent: done_percent,
                    });
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    error!(
                        "{}",
                        t!(
                            process_file_error,
                            file_path = path.display(),
                            exception = err_msg.clone()
                        )
                    );
                    errors.fetch_add(1, Ordering::Relaxed);
                    self.event_sink.emit(PipelineEvent::FileError {
                        path: path.display().to_string(),
                        error: err_msg,
                        error_key: Some("pipeline.process_file_error".to_string()),
                        current: done_idx,
                        total,
                        percent: done_percent,
                    });
                }
            }

            self.event_sink.emit(PipelineEvent::Progress {
                current: done_idx,
                total,
                percent: done_percent,
                status_text: None,
            });
        });

        let is_cancelled = self.cancel_flag.load(Ordering::Relaxed);
        let s = success.load(Ordering::Relaxed);
        let sk = skipped.load(Ordering::Relaxed);
        let err = errors.load(Ordering::Relaxed);
        let f = err;

        if is_cancelled {
            let cur = *emit_lock.lock().unwrap_or_else(|e| e.into_inner());
            self.event_sink
                .emit(PipelineEvent::TaskCancelled { current: cur, total });
            info!("{}", t!(operation_cancelled));
        }

        let summary = FixSummary {
            total_files: total,
            success_count: s,
            skipped_count: sk,
            failure_count: err,
            elapsed_ms: start_time.elapsed().as_millis() as u64,
        };

        let finish_msg = t!(
            process_folder_done,
            folder_path = dir.display(),
            success_count = s,
            failure_count = f
        );
        info!("{}", finish_msg);

        self.event_sink.emit(PipelineEvent::Finish {
            success: !is_cancelled && err == 0,
            message: finish_msg,
            summary: Some(summary.clone()),
        });

        summary
    }

    fn is_target_file(&self, path: &Path) -> bool {
        let exclude = ["desktop", "ntuser", "disabled_backup", "disabled"];
        if let Some(file_name) = path.file_name() {
            if let Some(name_str) = file_name.to_str() {
                let name = name_str.to_lowercase();
                let is_ini = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map_or(false, |ext| ext.eq_ignore_ascii_case("ini"));
                return is_ini && !exclude.iter().any(|kw| name.contains(kw));
            }
        }
        false
    }

    pub fn process_file(&self, path: &Path) -> Result<bool, FixerError> {
        self.process_file_with_session(path, None)
    }

    pub fn process_file_with_session(&self, path: &Path, session_time: Option<&str>) -> Result<bool, FixerError> {
        self.process_file_outcome(path, session_time).map(|o| o.modified)
    }

    pub fn process_file_outcome(
        &self,
        path: &Path,
        session_time: Option<&str>,
    ) -> Result<ProcessFileOutcome, FixerError> {
        let content = std::fs::read_to_string(path)?;

        let mut original_hashes = HashSet::new();
        for cap in RE_HASH.captures_iter(&content) {
            original_hashes.insert(cap[1].to_lowercase());
        }

        let t_pc = std::time::Instant::now();
        let potential_chars = self.find_potential_characters(&original_hashes);
        crate::domain::pipeline::record_prof("find_potential_characters", t_pc.elapsed().as_micros() as u64);
        if potential_chars.is_empty() {
            debug!("Skipping {} - No matching potential characters found.", path.display());
            return Ok(ProcessFileOutcome::default());
        }

        let t_mc = std::time::Instant::now();
        let mut mod_ctx = crate::domain::context::ModContext::new(
            path,
            content,
            original_hashes,
            self.enable_stable_texture,
            self.enable_fix_aemeath_mech,
            self.enable_rendering33_fix,
            self.aero_fix_mode,
            self.enable_texture_override,
        );
        mod_ctx.session_time = session_time.map(|s| s.to_string());
        crate::domain::pipeline::record_prof("ModContext::new", t_mc.elapsed().as_micros() as u64);

        let exec_result = self.pipeline.execute(
            &mut mod_ctx,
            &self.configs,
            &potential_chars,
            self.enable_texture_override,
        )?;

        let t_commit = std::time::Instant::now();
        let committed = mod_ctx.commit()?;
        crate::domain::pipeline::record_prof("commit", t_commit.elapsed().as_micros() as u64);

        if committed || exec_result.modified {
            info!("{}", t!(process_file_done, file_path = path.display()));
            Ok(ProcessFileOutcome {
                modified: true,
                matched_characters: exec_result.matched_characters,
            })
        } else {
            Ok(ProcessFileOutcome {
                modified: false,
                matched_characters: exec_result.matched_characters,
            })
        }
    }

    fn find_potential_characters(&self, file_hashes: &HashSet<String>) -> Vec<String> {
        let mut matched_chars = HashSet::new();
        for hash in file_hashes {
            if let Some(chars) = self.hash_to_characters.get(hash) {
                for c in chars {
                    matched_chars.insert(c.clone());
                }
            }
        }

        let mut result: Vec<String> = matched_chars.into_iter().collect();
        result.sort_unstable();
        result
    }
}
