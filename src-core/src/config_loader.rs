// src-core/src/config_loader.rs
// Config loading, validation, and hot-reload.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use localization::config::LangPack;
use reqwest::Client;
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::localization;
pub use crate::utils::vertex_remap::*;

/// Thread-safe, lock-free global config.
/// OnceLock ensures one-time initialization; ArcSwap enables safe hot-reload.
/// Old Arc<GlobalConfig> is automatically freed when all references drop.
static CONFIG: OnceLock<ArcSwap<GlobalConfig>> = OnceLock::new();
static CONFIG_OVERRIDE_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Global atomic flag indicating that the config has been hot-reloaded and UI needs to refresh.
pub static CONFIG_CHANGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct GlobalConfig {
    lang: LangPack,
    settings: SettingConfig,
    characters: HashMap<String, CharacterConfig>,
    version: VersionConfig,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct SettingConfig {
    pub state_texture_removers: Vec<String>,
    pub enable_aero_rover_fix: bool,
    #[serde(default = "default_early_characters")]
    pub early_characters: Vec<String>,
}

fn default_early_characters() -> Vec<String> {
    vec![
        "RoverFemale".into(),
        "RoverMale".into(),
        "Yangyang".into(),
        "Baizhi".into(),
        "Chixia".into(),
        "Jianxin".into(),
        "Danjin".into(),
        "Lingyang".into(),
        "Encore".into(),
        "Sanhua".into(),
        "Verina".into(),
        "Taoqi".into(),
        "Calcharo".into(),
        "Yuanwu".into(),
        "Mortefi".into(),
        "Aalto".into(),
        "Jiyan".into(),
        "Yinlin".into(),
        "Jinhsi".into(),
        "Changli".into(),
    ]
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct CharacterConfig {
    pub main_hashes: Vec<Replacement>,
    pub textures: HashMap<String, TextureNode>,
    pub checksum: Option<String>,
    pub rules: Option<Vec<ReplacementRule>>,
    pub vg_remaps: Option<Vec<VertexRemapConfig>>,
    pub stride_fix: Option<StrideFix>,
    pub shapekey_fix: Option<ShapeKeyFixConfig>,
    pub skip_components: Option<Vec<u8>>,
    pub materialmap_adapt: Option<Vec<MaterialmapAdaptRule>>,
    pub fallback_masks: Option<Vec<FallbackMaskRule>>,
    #[serde(alias = "rover_hair_fix")]
    pub hair_fix: Option<HairFixConfig>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub struct HairFixConfig {
    pub trigger_hash: Vec<String>,
    pub match_first_index: String,
    pub match_index_count: String,
    #[serde(deserialize_with = "deserialize_u16_from_str_or_num")]
    pub vg_offset: u16,
    #[serde(deserialize_with = "deserialize_u16_from_str_or_num")]
    pub vg_count: u16,
}

pub type RoverHairFixConfig = HairFixConfig;

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct FallbackMaskRule {
    pub hash: String,
    #[serde(default = "default_mask_resource_name")]
    pub resource_name: String,
    #[serde(default = "default_mask_filename")]
    pub filename: String,
}

fn default_mask_resource_name() -> String {
    "Resource_Mask_White".to_string()
}

fn default_mask_filename() -> String {
    "Textures/mask_white.png".to_string()
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct MaterialmapAdaptRule {
    #[serde(deserialize_with = "deserialize_u8_from_str_or_num")]
    pub component_id: u8,
    pub material_hash: String,
    pub source_lightmap_hash: Option<String>,
    pub clothing_value: Option<u8>,
    pub skin_value: Option<u8>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct StrideFix {
    pub trigger_hash: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymmetryFilter {
    All,
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetShapeKey {
    pub target_channel: u16,
    pub filter: SymmetryFilter,
}

impl TargetShapeKey {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some(num_part) = s.strip_suffix('L').or_else(|| s.strip_suffix('l')) {
            let ch = num_part
                .trim()
                .parse::<u16>()
                .map_err(|e| format!("Invalid channel '{s}': {e}"))?;
            Ok(Self {
                target_channel: ch,
                filter: SymmetryFilter::Left,
            })
        } else if let Some(num_part) = s.strip_suffix('R').or_else(|| s.strip_suffix('r')) {
            let ch = num_part
                .trim()
                .parse::<u16>()
                .map_err(|e| format!("Invalid channel '{s}': {e}"))?;
            Ok(Self {
                target_channel: ch,
                filter: SymmetryFilter::Right,
            })
        } else if let Some(num_part) = s.strip_suffix('A').or_else(|| s.strip_suffix('a')) {
            let ch = num_part
                .trim()
                .parse::<u16>()
                .map_err(|e| format!("Invalid channel '{s}': {e}"))?;
            Ok(Self {
                target_channel: ch,
                filter: SymmetryFilter::All,
            })
        } else {
            let ch = s.parse::<u16>().map_err(|e| format!("Invalid channel '{s}': {e}"))?;
            Ok(Self {
                target_channel: ch,
                filter: SymmetryFilter::All,
            })
        }
    }
}

impl From<u16> for TargetShapeKey {
    fn from(ch: u16) -> Self {
        Self {
            target_channel: ch,
            filter: SymmetryFilter::All,
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct ShapeKeyFixConfig {
    pub trigger_hash: Vec<String>,
    pub section_rewrites: Option<Vec<SectionRewrite>>,
    pub custom_values_array: Option<u32>,
    #[serde(default, deserialize_with = "deserialize_option_multimap_or_string")]
    pub expression_remap: Option<HashMap<u16, Vec<TargetShapeKey>>>,
    pub offset_stride: Option<u32>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct SectionRewrite {
    pub old_section: String,
    pub new_content: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct TextureNode {
    pub meta: Option<TextureMeta>,
    pub replace: Vec<String>,
    pub derive: HashMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct TextureMeta {
    #[serde(deserialize_with = "deserialize_id_as_vec", default)]
    pub id: Vec<u32>,
    #[serde(rename = "type", default)]
    pub type_: String,
    pub slot: Option<Vec<u32>>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct Replacement {
    pub old: Vec<String>,
    pub new: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct ReplacementRule {
    pub line_prefix: String,
    pub replacements: Vec<Replacement>,
}

// ── Version / Update ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct VersionConfig {
    pub min_required_version: String,
    pub current_version: String,
    pub update_url: String,
    pub latest_program_version: Option<String>,
    pub support_url_cn: Option<String>,
    pub support_url_intl: Option<String>,
}

#[derive(Debug)]
pub enum ConfigError {
    SerdeError(serde_json::Error),
    IoError(std::io::Error),
    NetworkError(reqwest::Error),
    AllRemoteFailed,
    Semver(String),
    VersionMismatch(String),
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        ConfigError::SerdeError(e)
    }
}
impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::IoError(e)
    }
}
impl From<semver::Error> for ConfigError {
    fn from(e: semver::Error) -> Self {
        ConfigError::Semver(format!("{e}"))
    }
}
impl From<reqwest::Error> for ConfigError {
    fn from(e: reqwest::Error) -> Self {
        ConfigError::NetworkError(e)
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::SerdeError(e) => write!(f, "JSON解析错误: {e}"),
            Self::IoError(e) => write!(f, "文件读写错误: {e}"),
            Self::NetworkError(e) => write!(f, "网络错误: {e}"),
            Self::AllRemoteFailed => write!(f, "所有远程源都不可用"),
            Self::Semver(e) => write!(f, "Semver解析错误: {e}"),
            Self::VersionMismatch(e) => write!(f, "版本不匹配: {e}"),
        }
    }
}
impl std::error::Error for ConfigError {}

// ── Public init API ─────────────────────────────────────────────────────────

/// Initialize config from local/embedded source (idempotent — first call wins).
/// Remote updates are handled separately via `update_config_from_remote()`.
pub async fn init_config() {
    // OnceLock ensures this block runs at most once across all threads
    CONFIG.get_or_init(|| {
        log::debug!("Loading config...");
        let load_start = Instant::now();

        #[cfg(debug_assertions)]
        {
            if let (Some(yml_path), Some(json_path), Some(script_path)) = (
                find_workspace_file("config.yml"),
                find_workspace_file("config.json"),
                find_workspace_file("scripts/compile_config.js"),
            ) {
                let yml_mtime = yml_path.metadata().and_then(|m| m.modified()).ok();
                let json_mtime = json_path.metadata().and_then(|m| m.modified()).ok();
                if let (Some(ym), Some(jm)) = (yml_mtime, json_mtime) {
                    if ym > jm {
                        log::info!("[DEV] config.yml is newer than config.json, pre-compiling on startup...");
                        let mut cmd = std::process::Command::new("node");
                        cmd.arg(script_path);
                        #[cfg(target_os = "windows")]
                        {
                            use std::os::windows::process::CommandExt;
                            cmd.creation_flags(0x08000000);
                        }
                        let _ = cmd.output();
                    }
                }
            }
        }

        let (config_data, is_override) = if let Some(override_path) = config_override_path() {
            log::info!("Loading config from specified path: {}", override_path.display());
            match std::fs::read_to_string(override_path) {
                Ok(content) => (content, true),
                Err(e) => {
                    log::warn!(
                        "Failed to read override config file '{}': {}. Falling back to default loader.",
                        override_path.display(),
                        e
                    );
                    (load_local("config.json"), false)
                }
            }
        } else {
            (load_local("config.json"), false)
        };

        let config: GlobalConfig = if is_override {
            serde_json::from_str(&config_data).unwrap_or_else(|e| {
                log::warn!("Failed to parse override config: {e}. Falling back to default configuration.");
                serde_json::from_str(&load_local("config.json")).unwrap_or_else(|_| {
                    serde_json::from_str(include_str!("../../config.json"))
                        .expect("Embedded config.json must be valid JSON")
                })
            })
        } else {
            serde_json::from_str(&config_data).unwrap_or_else(|e| {
                log::warn!("Failed to parse local config.json: {e}. Falling back to embedded config.");
                serde_json::from_str(include_str!("../../config.json"))
                    .expect("Embedded config.json must be valid JSON")
            })
        };

        log::debug!("Config loaded in {:.2?}", load_start.elapsed());

        // Only spawn the config.json watcher during local Dev/Debug mode!
        #[cfg(debug_assertions)]
        {
            spawn_dev_rules_watcher();
        }

        ArcSwap::new(Arc::new(config))
    });
}

/// Helper function to traverse directories upwards to locate a specific file in the workspace
#[cfg(debug_assertions)]
fn find_workspace_file(name: &str) -> Option<std::path::PathBuf> {
    if let Ok(mut dir) = std::env::current_dir() {
        loop {
            let path = dir.join(name);
            if path.exists() {
                return Some(path);
            }
            if !dir.pop() {
                break;
            }
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe;
        while dir.pop() {
            let path = dir.join(name);
            if path.exists() {
                return Some(path);
            }
        }
    }
    None
}

#[cfg(debug_assertions)]
fn spawn_dev_rules_watcher() {
    std::thread::spawn(move || {
        use std::time::SystemTime;

        let yml_path = match find_workspace_file("config.yml") {
            Some(path) => path,
            None => {
                eprintln!("[DEV] ❌ Error: config.yml could not be found in parent directories!");
                return;
            }
        };

        let workspace_root = yml_path.parent().unwrap().to_path_buf();
        let config_json_path = workspace_root.join("config.json");
        let compile_script_path = workspace_root.join("scripts").join("compile_config.js");

        println!("[DEV] Rules auto-reload watcher spawned!");
        println!("[DEV] Monitoring: {}", yml_path.display());
        println!("[DEV] Workspace root: {}", workspace_root.display());

        let mut last_modified_yml = yml_path
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        let mut last_modified_json = config_json_path
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        loop {
            std::thread::sleep(std::time::Duration::from_millis(1000));

            // 1. Check config.yml first
            let mut yml_changed = false;
            if let Ok(metadata) = yml_path.metadata() {
                if let Ok(modified) = metadata.modified() {
                    if modified > last_modified_yml {
                        last_modified_yml = modified;
                        yml_changed = true;
                    }
                }
            }

            if yml_changed {
                println!("[DEV] config.yml change detected! Recompiling config...");
                // Debounce slightly to let editor finish writing
                std::thread::sleep(std::time::Duration::from_millis(100));

                let mut cmd = std::process::Command::new("node");
                cmd.current_dir(&workspace_root);
                cmd.arg(&compile_script_path);
                #[cfg(target_os = "windows")]
                {
                    use std::os::windows::process::CommandExt;
                    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
                }

                let compile_status = cmd.status();
                match compile_status {
                    Ok(stat) if stat.success() => {
                        if let Ok(metadata) = config_json_path.metadata() {
                            if let Ok(modified) = metadata.modified() {
                                last_modified_json = modified;
                            }
                        }

                        match std::fs::read_to_string(&config_json_path) {
                            Ok(config_data) => match serde_json::from_str::<GlobalConfig>(&config_data) {
                                Ok(new_config) => {
                                    if let Some(arc_swap) = CONFIG.get() {
                                        arc_swap.store(std::sync::Arc::new(new_config));
                                        CONFIG_CHANGED.store(true, std::sync::atomic::Ordering::SeqCst);
                                        println!("[DEV] ⚡ Config successfully auto-reloaded in running app!");
                                    }
                                }
                                Err(e) => eprintln!("[DEV] ❌ Failed to parse config.json after changes: {e:?}"),
                            },
                            Err(e) => eprintln!("[DEV] ❌ Failed to read config.json: {e:?}"),
                        }
                    }
                    Ok(_) => {
                        eprintln!("[DEV] ❌ Recompile failed: compile_config.js exited with non-zero status.");
                    }
                    Err(e) => {
                        eprintln!("[DEV] ❌ Failed to execute Node.js to compile config.yml: {e:?}");
                    }
                }
                continue;
            }

            // 2. Direct config.json change check (fallback)
            if let Ok(metadata) = config_json_path.metadata() {
                if let Ok(modified) = metadata.modified() {
                    if modified > last_modified_json {
                        last_modified_json = modified;
                        println!("[DEV] config.json direct change detected, reloading in-memory config...");

                        match std::fs::read_to_string(&config_json_path) {
                            Ok(config_data) => match serde_json::from_str::<GlobalConfig>(&config_data) {
                                Ok(new_config) => {
                                    if let Some(arc_swap) = CONFIG.get() {
                                        arc_swap.store(std::sync::Arc::new(new_config));
                                        CONFIG_CHANGED.store(true, std::sync::atomic::Ordering::SeqCst);
                                        println!("[DEV] ⚡ Config successfully auto-reloaded from config.json!");
                                    }
                                }
                                Err(e) => eprintln!("[DEV] ❌ Failed to parse config.json after change: {e:?}"),
                            },
                            Err(e) => eprintln!("[DEV] ❌ Failed to read config.json: {e:?}"),
                        }
                    }
                }
            }
        }
    });
}

/// Core logic to fetch the latest config.json from remote sources and hot-swap it.
pub async fn update_config_from_remote() -> Result<(), ConfigError> {
    let config_data = load_remote_config("config.json").await?;
    let remote_config: GlobalConfig = serde_json::from_str(&config_data).map_err(ConfigError::SerdeError)?;

    if let Some(arc_swap) = CONFIG.get() {
        arc_swap.store(Arc::new(remote_config));
        log::info!("Config successfully updated from remote and hot-swapped.");
    } else {
        CONFIG.get_or_init(|| ArcSwap::new(Arc::new(remote_config)));
        log::info!("Config initialized from remote.");
    }
    Ok(())
}

/// Hot-reload config from remote sources manually.
pub async fn force_reload_remote_config() -> Result<(), ConfigError> {
    if config_override_path().is_some() {
        return Ok(());
    }
    log::info!("Forcing config update from remote...");
    update_config_from_remote().await
}

async fn load_remote_config(file_name: &str) -> Result<String, ConfigError> {
    let remotes = [
        format!("https://gitee.com/moonholder/Wuwa_Mod_Fixer/raw/main/{file_name}"),
        format!("https://raw.githubusercontent.com/Moonholder/Wuwa_Mod_Fixer/main/{file_name}"),
    ];

    let agent_ref = build_agent();
    let mut tasks = Vec::new();
    for url in &remotes {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let client = agent_ref.clone();
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => resp.text().await.map_err(|e| e.to_string()),
                Ok(resp) => Err(format!("StatusCode: {}", resp.status())),
                Err(e) => Err(e.to_string()),
            }
        }));
    }

    while !tasks.is_empty() {
        let (result, _, rest) = futures::future::select_all(tasks).await;
        tasks = rest;
        if let Ok(Ok(content)) = result {
            log::info!("Remote config loaded: {file_name}");
            for task in &tasks {
                task.abort();
            }
            return Ok(content);
        }
    }
    Err(ConfigError::AllRemoteFailed)
}

fn load_local(file_name: &str) -> String {
    let path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
        .join(file_name);

    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            log::info!("Loaded local config from disk: {}", path.display());
            return content;
        }
    }

    #[cfg(debug_assertions)]
    {
        if let Some(workspace_path) = find_workspace_file(file_name) {
            if let Ok(content) = std::fs::read_to_string(&workspace_path) {
                log::info!("Loaded config from workspace disk: {}", workspace_path.display());
                return content;
            }
        }
    }

    log::debug!("Loaded embedded config: config.json");
    include_str!("../../config.json").to_string()
}

pub fn set_config_override_path(path: impl Into<PathBuf>) {
    let path = path.into();
    if CONFIG_OVERRIDE_PATH.set(path.clone()).is_err() {
        if let Some(current) = CONFIG_OVERRIDE_PATH.get() {
            if current != &path {
                log::warn!(
                    "Config override path already set to {}, ignoring change to {}",
                    current.display(),
                    path.display()
                );
            }
        }
    }
}

pub fn config_override_path() -> Option<&'static PathBuf> {
    CONFIG_OVERRIDE_PATH.get()
}

static GLOBAL_AGENT: OnceLock<Client> = OnceLock::new();

fn build_agent() -> &'static Client {
    GLOBAL_AGENT.get_or_init(|| {
        Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .build()
            .unwrap_or_else(|_| Client::new())
    })
}

/// Load the current config snapshot.
/// Returns a full Arc clone — cheap (just ref-count bump) and safe.
fn load_config() -> Arc<GlobalConfig> {
    CONFIG
        .get()
        .expect("Config not initialized — call init_config() first")
        .load_full()
}

/// Safely attempts to get the current config snapshot if already initialized.
pub fn try_config() -> Option<Arc<GlobalConfig>> {
    CONFIG.get().map(|c| c.load_full())
}

/// Load the current config snapshot as an Arc.
/// Callers access sub-fields via `.lang_ref()`, `.characters_ref()`, etc.
pub fn config() -> Arc<GlobalConfig> {
    load_config()
}

// Convenience accessors for direct field access (backward-compatible pattern)
impl GlobalConfig {
    pub fn lang_ref(&self) -> &LangPack {
        &self.lang
    }
    pub fn settings_ref(&self) -> &SettingConfig {
        &self.settings
    }
    pub fn characters_ref(&self) -> &HashMap<String, CharacterConfig> {
        &self.characters
    }
    pub fn version_ref(&self) -> &VersionConfig {
        &self.version
    }
}

pub fn check_version() -> Result<String, ConfigError> {
    let current_ver = Version::parse(env!("CARGO_PKG_VERSION").trim_start_matches('v'))?;
    let cfg = load_config();
    let config = cfg.version_ref();
    let min_ver = Version::parse(config.min_required_version.trim_start_matches('v'))?;
    if current_ver < min_ver {
        return Err(ConfigError::VersionMismatch(format!(
            "Current version {current_ver} < required {min_ver}. Update: {}",
            config.update_url
        )));
    }
    Ok(format!("Config version: {}", config.current_version))
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum UpdateStatus {
    NoUpdate,
    OptionalUpdate(String, String),
    MandatoryUpdate(String, String),
}

pub fn check_update_status() -> UpdateStatus {
    let cfg = load_config();
    let config = cfg.version_ref();
    if let Ok(current) = Version::parse(env!("CARGO_PKG_VERSION").trim_start_matches('v')) {
        if let Ok(min_req) = Version::parse(config.min_required_version.trim_start_matches('v')) {
            if current < min_req {
                let target = config
                    .latest_program_version
                    .clone()
                    .unwrap_or_else(|| config.min_required_version.clone());
                return UpdateStatus::MandatoryUpdate(target, config.update_url.clone());
            }
        }
        if let Some(latest_str) = &config.latest_program_version {
            if let Ok(latest) = Version::parse(latest_str.trim_start_matches('v')) {
                if latest > current {
                    return UpdateStatus::OptionalUpdate(latest_str.clone(), config.update_url.clone());
                }
            }
        }
    }
    UpdateStatus::NoUpdate
}

pub fn deserialize_map_or_string<'de, D>(deserializer: D) -> Result<HashMap<u16, u16>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct MapOrStringVisitor;

    impl<'de> serde::de::Visitor<'de> for MapOrStringVisitor {
        type Value = HashMap<u16, u16>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a map of u16 to u16 or a compact comma-separated string of key:value pairs")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut values = HashMap::new();
            while let Some((k_str, v)) = map.next_entry::<String, u16>()? {
                if let Ok(k) = k_str.parse::<u16>() {
                    values.insert(k, v);
                }
            }
            Ok(values)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let mut values = HashMap::new();
            if v.is_empty() {
                return Ok(values);
            }
            for pair in v.split(',') {
                let mut parts = pair.split(':');
                if let (Some(k_str), Some(v_str)) = (parts.next(), parts.next()) {
                    let k = k_str.trim().parse::<u16>().map_err(serde::de::Error::custom)?;
                    let v = v_str.trim().parse::<u16>().map_err(serde::de::Error::custom)?;
                    values.insert(k, v);
                }
            }
            Ok(values)
        }
    }

    deserializer.deserialize_any(MapOrStringVisitor)
}

pub fn deserialize_option_map_or_string<'de, D>(deserializer: D) -> Result<Option<HashMap<u16, u16>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    struct Wrapper(#[serde(deserialize_with = "deserialize_map_or_string")] HashMap<u16, u16>);

    Option::<Wrapper>::deserialize(deserializer).map(|opt| opt.map(|w| w.0))
}

pub fn deserialize_option_multimap_or_string<'de, D>(
    deserializer: D,
) -> Result<Option<HashMap<u16, Vec<TargetShapeKey>>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum ChannelVal {
        Num(u16),
        Str(String),
    }

    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum OneOrManyChannel {
        One(ChannelVal),
        Many(Vec<ChannelVal>),
    }

    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Str(String),
        Map(HashMap<String, OneOrManyChannel>),
    }

    let opt = Option::<Raw>::deserialize(deserializer)?;
    let Some(raw) = opt else {
        return Ok(None);
    };

    let mut result: HashMap<u16, Vec<TargetShapeKey>> = HashMap::new();
    match raw {
        Raw::Str(s) => {
            if !s.is_empty() {
                for pair in s.split(',') {
                    let mut parts = pair.split(':');
                    if let (Some(k_str), Some(v_str)) = (parts.next(), parts.next()) {
                        let k = k_str.trim().parse::<u16>().map_err(serde::de::Error::custom)?;
                        let target = TargetShapeKey::parse(v_str).map_err(serde::de::Error::custom)?;
                        result.entry(k).or_default().push(target);
                    }
                }
            }
        }
        Raw::Map(m) => {
            for (k_str, v) in m {
                if let Ok(k) = k_str.parse::<u16>() {
                    let parse_val = |cv: ChannelVal| -> Result<TargetShapeKey, _> {
                        match cv {
                            ChannelVal::Num(n) => Ok(TargetShapeKey::from(n)),
                            ChannelVal::Str(s) => TargetShapeKey::parse(&s),
                        }
                    };
                    match v {
                        OneOrManyChannel::One(val) => {
                            if let Ok(target) = parse_val(val) {
                                result.entry(k).or_default().push(target);
                            }
                        }
                        OneOrManyChannel::Many(vec) => {
                            for val in vec {
                                if let Ok(target) = parse_val(val) {
                                    result.entry(k).or_default().push(target);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(Some(result))
}

fn deserialize_id_as_vec<'de, D>(deserializer: D) -> Result<Vec<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct IdVisitor;

    impl<'de> serde::de::Visitor<'de> for IdVisitor {
        type Value = Vec<u32>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a u32 or an array of u32")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![v as u32])
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![v as u32])
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if let Ok(num) = v.parse::<u32>() {
                Ok(vec![num])
            } else {
                Ok(Vec::new())
            }
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut ids = Vec::new();
            while let Some(val) = seq.next_element::<u32>()? {
                ids.push(val);
            }
            Ok(ids)
        }
    }

    deserializer.deserialize_any(IdVisitor)
}

pub fn deserialize_u8_from_str_or_num<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct U8Visitor;

    impl<'de> serde::de::Visitor<'de> for U8Visitor {
        type Value = u8;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a u8 integer or string representation of a number")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            u8::try_from(v).map_err(serde::de::Error::custom)
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            u8::try_from(v).map_err(serde::de::Error::custom)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            v.trim().parse::<u8>().map_err(serde::de::Error::custom)
        }
    }

    deserializer.deserialize_any(U8Visitor)
}

pub fn deserialize_u32_from_str_or_num<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct U32Visitor;

    impl<'de> serde::de::Visitor<'de> for U32Visitor {
        type Value = u32;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a u32 integer or string representation of a number")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            u32::try_from(v).map_err(serde::de::Error::custom)
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            u32::try_from(v).map_err(serde::de::Error::custom)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            v.trim().parse::<u32>().map_err(serde::de::Error::custom)
        }
    }

    deserializer.deserialize_any(U32Visitor)
}

pub fn deserialize_u16_from_str_or_num<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct U16Visitor;

    impl<'de> serde::de::Visitor<'de> for U16Visitor {
        type Value = u16;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a u16 integer or string representation of a number")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            u16::try_from(v).map_err(serde::de::Error::custom)
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            u16::try_from(v).map_err(serde::de::Error::custom)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            v.trim().parse::<u16>().map_err(serde::de::Error::custom)
        }
    }

    deserializer.deserialize_any(U16Visitor)
}
