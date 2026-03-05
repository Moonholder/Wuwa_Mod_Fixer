use crate::{collector, localization};
use localization::config::{LangPack, get_lang};
use semver::Version;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use inquire::Confirm;
use ureq::Agent;
static CONFIG_PTR: AtomicPtr<GlobalConfig> = AtomicPtr::new(std::ptr::null_mut());

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct GlobalConfig {
    lang: LangPack,
    settings: SettingConfig,
    characters: HashMap<String, CharacterConfig>,
    version: VersionConfig,
}

#[derive(Deserialize, Clone, Default)]
#[serde(default)]
pub struct SettingConfig {
    pub state_texture_removers: Vec<String>,
    pub enable_aero_rover_fix: bool,
}

#[derive(Deserialize, Clone, Default)]
#[serde(default)]
pub struct CharacterConfig {
    pub main_hashes: Vec<Replacement>,
    #[serde(flatten)]
    pub textures: HashMap<String, TextureNode>,
    pub checksum: Option<String>,
    pub rules: Option<Vec<ReplacementRule>>,
    pub vg_remaps: Option<Vec<VertexRemapConfig>>,
    pub stride_fix: Option<StrideFix>,
}

#[derive(Deserialize, Clone, Default)]
#[serde(default)]
pub struct StrideFix {
    pub trigger_hash: Vec<String>,
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct TextureNode {
    pub meta: Option<TextureMeta>,
    pub replace: Vec<String>,
    pub derive: HashMap<String, Vec<String>>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct TextureMeta {
    pub id: u32,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Deserialize, Clone, Default)]
#[serde(default)]
pub struct Replacement {
    pub old: Vec<String>,
    pub new: String,
}

#[derive(Deserialize, Clone, Default)]
pub struct ReplacementRule {
    pub line_prefix: String,
    pub replacements: Vec<Replacement>,
}

#[derive(Deserialize, Clone, Default)]
#[serde(default)]
pub struct VertexRemapConfig {
    pub trigger_hash: Vec<String>,
    pub vertex_groups: Option<HashMap<u8, u8>>,
    pub component_remap: Option<Vec<ComponentRemapRegion>>,
}

#[derive(Deserialize, Clone, Default)]
#[serde(default)]
pub struct ComponentRemapRegion {
    pub component_index: u8,
    pub indices: HashMap<u8, u8>,
}

impl VertexRemapConfig {
    pub fn apply_remap_merged(
        &self,
        blend_data: &mut Vec<u8>,
        stride: usize,
    ) -> Result<bool, String> {
        if let Some(vertex_groups) = &self.vertex_groups {
            // Ensure stride is valid (even number and >=8)
            if stride % 2 != 0 || stride < 8 {
                return Err(format!("Invalid stride {} - must be even and >=8", stride));
            }

            self.remapping_vertex_groups(blend_data, vertex_groups, 0, blend_data.len(), stride);
            info!("merged remapping...");
            return Ok(true);
        }
        Ok(false)
    }

    pub fn apply_remap_component(
        &self,
        blend_data: &mut Vec<u8>,
        blend_path: &PathBuf,
        content: &str,
        multiple: bool,
        stride: usize,
    ) -> Result<bool, String> {
        // Validate stride is valid (even number and >=8)
        if stride % 2 != 0 || stride < 8 {
            return Err(format!("Invalid stride {} - must be even and >=8", stride));
        }

        if let Some(regions) = &self.component_remap {
            let mut applied = false;

            let index_path =
                collector::combile_buf_path(&blend_path, &collector::BufferType::Index);

            let buf_index_opt = collector::get_buf_path_index(&blend_path);
            let mut component_indices = if multiple || buf_index_opt.is_some() {
                collector::parse_component_indices_with_multiple(
                    content,
                    buf_index_opt.unwrap_or("0"),
                )
            } else {
                collector::parse_component_indices(content)
            };

            if component_indices.is_empty() {
                component_indices = collector::parse_component_indices(content);
            }

            debug!("index_path={}: ", index_path.display());

            let index_data = std::fs::read(&index_path).map_err(|e| {
                format!(
                    "Failed to read index buffer from {}: {}",
                    index_path.display(),
                    e
                )
            })?;

            for region in regions {
                let component_index = region.component_index;

                if let Some(&(index_count, index_offset)) = component_indices.get(&component_index)
                {
                    debug!(
                        "component {}: index_count={}, index_offset={}",
                        component_index, index_count, index_offset
                    );

                    let (start, end) = collector::get_byte_range_in_buffer(
                        index_count,
                        index_offset,
                        &index_data,
                        stride,
                    )
                    .map_err(|e| format!("Failed to get byte range in buffer: {}", e))?;

                    debug!(
                        "component {}: start_byte={}, end_byte={}",
                        component_index, start, end
                    );

                    if start >= end || end > blend_data.len() {
                        warn!(
                            "Component {}: Invalid range (start={}, end={}), skipped",
                            component_index, start, end
                        );
                        continue;
                    }

                    info!(
                        "Remapping component {}: index_count={}, index_offset={}",
                        component_index, index_count, index_offset
                    );

                    self.remapping_vertex_groups(blend_data, &region.indices, start, end, stride);
                    applied = true;
                } else {
                    warn!(
                        "Component {} not found in parsed indices, continuing to next region",
                        component_index
                    );
                    continue;
                }
            }
            return Ok(applied);
        }
        Ok(false)
    }

    fn remapping_vertex_groups(
        &self,
        blend_data: &mut Vec<u8>,
        remap_indices: &HashMap<u8, u8>,
        start: usize,
        end: usize,
        stride: usize,
    ) {
        let indices_len = stride / 2;
        for chunk in blend_data[start..end].chunks_exact_mut(stride) {
            let indices = &mut chunk[0..indices_len];
            indices.iter_mut().for_each(|idx| {
                *idx = *remap_indices.get(idx).unwrap_or(idx);
            });
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct VersionConfig {
    pub min_required_version: String,
    pub current_version: String,
    pub update_url: String,
    pub latest_program_version: Option<String>,
}

#[derive(Debug)]
pub enum ConfigError {
    SerdeError(serde_json::Error),
    IoError(std::io::Error),
    NetworkError(ureq::Error),
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
        ConfigError::Semver(format!("Semver parsing error: {}", e))
    }
}

impl From<ureq::Error> for ConfigError {
    fn from(e: ureq::Error) -> Self {
        ConfigError::NetworkError(e)
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::SerdeError(e) => write!(f, "JSON解析错误: {}", e),
            Self::IoError(e) => write!(f, "文件读写错误: {}", e),
            Self::NetworkError(e) => write!(f, "网络错误: {}", e),
            Self::AllRemoteFailed => write!(f, "所有远程源都不可用"),
            Self::Semver(e) => write!(f, "Semver解析错误: {}", e),
            Self::VersionMismatch(e) => write!(f, "版本不匹配: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

pub async fn init_config() -> &'static GlobalConfig {
    init_config_inner(true, false).await
}

/// GUI mode: load local config directly to avoid startup delay
pub async fn init_config_local() -> &'static GlobalConfig {
    init_config_inner(false, true).await
}

async fn init_config_inner(prompt: bool, force_local: bool) -> &'static GlobalConfig {
    let current_ptr = CONFIG_PTR.load(Ordering::SeqCst);
    if !current_ptr.is_null() {
        return unsafe { &*current_ptr };
    }

    let should_load_remote_fetch = if force_local { false } else if prompt { should_load_remote() } else { true };
    println!("Loading config...");

    let load_start = Instant::now();

    let data = if should_load_remote_fetch {
        load_config("config.json")
            .await
            .map_err(|_| ())
            .unwrap_or_else(|_| load_local("config.json"))
    } else {
        load_local("config.json")
    };

    let config: GlobalConfig = serde_json::from_str(&data).unwrap();

    let duration = load_start.elapsed();
    println!("Config loaded in {:.2?}", duration);

    let leaked = Box::into_raw(Box::new(config));
    match CONFIG_PTR.compare_exchange(std::ptr::null_mut(), leaked, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => unsafe { &*leaked },
        Err(actual) => {
            unsafe { drop(Box::from_raw(leaked)); }
            unsafe { &*actual }
        }
    }
}

/// Force fetch config from internet and update global state
pub async fn force_reload_remote_config() -> Result<(), ConfigError> {
    let data = load_config("config.json").await?;
        
    let new_config: GlobalConfig = serde_json::from_str(&data).map_err(ConfigError::SerdeError)?;
    
    // Ensure initialized
    init_config_local().await;
    
    let leaked = Box::into_raw(Box::new(new_config));
    // NOTE: We intentionally leak the old config. Functions like characters(),
    // lang(), settings() return &'static references into the config, and
    // LANG_PACK caches a &'static LangPack from the first config.
    // Dropping the old allocation would create dangling references (UB).
    CONFIG_PTR.store(leaked, Ordering::SeqCst);
    
    Ok(())
}

async fn load_config(file_name: &str) -> Result<String, ConfigError> {
    let (success_msg, status_code_msg, connection_failed_msg) = if get_lang() == "zh" {
        ("远程加载成功", "远程异常状态码", "远程请求失败")
    } else {
        (
            "Remote loaded successfully",
            "Remote status code",
            "Remote connection failed",
        )
    };

    // 远程源列表
    let remotes = [
        format!(
            "https://gitee.com/moonholder/Wuwa_Mod_Fixer/raw/main/{}",
            file_name
        ),
        format!(
            "https://raw.githubusercontent.com/Moonholder/Wuwa_Mod_Fixer/main/{}",
            file_name
        ),
    ];

    let mut tasks = Vec::new();

    let agent_ref = build_agent();

    for url in &remotes {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                match agent_ref.get(&url).call() {
                    Ok(resp) => {
                        resp.into_body().read_to_string().map_err(|e| e.to_string())
                    }
                    Err(ureq::Error::StatusCode(code)) => Err(format!("StatusCode: {}", code)),
                    Err(e) => Err(e.to_string())
                }
            }).await
        }));
    }

    while !tasks.is_empty() {
        let (result, _, remaining) = futures::future::select_all(tasks).await;
        tasks = remaining;

        match result {
            Ok(Ok(Ok(content))) => {
                println!("🌐 {}: {}", success_msg, file_name);
                return Ok(content);
            }
            Ok(Ok(Err(e))) => {
                if e.starts_with("StatusCode") {
                    eprintln!("⚠️ {}: {}", status_code_msg, e);
                } else {
                    eprintln!("⚠️ {}: {}", connection_failed_msg, e);
                }
            }
            Ok(Err(join_err)) => eprintln!("⚠️ Task failed: {}", join_err),
            Err(join_err) => eprintln!("⚠️ Task join failed: {}", join_err),
        }
    }

    Err(ConfigError::AllRemoteFailed)
}

fn load_local(file_name: &str) -> String {
    println!(
        "📁 {}: {}",
        if get_lang() == "zh" {
            "本地加载配置"
        } else {
            "Loaded local config"
        },
        file_name
    );
    return include_str!("../config.json").to_string();
}

fn should_load_remote() -> bool {
    let prompt = if get_lang() == "zh" {
        "需要联网获取最新配置吗？"
    } else {
        "Do you want to fetch the latest config from the Internet?"
    };
    match Confirm::new(prompt).with_default(true).prompt() {
        Ok(true) => true,
        Ok(false) => false,
        Err(_) => false,
    }
}

static GLOBAL_AGENT: OnceLock<Agent> = OnceLock::new();

fn build_agent() -> &'static Agent {
    GLOBAL_AGENT.get_or_init(|| {
        let config_builder = Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(2)))
            .timeout_global(Some(Duration::from_secs(3)));

        Agent::new_with_config(config_builder.build())
    })
}

fn get_config() -> &'static GlobalConfig {
    let ptr = CONFIG_PTR.load(Ordering::SeqCst);
    if ptr.is_null() {
        panic!("Config not initialized");
    }
    unsafe { &*ptr }
}

pub fn lang() -> &'static LangPack {
    &get_config().lang
}

pub fn settings() -> &'static SettingConfig {
    &get_config().settings
}

pub fn characters() -> &'static HashMap<String, CharacterConfig> {
    &get_config().characters
}

pub fn version() -> &'static VersionConfig {
    &get_config().version
}

pub fn check_version() -> Result<String, ConfigError> {
    let current_ver = Version::parse(env!("CARGO_PKG_VERSION"))?;
    let config = version();
    let min_ver = Version::parse(&config.min_required_version)?;

    if current_ver < min_ver {
        return Err(ConfigError::VersionMismatch(t!(
            version_mismatch,
            current_version = current_ver,
            min_required_version = min_ver,
            update_url = config.update_url
        )));
    }
    Ok(t!(current_version, version = config.current_version))
}

#[derive(Debug, Clone, PartialEq)]
pub enum UpdateStatus {
    NoUpdate,
    OptionalUpdate(String, String),
    MandatoryUpdate(String, String),
}

pub fn check_update_status() -> UpdateStatus {
    let config = version();
    if let Ok(current) = Version::parse(env!("CARGO_PKG_VERSION")) {
        if let Ok(min_req) = Version::parse(&config.min_required_version) {
            if current < min_req {
                let target_ver = config.latest_program_version.clone().unwrap_or_else(|| config.min_required_version.clone());
                return UpdateStatus::MandatoryUpdate(target_ver, config.update_url.clone());
            }
        }
        
        if let Some(latest_str) = &config.latest_program_version {
            if let Ok(latest) = Version::parse(latest_str) {
                if latest > current {
                    return UpdateStatus::OptionalUpdate(latest_str.clone(), config.update_url.clone());
                }
            }
        }
    }
    UpdateStatus::NoUpdate
}
