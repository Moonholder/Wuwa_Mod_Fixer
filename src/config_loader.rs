use crate::{collector, localization};
use localization::config::{LangPack, get_lang};
use semver::Version;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::OnceCell as AsyncOnceCell;
use ureq::Agent;
use inquire::Confirm;

static CONFIG: AsyncOnceCell<GlobalConfig> = AsyncOnceCell::const_new();

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
            let component_indices = if multiple || buf_index_opt.is_some() {
                collector::parse_component_indices_with_multiple(
                    content,
                    buf_index_opt.unwrap_or("0"),
                )
            } else {
                collector::parse_component_indices(content)
            };

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
    CONFIG
        .get_or_init(|| async {

            let should_load_remote = should_load_remote();
            println!(
                "🔄 {}...",
                if get_lang() == "zh" {
                    "正在加载配置..."
                } else {
                    "Loading config..."
                }
            );

            let load_start = Instant::now();

            let data = if should_load_remote {
            load_config("config.json")
                .await
                .map_err(|_| ())
                .unwrap_or_else(|_| load_local("config.json"))
            } else {
                load_local("config.json")
            };

            let config: GlobalConfig = serde_json::from_str(&data).unwrap();

            let duration = load_start.elapsed();
            println!(
                "✅ {}: {:.2?}",
                if get_lang() == "zh" {
                    "所有配置加载完成，耗时"
                } else {
                    "Config loaded, took"
                },
                duration
            );

            config
        })
        .await
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

    let agent = build_agent();

    for url in &remotes {
        let url = url.clone();
        let agent = agent.clone();
        tasks.push(tokio::spawn(async move {
            tokio::task::spawn_blocking(move || agent.get(&url).call()).await
        }));
    }

    while !tasks.is_empty() {
        let (result, _, remaining) = futures::future::select_all(tasks).await;
        tasks = remaining;

        match result {
            Ok(Ok(Ok(resp))) => {
                let content = resp.into_body().read_to_string()?;
                println!("🌐 {}: {}", success_msg, file_name);
                return Ok(content);
            }
            Ok(Ok(Err(ureq::Error::StatusCode(code)))) => {
                eprintln!("⚠️ {}: {}", status_code_msg, code);
            }
            Ok(Ok(Err(e))) => {
                eprintln!("⚠️ {}: {}", connection_failed_msg, e);
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

fn build_agent() -> Agent {
    let config_builder = Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(2)))
        .timeout_global(Some(Duration::from_secs(3)));

    Agent::new_with_config(config_builder.build())
}

pub fn lang() -> &'static LangPack {
    &CONFIG.get().unwrap().lang
}

pub fn settings() -> &'static SettingConfig {
    &CONFIG.get().unwrap().settings
}

pub fn characters() -> &'static HashMap<String, CharacterConfig> {
    &CONFIG.get().unwrap().characters
}

pub fn version() -> &'static VersionConfig {
    &CONFIG.get().unwrap().version
}

pub fn check_version() -> Result<String, ConfigError> {
    let current_ver = Version::parse(env!("CARGO_PKG_VERSION"))?;
    let config: &VersionConfig = version();
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
