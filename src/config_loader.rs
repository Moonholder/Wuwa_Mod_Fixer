use crate::localization;
use localization::config::get_lang;
use semver::Version;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::OnceCell as AsyncOnceCell;
use ureq::AgentBuilder;

static CONFIG: AsyncOnceCell<GlobalConfig> = AsyncOnceCell::const_new();

#[derive(Deserialize)]
pub struct GlobalConfig {
    lang: LangPack,
    characters: HashMap<String, CharacterConfig>,
    version: VersionConfig,
}

#[derive(Deserialize)]
pub struct LangPack {
    pub title: LangItem,
    pub intro: LangItem,
    pub intro_note: LangItem,
    pub compatibility_note: LangItem,
    pub graphics_setting_note: LangItem,
    pub graphics_quality_note: LangItem,
    pub texture_override_note: LangItem,
    pub found_old_mod: LangItem,
    pub texture_override_prompt: LangItem,
    pub match_character_prompt: LangItem,
    pub remapped_successfully: LangItem,
    pub process_file_start: LangItem,
    pub process_file_done: LangItem,
    pub backup_created: LangItem,
    pub backup_failed: LangItem,
    pub no_need_fix: LangItem,
    pub process_file_error: LangItem,
    pub process_folder_done: LangItem,
    pub input_folder_prompt: LangItem,
    pub start_processing: LangItem,
    pub all_done: LangItem,
    pub error_occurred: LangItem,
    pub error_prompt: LangItem,
}

#[derive(Deserialize)]
pub struct LangItem {
    pub zh: String,
    pub en: String,
}

#[derive(Deserialize, Clone)]
pub struct CharacterConfig {
    pub main_hashes: Vec<Replacement>,
    pub texture_hashes: Vec<Replacement>,
    pub checksum: Option<String>,
    pub rules: Option<Vec<ReplacementRule>>,
    pub vg_remaps: Option<Vec<VertexRemapConfig>>,
    pub states: Option<HashMap<String, HashMap<String, String>>>,
}
#[derive(Deserialize, Clone)]
pub struct Replacement {
    pub old: Vec<String>,
    pub new: String,
}

#[derive(Deserialize, Clone)]
pub struct ReplacementRule {
    pub line_prefix: String,
    pub replacements: Vec<Replacement>,
}
#[derive(Deserialize, Clone)]
pub struct VertexRemapConfig {
    pub trigger_hash: Vec<String>,
    pub vertex_groups: Option<HashMap<u8, u8>>,
    #[serde(default)]
    pub component_remap: Option<Vec<ComponentRemapRegion>>,
}

#[derive(Deserialize, Clone)]
pub struct ComponentRemapRegion {
    pub vertex_offset: usize,
    #[serde(default)]
    pub vertex_count: Option<usize>, // 可选字段，默认 None
    pub indices: HashMap<u8, u8>,
}

impl VertexRemapConfig {
    pub fn apply_remap(&self, blend_data: &mut Vec<u8>, use_merged_skeleton: bool) -> bool {
        const STRIDE: usize = 8;

        if use_merged_skeleton {
            // 处理顶点组重映射
            if let Some(vertex_groups) = &self.vertex_groups {
                for chunk in blend_data.chunks_exact_mut(STRIDE) {
                    let indices = &mut chunk[0..4];
                    indices.iter_mut().for_each(|idx| {
                        *idx = *vertex_groups.get(idx).unwrap_or(idx);
                    });
                }
                info!("merged remapping...");
                return true;
            }
            false
        } else if let Some(regions) = &self.component_remap {
            // 处理多区块组件重映射
            for region in regions {
                let offset = region.vertex_offset * STRIDE;
                let end = region
                    .vertex_count
                    .map(|cnt| offset + cnt * STRIDE)
                    .unwrap_or(blend_data.len());

                debug!(
                    "offset: {}, end: {}, len: {}",
                    offset,
                    end,
                    blend_data.len()
                );

                let end = end.min(blend_data.len());
                if offset >= end {
                    continue;
                }

                info!("component remapping...");

                // 遍历当前区块的每个顶点
                for chunk in blend_data[offset..end].chunks_exact_mut(STRIDE) {
                    let indices = &mut chunk[0..4];
                    indices.iter_mut().for_each(|idx| {
                        *idx = *region.indices.get(idx).unwrap_or(idx);
                    });
                }
            }
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Deserialize)]
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
            println!(
                "🔄 {}...",
                if get_lang() == "zh" {
                    "正在加载配置..."
                } else {
                    "Loading config..."
                }
            );

            let load_start = Instant::now();

            let data = load_config("config.json")
                .await
                .map_err(|_| ())
                .unwrap_or_else(|_| load_local("config.json"));

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
    let agent = AgentBuilder::new().timeout(Duration::from_secs(3)).build();

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
            "https://cdn.jsdelivr.net/gh/Moonholder/Wuwa_Mod_Fixer/{}",
            file_name
        ),
        format!(
            "https://raw.githubusercontent.com/Moonholder/Wuwa_Mod_Fixer/main/{}",
            file_name
        ),
    ];

    // 尝试所有远程源
    for url in &remotes {
        match agent.get(url).call() {
            Ok(resp) => {
                let content = resp.into_string()?;
                println!("🌐 {}: {}", success_msg, file_name);
                return Ok(content);
            }
            Err(ureq::Error::Status(code, _)) => {
                eprintln!("⚠️ {}: {}", status_code_msg, code)
            }
            Err(e) => {
                eprintln!("⚠️ {}: {}", connection_failed_msg, e)
            }
        }
    }

    Err(ConfigError::AllRemoteFailed)
}

fn load_local(file_name: &str) -> String {
    let path = format!("{}", file_name);
    println!(
        "📁 {}: {}",
        if get_lang() == "zh" {
            "本地加载配置"
        } else {
            "Loaded local config"
        },
        path
    );
    return std::fs::read_to_string(&path)
        .or_else(|_| {
            let fallback_path = format!(
                "{}/{}",
                env!("CARGO_MANIFEST_DIR"),
                Path::new(&path).file_name().unwrap().to_str().unwrap()
            );
            std::fs::read_to_string(fallback_path)
        })
        .unwrap_or_else(|e| panic!("💥 本地配置 {} 加载失败: {}", path, e));
}

pub fn lang() -> &'static LangPack {
    &CONFIG.get().unwrap().lang
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
        return Err(ConfigError::VersionMismatch(if get_lang() == "zh" {
            format!(
                "当前版本 {} < 要求的最低版本 {}，请下载最新版本: {}",
                current_ver, min_ver, config.update_url
            )
        } else {
            format!(
                "Current version {} < minimum required version {}. Please download the latest version: {}",
                current_ver, min_ver, config.update_url
            )
        }));
    }
    Ok(if get_lang() == "zh" {
        format!("当前配置版本: {}", config.current_version)
    } else {
        format!("Current config version: {}", config.current_version)
    })
}
