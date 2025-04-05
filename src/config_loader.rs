use crate::localization;
use localization::config::get_lang;
use regex::Regex;
use semver::Version;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::OnceCell as AsyncOnceCell;
use ureq::AgentBuilder;
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

static CONFIG: AsyncOnceCell<GlobalConfig> = AsyncOnceCell::const_new();

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct GlobalConfig {
    lang: LangPack,
    characters: HashMap<String, CharacterConfig>,
    version: VersionConfig,
}

#[derive(Deserialize, Default)]
#[serde(default)]
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

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct LangItem {
    pub zh: String,
    pub en: String,
}

#[derive(Deserialize, Clone, Default)]
#[serde(default)]
pub struct CharacterConfig {
    pub main_hashes: Vec<Replacement>,
    pub texture_hashes: Vec<Replacement>,
    pub checksum: Option<String>,
    pub rules: Option<Vec<ReplacementRule>>,
    pub vg_remaps: Option<Vec<VertexRemapConfig>>,
    pub states: Option<HashMap<String, HashMap<String, String>>>,
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
    #[serde(default)]
    pub component_remap: Option<Vec<ComponentRemapRegion>>,
}

#[derive(Deserialize, Clone, Default)]
#[serde(default)]
pub struct ComponentRemapRegion {
    pub component_index: u8,
    pub indices: HashMap<u8, u8>,
}

impl VertexRemapConfig {
    const STRIDE: usize = 8;

    const INDEX_SIZE: usize = 4;

    pub fn apply_remap_merged(&self, blend_data: &mut Vec<u8>) -> Result<bool, String> {
        if let Some(vertex_groups) = &self.vertex_groups {
            for chunk in blend_data.chunks_exact_mut(Self::STRIDE) {
                let indices = &mut chunk[0..4];
                indices.iter_mut().for_each(|idx| {
                    *idx = *vertex_groups.get(idx).unwrap_or(idx);
                });
            }
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
    ) -> Result<bool, String> {
        if let Some(regions) = &self.component_remap {
            let buf_index = blend_path
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .split("_")
                .last()
                .unwrap()
                .parse::<u8>()
                .unwrap_or(0);
            let index_path = if multiple && buf_index > 0 {
                blend_path.with_file_name(format!("Index_{}.buf", buf_index))
            } else {
                blend_path.with_file_name(format!("Index.buf"))
            };

            debug!("index_path={}: ", index_path.display());

            let index_data = std::fs::read(&index_path).map_err(|e| {
                format!(
                    "Failed to read index buffer from {}: {}",
                    index_path.display(),
                    e
                )
            })?;

            let component_indices = if multiple {
                Self::parse_component_indices_with_multiple(content, buf_index)
                    .map_err(|e| format!("Failed to parse component indices: {}", e))?
            } else {
                Self::parse_component_indices(content)
                    .map_err(|e| format!("Failed to parse component indices: {}", e))?
            };

            for region in regions {
                let component_index = region.component_index;

                let &(index_count, index_offset) =
                    component_indices.get(&component_index).ok_or_else(|| {
                        format!("Component {} not found in parsed indices", component_index)
                    })?;

                debug!(
                    "component {}: index_count={}, index_offset={}",
                    component_index, index_count, index_offset
                );

                let (start, end) =
                    Self::get_byte_range_in_buffer(index_count, index_offset, &index_data)
                        .map_err(|e| format!("Failed to get byte range in buffer: {}", e))?;

                debug!(
                    "component {}: start_byte={}, end_byte={}",
                    component_index, start, end
                );

                if start >= end {
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

                for chunk in blend_data[start..end].chunks_exact_mut(Self::STRIDE) {
                    let indices = &mut chunk[0..4];
                    indices.iter_mut().for_each(|idx| {
                        *idx = *region.indices.get(idx).unwrap_or(idx);
                    });
                }
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn parse_component_indices(content: &str) -> Result<HashMap<u8, (usize, usize)>, String> {
        // 1. 匹配 [TextureOverrideComponentX] 节
        let component_re = Regex::new(r"(?m)^\[TextureOverrideComponent(\d+)\]([^\[]*)")
            .map_err(|e| format!("Regex error: {}", e))?;

        // 2. 提取 drawindexed 的 indexCount 和 indexOffset
        let drawindexed_re = Regex::new(r"drawindexed\s*=\s*(\d+),\s*(\d+),")
            .map_err(|e| format!("Regex error: {}", e))?;

        let mut component_indices = HashMap::new();

        // 3. 遍历所有匹配的组件块
        for cap in component_re.captures_iter(content) {
            let component_index: u8 = cap[1]
                .parse()
                .map_err(|_| format!("invalid component id: {}", &cap[1]))?;

            let block_content = &cap[2];
            let mut index_offset = usize::MAX;
            let mut max_end_offset = 0;

            // 4. 提取每个 drawindexed 的 indexCount 和 indexOffset
            for draw_cap in drawindexed_re.captures_iter(block_content) {
                let count: usize = draw_cap[1]
                    .parse()
                    .map_err(|_| format!("invalid index count in component {}", component_index))?;
                let offset: usize = draw_cap[2].parse().map_err(|_| {
                    format!("invalid index offset in component {}", component_index)
                })?;
                index_offset = index_offset.min(offset);
                max_end_offset = max_end_offset.max(offset + count);
            }

            let index_count = max_end_offset - index_offset;

            if index_count > 0 {
                component_indices.insert(component_index, (index_count, index_offset));
            }
        }

        if component_indices.is_empty() {
            Err("No component found in content".into())
        } else {
            Ok(component_indices)
        }
    }

    fn parse_component_indices_with_multiple(
        content: &str,
        draw_block_index: u8,
    ) -> Result<HashMap<u8, (usize, usize)>, String> {
        // 1. 匹配 [TextureOverrideComponentX] 节
        let component_re = Regex::new(r"(?m)^\[TextureOverrideComponent(\d+)\]([^\[]*)")
            .map_err(|e| format!("Regex error: {}", e))?;

        // 2. 提取 drawindexed 的 indexCount 和 indexOffset
        let drawindexed_re = Regex::new(r"drawindexed\s*=\s*(\d+),\s*(\d+),")
            .map_err(|e| format!("Regex error: {}", e))?;

        let mut component_indices = HashMap::new();

        // 3. 遍历所有匹配的组件块
        for cap in component_re.captures_iter(content) {
            let component_index: u8 = cap[1]
                .parse()
                .map_err(|_| format!("invalid component id: {}", &cap[1]))?;

            let block_content = &cap[2];
            let mut index_count = 0;
            let mut index_offset = usize::MAX;

            // 根据 draw_block_index 分割获取对应的 drawindexed
            let pattern = format!(
                r"if \$swapvar == {}\s*([\s\S]*?)(?:else if \$swapvar|endif)",
                draw_block_index
            );
            let re = Regex::new(&pattern).map_err(|e| format!("Regex error: {}", e))?;

            if let Some(swapvar_cap) = re.captures(block_content) {
                let target_section = swapvar_cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let mut max_end_offset = 0;
                // 4. 提取每个 drawindexed 的 indexCount 和 indexOffset
                for draw_cap in drawindexed_re.captures_iter(target_section) {
                    let count: usize = draw_cap[1].parse().map_err(|_| {
                        format!("invalid index count in component {}", component_index)
                    })?;
                    let offset: usize = draw_cap[2].parse().map_err(|_| {
                        format!("invalid index offset in component {}", component_index)
                    })?;
                    index_offset = index_offset.min(offset);
                    max_end_offset = max_end_offset.max(offset + count);
                }
                index_count = max_end_offset - index_offset;
            }

            if index_count > 0 {
                component_indices.insert(component_index, (index_count, index_offset));
            }
        }

        if component_indices.is_empty() {
            Err("No component found in content".into())
        } else {
            Ok(component_indices)
        }
    }

    fn get_byte_range_in_buffer(
        index_count: usize,
        index_offset: usize,
        index_buffer: &[u8],
    ) -> Result<(usize, usize), String> {
        let start_index = index_offset;
        let end_index = index_offset + index_count;

        if end_index > index_buffer.len() / Self::INDEX_SIZE {
            return Err("index out of range".to_string());
        }

        let mut vertex_indices = Vec::with_capacity(index_count);
        for i in start_index..end_index {
            let start = i * Self::INDEX_SIZE;
            let end = start + Self::INDEX_SIZE;
            let index = u32::from_le_bytes(index_buffer[start..end].try_into().unwrap()) as usize;
            vertex_indices.push(index);
        }

        let min_vertex_index = vertex_indices
            .iter()
            .min()
            .ok_or("not found min vertex index")?;
        let max_vertex_index = vertex_indices
            .iter()
            .max()
            .ok_or("not found max vertex index")?;
        let start_byte = *min_vertex_index * Self::STRIDE;
        let end_byte = (*max_vertex_index + 1) * Self::STRIDE;

        Ok((start_byte, end_byte))
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

    // 尝试所有远程源
    for url in &remotes {
        let url = url.clone();
        tasks.push(tokio::spawn(async move { build_agent().get(&url).call() }));
    }

    while !tasks.is_empty() {
        let (result, _, remaining) = futures::future::select_all(tasks).await;
        tasks = remaining;

        match result {
            Ok(Ok(resp)) => {
                let content = resp.into_string()?;
                println!("🌐 {}: {}", success_msg, file_name);
                return Ok(content);
            }
            Ok(Err(ureq::Error::Status(code, _))) => {
                eprintln!("⚠️ {}: {}", status_code_msg, code);
            }
            Ok(Err(e)) => {
                eprintln!("⚠️ {}: {}", connection_failed_msg, e);
            }
            Err(join_err) => eprintln!("⚠️ Task failed: {}", join_err),
        }
    }

    Err(ConfigError::AllRemoteFailed)
}

fn load_local(file_name: &str) -> String {
    let path = PathBuf::from(file_name);
    println!(
        "📁 {}: {}",
        if get_lang() == "zh" {
            "本地加载配置"
        } else {
            "Loaded local config"
        },
        path.display()
    );
    return std::fs::read_to_string(&path)
        .or_else(|_| {
            let mut fallback_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            fallback_path.push(path.file_name().unwrap());
            std::fs::read_to_string(fallback_path)
        })
        .unwrap_or_else(|e| panic!("💥 本地配置 {} 加载失败: {}", path.display(), e));
}

fn build_agent() -> ureq::Agent {
    let mut builder = AgentBuilder::new()
        .timeout_connect(Duration::from_secs(2))
        .timeout(Duration::from_secs(3));

    if let Some(proxy) = get_system_proxy() {
        if let Some((host, port)) = proxy.split_once(':') {
            builder = builder.proxy(ureq::Proxy::new(format!("http://{}:{}", host, port)).unwrap());
        }
    }

    builder.build()
}

fn get_system_proxy() -> Option<String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let internet_settings = hkcu
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        .ok()?;

    let proxy_enable: u32 = internet_settings.get_value("ProxyEnable").ok()?;
    if proxy_enable != 1 {
        return None;
    }

    let proxy_server: String = internet_settings.get_value("ProxyServer").ok()?;

    // 处理代理格式，可能包含http=或https=前缀
    proxy_server
        .split(';')
        .find(|s| s.starts_with("http=") || s.starts_with("https=") || !s.contains("://"))
        .map(|s| {
            s.trim_start_matches("http=")
                .trim_start_matches("https=")
                .trim()
                .to_string()
        })
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
