use reqwest::StatusCode;
use semver::Version;
use serde::Deserialize;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::OnceCell as AsyncOnceCell;

static CONFIG: AsyncOnceCell<GlobalConfig> = AsyncOnceCell::const_new();

#[derive(Debug)]
pub struct GlobalConfig {
    lang: String,
    characters: String,
    states: String,
    version: VersionConfig,
}

#[derive(Debug, Deserialize)]
pub struct VersionConfig {
    pub min_required_version: String,
    pub latest_version: String,
    pub update_url: String,
}

#[derive(Debug)]
pub enum ConfigError {
    Network(String),
    Parse(String),
    VersionMismatch(String),
    Semver(String), 
    Io(std::io::Error),
}

impl From<reqwest::Error> for ConfigError {
    fn from(e: reqwest::Error) -> Self {
        ConfigError::Network(e.to_string())
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        ConfigError::Parse(e.to_string())
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e)
    }
}

impl From<semver::Error> for ConfigError {
    fn from(e: semver::Error) -> Self {
        ConfigError::Semver(format!("Semver parsing error: {}", e))
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConfigError::Network(e) => write!(f, "Network error: {}", e),
            ConfigError::Parse(e) => write!(f, "Parse error: {}", e),
            ConfigError::VersionMismatch(e) => write!(f, "Version mismatch: {}", e),
            ConfigError::Semver(e) => write!(f, "Version parsing error: {}", e),
            ConfigError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

pub async fn init_config() -> &'static GlobalConfig {
    CONFIG.get_or_init(|| async {
        println!("🔄 开始加载配置...");
        let load_start = Instant::now();
        
        let (lang_res, characters_res, states_res, version_res) = tokio::join!(
            load_config("lang.json"),
            load_config("characters.json"),
            load_config("characters_states.json"),
            load_config("version.json")
        );
 
        let version: VersionConfig = serde_json::from_str(&version_res.unwrap()).unwrap();

        let duration = load_start.elapsed();
        println!("✅ 所有配置加载完成，耗时: {:.2?}", duration);
        
        
        GlobalConfig {
            lang: lang_res.unwrap(),
            characters: characters_res.unwrap(),
            states: states_res.unwrap(),
            version
        }
    }).await
}

async fn load_config(file_name: &str) -> Result<String, ConfigError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();

    // 远程源列表
    let remotes = [
        format!("https://cdn.jsdelivr.net/gh/Moonholder/Wuwa_Mod_Fixer/config/{}", file_name),
        format!("https://raw.githubusercontent.com/Moonholder/Wuwa_Mod_Fixer/main/config/{}", file_name),
    ];

    // 尝试所有远程源
    for url in &remotes {
        let start = Instant::now();
        match client.get(url).send().await {
            Ok(resp) if resp.status() == StatusCode::OK => {
                let content = resp.text().await?;
                println!("🌐 远程加载 {} 成功 ({:.2?})", file_name, start.elapsed());
                return Ok(content);
            }
            Ok(resp) => eprintln!("⚠️  {} 状态码: {}", url, resp.status()),
            Err(e) => eprintln!("⚠️  {} 错误: {}", url, e),
        }
    }

    // 回退到本地文件
    let start = Instant::now();
    let local_path = format!("config/{}", file_name);
    let content = std::fs::read_to_string(&local_path).or_else(|_| {
        let fallback_path = format!(
            "{}/config/{}",
            env!("CARGO_MANIFEST_DIR"),
            Path::new(&local_path).file_name().unwrap().to_str().unwrap()
        );
        println!("📁 使用本地备份: {}", fallback_path);
        std::fs::read_to_string(fallback_path)
    })?;
    
    println!("📦 本地加载 {} 完成 ({:.2?})", file_name, start.elapsed());
    Ok(content)
}

pub fn lang() -> &'static str {
    &CONFIG.get().unwrap().lang
}

pub fn characters() -> &'static str {
    &CONFIG.get().unwrap().characters
}

pub fn states() -> &'static str {
    &CONFIG.get().unwrap().states
}

pub fn version() -> &'static VersionConfig {
    &CONFIG.get().unwrap().version
}

pub fn check_version() -> Result<String, ConfigError> {
    let current_ver = Version::parse(env!("CARGO_PKG_VERSION"))?;
    let config: &VersionConfig = version();
    let min_ver = Version::parse(&config.min_required_version)?;

    if current_ver < min_ver {
        return Err(ConfigError::VersionMismatch(format!(
            "当前版本 {} < 要求的最低版本 {}，请下载最新版本: {}",
            current_ver, min_ver, config.update_url
        )));
    }
    Ok(format!("当前版本: {}, 最新版本: {}", current_ver, config.latest_version))
}