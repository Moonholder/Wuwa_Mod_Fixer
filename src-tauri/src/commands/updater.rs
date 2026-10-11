use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter};
use tokio::io::AsyncWriteExt;

use crate::error::AppError;

const REPO_BASE_URL: &str = "https://github.com/Moonholder/Wuwa_Mod_Fixer/releases/latest/download/update.json";

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UpdateManifest {
    pub version: String,
    pub notes: serde_json::Value,
    pub pub_date: String,
    pub min_required_version: String,
    #[serde(default)]
    pub platforms: Option<std::collections::HashMap<String, DownloadInfo>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DownloadInfo {
    pub url: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Serialize)]
pub struct UpdateCheckResult {
    pub available: bool,
    pub mandatory: bool,
    pub manifest: Option<UpdateManifest>,
}

#[derive(Clone, Serialize)]
struct DownloadProgress {
    downloaded: u64,
    total: u64,
}

#[tauri::command]
pub async fn check_update(proxy_node: String) -> Result<UpdateCheckResult, AppError> {
    let manifest = fetch_manifest_racing(&proxy_node).await?;

    let current = semver::Version::parse(env!("CARGO_PKG_VERSION").trim_start_matches('v'))
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let latest = semver::Version::parse(manifest.version.trim_start_matches('v'))
        .map_err(|e| AppError::ConfigParse(e.to_string()))?;
    let min_req = semver::Version::parse(manifest.min_required_version.trim_start_matches('v'))
        .unwrap_or_else(|_| current.clone());

    if latest <= current {
        return Ok(UpdateCheckResult {
            available: false,
            mandatory: false,
            manifest: None,
        });
    }

    Ok(UpdateCheckResult {
        available: true,
        mandatory: current < min_req,
        manifest: Some(manifest),
    })
}

#[tauri::command]
pub async fn download_and_apply_update(
    manifest: UpdateManifest,
    proxy_node: String,
    app_handle: AppHandle,
) -> Result<(), AppError> {
    let platform = if cfg!(target_os = "windows") {
        "windows-x86_64"
    } else {
        "linux-x86_64"
    };

    let download_info = manifest
        .platforms
        .as_ref()
        .and_then(|p| p.get(platform))
        .ok_or_else(|| AppError::Update("当前平台无可用更新包".into()))?
        .clone();

    let exe = std::env::current_exe().map_err(|e| AppError::Io(e.to_string()))?;
    let temp_path = exe.with_extension("update_tmp");
    let version_file = exe.with_extension("update_tmp.version");

    // Clean up temp file if it belongs to a different version
    let current_target_version = manifest.version.clone();
    let last_target_version = tokio::fs::read_to_string(&version_file).await.unwrap_or_default();
    if last_target_version != current_target_version {
        let _ = tokio::fs::remove_file(&temp_path).await;
        let _ = tokio::fs::write(&version_file, &current_target_version).await;
    }

    let download_nodes = generate_download_nodes(&download_info.url, &proxy_node);

    let mut client_builder = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(12))
        .read_timeout(std::time::Duration::from_secs(30))
        .tcp_keepalive(std::time::Duration::from_secs(30));

    if let Some(sys_proxy) = get_system_proxy_url() {
        if let Ok(proxy) = reqwest::Proxy::all(&sys_proxy) {
            client_builder = client_builder.proxy(proxy);
        }
    }

    let client = client_builder.build().map_err(|e| AppError::Network(e.to_string()))?;

    let mut download_success = false;

    // Separate nodes into primary (user preferred) and fallback candidates
    let primary_node = download_nodes.first().cloned();
    let fallback_nodes: Vec<_> = download_nodes.iter().skip(1).cloned().collect();

    // Strategy: Try the primary node up to 3 times before falling back to other nodes
    let mut execution_plan: Vec<(String, String, u32)> = Vec::new();
    if let Some((id, url)) = primary_node {
        execution_plan.push((id, url, 3)); // 3 attempts for primary
    }
    for (id, url) in fallback_nodes {
        execution_plan.push((id, url, 1)); // 1 attempt for each fallback
    }

    'node_loop: for (node_id, node_url, max_attempts) in execution_plan {
        let _ = app_handle.emit("updater:node_switch", &node_id);

        for attempt in 1..=max_attempts {
            let mut downloaded = tokio::fs::metadata(&temp_path).await.map(|m| m.len()).unwrap_or(0);

            // Delete local temp file if size exceeds target
            if downloaded > download_info.size {
                let _ = tokio::fs::remove_file(&temp_path).await;
                downloaded = 0;
            }

            // If already fully downloaded, skip download phase
            if downloaded == download_info.size {
                let _ = app_handle.emit(
                    "updater:progress",
                    DownloadProgress {
                        downloaded,
                        total: download_info.size,
                    },
                );
                download_success = true;
                break 'node_loop;
            }

            let mut req = client.get(&node_url);
            if downloaded > 0 {
                req = req.header("Range", format!("bytes={}-", downloaded));
            }

            let mut resp = match req.send().await {
                Ok(r) if r.status().is_success() => r,
                _ => {
                    if attempt < max_attempts {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                    continue;
                }
            };

            let is_partial = resp.status() == reqwest::StatusCode::PARTIAL_CONTENT;
            let raw_file = if downloaded > 0 && !is_partial {
                // Node does not support range requests, reset to 0
                downloaded = 0;
                match tokio::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&temp_path)
                    .await
                {
                    Ok(f) => f,
                    Err(_) => continue,
                }
            } else {
                match tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&temp_path)
                    .await
                {
                    Ok(f) => f,
                    Err(_) => continue,
                }
            };

            let mut file = tokio::io::BufWriter::with_capacity(64 * 1024, raw_file);
            let mut last_emit = Instant::now();
            let mut chunk_failed = false;

            while let Ok(Some(chunk)) = resp.chunk().await {
                if file.write_all(&chunk).await.is_err() {
                    chunk_failed = true;
                    break;
                }
                downloaded += chunk.len() as u64;

                if last_emit.elapsed().as_millis() >= 40 || downloaded == download_info.size {
                    let _ = app_handle.emit(
                        "updater:progress",
                        DownloadProgress {
                            downloaded,
                            total: download_info.size,
                        },
                    );
                    last_emit = Instant::now();
                }
            }

            let _ = file.flush().await;

            if !chunk_failed && downloaded == download_info.size {
                download_success = true;
                break 'node_loop;
            }

            if attempt < max_attempts {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    }

    if !download_success {
        return Err(AppError::Network("下载更新失败，请检查网络连接或更换节点。".into()));
    }

    // Verify SHA256 hash in a background thread
    let expected_sha = download_info.sha256.clone();
    let temp_path_clone = temp_path.clone();
    let hash_matches = tokio::task::spawn_blocking(move || {
        let mut f = std::fs::File::open(&temp_path_clone)?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut f, &mut hasher)?;
        let actual = format!("{:x}", hasher.finalize());
        Ok::<bool, std::io::Error>(actual == expected_sha)
    })
    .await
    .map_err(|_| AppError::Internal("哈希校验线程崩溃".into()))?
    .map_err(|e| AppError::Io(e.to_string()))?;

    if !hash_matches {
        let _ = tokio::fs::remove_file(&temp_path).await;
        let _ = tokio::fs::remove_file(&version_file).await;
        return Err(AppError::Update("更新包校验失败，文件已损坏，请重试。".into()));
    }

    // Clean up helper version file on success
    let _ = tokio::fs::remove_file(&version_file).await;

    // Hot-swap executable across platforms
    let temp_path_clone = temp_path.clone();

    #[cfg(target_os = "windows")]
    {
        let old_exe = exe.with_extension("exe.old");
        if old_exe.exists() {
            let _ = std::fs::remove_file(&old_exe);
        }

        // Rename the running executable to .old
        std::fs::rename(&exe, &old_exe)
            .map_err(|e| AppError::Io(format!("Failed to rename running executable: {}", e)))?;

        // Rename the new temp file to target executable name
        std::fs::rename(&temp_path_clone, &exe)
            .map_err(|e| AppError::Io(format!("Failed to rename update file to target: {}", e)))?;

        // Spawn the new version of the application.
        // We must set stdin/stdout/stderr to Stdio::null() to avoid OS error 50 (The request is not supported)
        // caused by FreeConsole() invalidating the inherited standard handles.
        std::process::Command::new(&exe)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| AppError::Io(format!("Failed to launch new version: {}", e)))?;
    }

    #[cfg(target_os = "linux")]
    {
        let exe_dir = exe
            .parent()
            .ok_or_else(|| AppError::Io("Executable directory not found".into()))?;
        let temp_extract_dir = exe_dir.join(".update_tmp");
        let _ = std::fs::create_dir_all(&temp_extract_dir);

        let temp_str = temp_path_clone
            .to_str()
            .ok_or_else(|| AppError::Io("Invalid temp path encoding".into()))?;
        let extract_str = temp_extract_dir
            .to_str()
            .ok_or_else(|| AppError::Io("Invalid extract dir encoding".into()))?;

        let status = std::process::Command::new("tar")
            .args(["-xzf", temp_str, "-C", extract_str])
            .status()
            .map_err(|e| AppError::Io(format!("Failed to run tar: {}", e)))?;

        if !status.success() {
            let _ = std::fs::remove_dir_all(&temp_extract_dir);
            return Err(AppError::Update("Failed to extract tar.gz".into()));
        }

        let extracted_bin = temp_extract_dir.join("Wuwa_Mod_Fixer");
        std::fs::remove_file(&exe).ok();
        std::fs::rename(&extracted_bin, &exe)
            .or_else(|_| std::fs::copy(&extracted_bin, &exe).map(|_| ()))
            .map_err(|e| AppError::Io(format!("Failed to replace exe: {}", e)))?;

        let _ = std::fs::remove_dir_all(&temp_extract_dir);
        let _ = std::fs::remove_file(&temp_path_clone);

        std::process::Command::new(&exe)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| AppError::Io(format!("Failed to spawn new exe: {}", e)))?;
    }

    std::process::exit(0);
}

// Speed-racing routing helpers

async fn fetch_manifest_racing(proxy_node: &str) -> Result<UpdateManifest, AppError> {
    let nodes = generate_download_nodes(REPO_BASE_URL, proxy_node);

    let mut client_builder = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(6))
        .read_timeout(std::time::Duration::from_secs(8));

    if let Some(sys_proxy) = get_system_proxy_url() {
        if let Ok(proxy) = reqwest::Proxy::all(&sys_proxy) {
            client_builder = client_builder.proxy(proxy);
        }
    }

    let client = client_builder.build().map_err(|e| AppError::Internal(e.to_string()))?;

    let tasks: Vec<_> = nodes
        .into_iter()
        .map(|(_, url)| {
            let client_clone = client.clone();
            Box::pin(async move {
                let resp = client_clone
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| AppError::Network(e.to_string()))?;

                if !resp.status().is_success() {
                    return Err(AppError::Network(format!("HTTP {}", resp.status())));
                }

                let manifest: UpdateManifest = resp.json().await.map_err(|e| AppError::ConfigParse(e.to_string()))?;

                Ok(manifest)
            })
        })
        .collect();

    let racing_future = futures::future::select_ok(tasks);
    let (manifest, _) = tokio::time::timeout(std::time::Duration::from_secs(8), racing_future)
        .await
        .map_err(|_| AppError::Network("获取更新配置超时".into()))?
        .map_err(|_| AppError::Network("所有测速节点均无响应，请检查网络".into()))?;

    Ok(manifest)
}

fn generate_download_nodes(raw_url: &str, preferred: &str) -> Vec<(String, String)> {
    let mut nodes = Vec::new();
    let preferred = if preferred.trim().is_empty() {
        "direct"
    } else {
        preferred
    };

    let apply_proxy = |url: &str, node: &str| -> String {
        match node {
            "ghproxy" => format!("https://ghproxy.net/{}", url),
            "ghfast" => format!("https://ghfast.top/{}", url),
            "kgithub" => url.replace("github.com", "kkgithub.com"),
            _ => url.to_string(), // "direct"
        }
    };

    let preferred_url = apply_proxy(raw_url, preferred);

    if preferred == "direct" {
        nodes.push(("direct".into(), raw_url.to_string()));
    } else {
        nodes.push((preferred.into(), preferred_url.clone()));
    }

    let fallbacks = [
        ("ghfast", format!("https://ghfast.top/{}", raw_url)),
        ("kgithub", raw_url.replace("github.com", "kkgithub.com")),
        ("ghproxy", format!("https://ghproxy.net/{}", raw_url)),
        ("direct", raw_url.to_string()),
    ];

    for (id, url) in fallbacks {
        if url != preferred_url {
            nodes.push((id.to_string(), url));
        }
    }

    nodes
}

/// Automatically detects Windows System Proxy settings from Windows Registry
fn get_system_proxy_url() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::{
            Foundation::ERROR_SUCCESS,
            System::Registry::{
                HKEY_CURRENT_USER, KEY_READ, REG_DWORD, REG_SZ, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
            },
        };

        let subkey: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\0"
            .encode_utf16()
            .collect();
        let mut hkey = std::ptr::null_mut();

        unsafe {
            if RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut hkey) == ERROR_SUCCESS {
                let mut proxy_enable: u32 = 0;
                let mut dword_size: u32 = std::mem::size_of::<u32>() as u32;
                let mut val_type = REG_DWORD;
                let enable_name: Vec<u16> = "ProxyEnable\0".encode_utf16().collect();

                let status = RegQueryValueExW(
                    hkey,
                    enable_name.as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    &mut proxy_enable as *mut u32 as *mut u8,
                    &mut dword_size,
                );

                if status == ERROR_SUCCESS && proxy_enable == 1 {
                    let mut str_size: u32 = 0;
                    let server_name: Vec<u16> = "ProxyServer\0".encode_utf16().collect();

                    if RegQueryValueExW(
                        hkey,
                        server_name.as_ptr(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        &mut str_size,
                    ) == ERROR_SUCCESS
                        && str_size > 0
                    {
                        let mut buffer: Vec<u8> = vec![0; str_size as usize];
                        let mut str_type = REG_SZ;
                        if RegQueryValueExW(
                            hkey,
                            server_name.as_ptr(),
                            std::ptr::null_mut(),
                            &mut str_type,
                            buffer.as_mut_ptr(),
                            &mut str_size,
                        ) == ERROR_SUCCESS
                        {
                            RegCloseKey(hkey);
                            let u16_slice =
                                std::slice::from_raw_parts(buffer.as_ptr() as *const u16, (str_size as usize) / 2);
                            let proxy_str = String::from_utf16_lossy(u16_slice)
                                .trim_matches('\0')
                                .trim()
                                .to_string();

                            if !proxy_str.is_empty() {
                                let target = if proxy_str.contains('=') {
                                    proxy_str
                                        .split(';')
                                        .find(|p| p.starts_with("http=") || p.starts_with("https="))
                                        .and_then(|p| p.split('=').nth(1))
                                        .unwrap_or(&proxy_str)
                                } else {
                                    &proxy_str
                                };

                                let formatted = if !target.starts_with("http://") && !target.starts_with("socks5://") {
                                    format!("http://{}", target)
                                } else {
                                    target.to_string()
                                };
                                return Some(formatted);
                            }
                        }
                    }
                }
                RegCloseKey(hkey);
            }
        }
    }
    None
}
