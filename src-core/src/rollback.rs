// src-core/src/rollback.rs
// Migrated verbatim from src/rollback.rs

use anyhow::{Result, anyhow};
use regex::Regex;
use std::collections::{HashMap, BTreeMap};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

lazy_static::lazy_static! {
    static ref BAK_RE: Regex = Regex::new(
        r"^(.*)_(\d{4}-\d{2}-\d{2} \d{2}-\d{2}-\d{2}(?:\.\d{3})?)\.BAK$"
    ).unwrap();
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackupFile {
    pub current_path:  PathBuf,
    pub original_path: PathBuf,
    pub timestamp:     String,
    #[allow(dead_code)]
    pub group_key:     String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackupGroup {
    pub group_key: String,
    pub files:     Vec<BackupFile>,
}

pub fn scan_backups(dir: &Path) -> Result<Vec<BackupGroup>> {
    let mut files_by_time: BTreeMap<String, Vec<BackupFile>> = BTreeMap::new();

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if let Some(caps) = BAK_RE.captures(file_name) {
                    let original_name  = caps.get(1).unwrap().as_str();
                    let full_timestamp = caps.get(2).unwrap().as_str();
                    let group_key = String::from(&full_timestamp[..full_timestamp.len().min(16)]);
                    let original_path  = path.with_file_name(original_name);

                    files_by_time
                        .entry(group_key.clone())
                        .or_default()
                        .push(BackupFile {
                            current_path: path.to_path_buf(),
                            original_path,
                            timestamp: full_timestamp.to_string(),
                            group_key,
                        });
                }
            }
        }
    }

    let mut groups: Vec<BackupGroup> = files_by_time
        .into_iter()
        .map(|(group_key, files)| BackupGroup { group_key, files })
        .collect();
    groups.sort_by(|a, b| b.group_key.cmp(&a.group_key));
    Ok(groups)
}

pub fn execute_rollback(dir: &Path, target_group_key: &str) -> Result<()> {
    let all_groups = scan_backups(dir)?;

    let mut found            = false;
    let mut all_candidates:  Vec<BackupFile> = Vec::new();
    let mut files_to_delete: Vec<PathBuf>    = Vec::new();

    for group in &all_groups {
        if group.group_key == target_group_key { found = true; }
        if group.group_key >= target_group_key.to_string() {
            for bf in &group.files {
                all_candidates.push(bf.clone());
                files_to_delete.push(bf.current_path.clone());
            }
        }
    }

    if !found {
        return Err(anyhow!("Backup group not found: {}", target_group_key));
    }

    let mut earliest_per_file: HashMap<PathBuf, BackupFile> = HashMap::new();
    for bf in all_candidates {
        let key = bf.original_path.clone();
        earliest_per_file
            .entry(key)
            .and_modify(|existing| {
                if bf.timestamp < existing.timestamp { *existing = bf.clone(); }
            })
            .or_insert(bf);
    }

    for (original_path, bf) in &earliest_per_file {
        fs::copy(&bf.current_path, original_path)?;
        log::info!("Restored: {} (from backup {})", original_path.display(), bf.timestamp);
    }

    for bak_path in &files_to_delete {
        match fs::remove_file(bak_path) {
            Ok(_)  => log::info!("Cleaned up: {}", bak_path.display()),
            Err(e) => log::warn!("Failed to clean {}: {}", bak_path.display(), e),
        }
    }
    Ok(())
}

pub fn calculate_backup_size(dir: &Path) -> Result<(u64, usize)> {
    let mut total_size = 0;
    let mut total_count = 0;

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if BAK_RE.is_match(file_name) {
                    if let Ok(metadata) = fs::metadata(path) {
                        total_size += metadata.len();
                        total_count += 1;
                    }
                }
            }
        }
    }

    Ok((total_size, total_count))
}

pub fn delete_all_backups(dir: &Path) -> Result<()> {
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if BAK_RE.is_match(file_name) {
                    fs::remove_file(path)?;
                }
            }
        }
    }
    Ok(())
}
