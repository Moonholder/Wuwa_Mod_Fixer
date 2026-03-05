use anyhow::{Result, anyhow};
use regex::Regex;
use std::collections::{HashMap, BTreeMap};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

lazy_static::lazy_static! {
    // Match filenames like:
    //   new: filename_2026-03-01 15-32-14.182.BAK  (with millis)
    //   old: filename_2026-03-01 15-32-14.BAK      (without millis)
    static ref BAK_RE: Regex = Regex::new(r"^(.*)_(\d{4}-\d{2}-\d{2} \d{2}-\d{2}-\d{2}(?:\.\d{3})?)\.BAK$").unwrap();
}

#[derive(Debug, Clone)]
pub struct BackupFile {
    pub current_path: PathBuf,
    pub original_path: PathBuf,
    pub timestamp: String,      // full timestamp, may or may not include millis
    #[allow(dead_code)]
    pub group_key: String,      // truncated to minute  "YYYY-MM-DD HH-MM"
}

#[derive(Debug, Clone)]
pub struct BackupGroup {
    pub group_key: String,
    pub files: Vec<BackupFile>,
}

/// Scan all .BAK files under `dir`, grouped by minute-precision timestamp.
/// Files created within the same minute (i.e. from the same fix run) are
/// treated as a single rollback unit.
pub fn scan_backups(dir: &Path) -> Result<Vec<BackupGroup>> {
    let mut files_by_time: BTreeMap<String, Vec<BackupFile>> = BTreeMap::new();

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if let Some(caps) = BAK_RE.captures(file_name) {
                    let original_name = caps.get(1).unwrap().as_str();
                    let full_timestamp = caps.get(2).unwrap().as_str();
                    
                    // Take first 16 chars "YYYY-MM-DD HH-MM" as group key (minute precision)
                    let group_key = String::from(&full_timestamp[..full_timestamp.len().min(16)]);
                    let original_path = path.with_file_name(original_name);
                    
                    let backup_file = BackupFile {
                        current_path: path.to_path_buf(),
                        original_path,
                        timestamp: full_timestamp.to_string(),
                        group_key: group_key.clone(),
                    };

                    files_by_time.entry(group_key).or_default().push(backup_file);
                }
            }
        }
    }

    let mut groups: Vec<BackupGroup> = files_by_time
        .into_iter()
        .map(|(group_key, files)| BackupGroup { group_key, files })
        .collect();
    
    // Newest first
    groups.sort_by(|a, b| b.group_key.cmp(&a.group_key));

    Ok(groups)
}

/// Execute rollback with safe deduplication:
///
/// When the old fixer created multiple backups for the same file in one run
/// (e.g. VG remap at T1, stride fix at T2 for the same .buf), the T1 backup
/// is the true original and T2 is an intermediate state. This function:
///
/// 1. Collects ALL backups >= target_group_key
/// 2. For each original file, picks the EARLIEST backup (= true original)
/// 3. Restores that earliest backup to the original path
/// 4. Deletes all collected .BAK files (target + newer)
pub fn execute_rollback(dir: &Path, target_group_key: &str) -> Result<()> {
    let all_groups = scan_backups(dir)?;
    
    let mut found = false;
    let mut all_candidates: Vec<BackupFile> = Vec::new();
    let mut files_to_delete: Vec<PathBuf> = Vec::new();

    for group in &all_groups {
        if group.group_key == target_group_key {
            found = true;
        }
        
        // Collect everything >= target (target group + newer)
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

    // For each original file, find the EARLIEST backup (smallest timestamp = true original)
    let mut earliest_per_file: HashMap<PathBuf, BackupFile> = HashMap::new();
    for bf in all_candidates {
        let key = bf.original_path.clone();
        let entry = earliest_per_file.entry(key);
        entry
            .and_modify(|existing| {
                if bf.timestamp < existing.timestamp {
                    *existing = bf.clone();
                }
            })
            .or_insert(bf);
    }

    // 1. Restore: use the earliest backup for each file
    for (original_path, bf) in &earliest_per_file {
        fs::copy(&bf.current_path, original_path)?;
        log::info!(
            "Restored: {} (from backup {})",
            original_path.display(),
            bf.timestamp
        );
    }

    // 2. Cleanup: remove all .BAK files that were >= target
    for bak_path in &files_to_delete {
        match fs::remove_file(bak_path) {
            Ok(_) => log::info!("Cleaned up: {}", bak_path.display()),
            Err(e) => log::warn!("Failed to clean {}: {}", bak_path.display(), e),
        }
    }

    Ok(())
}
