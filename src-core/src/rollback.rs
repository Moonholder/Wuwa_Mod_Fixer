// src-core/src/rollback.rs

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};
use walkdir::WalkDir;

use crate::utils::regex_patterns::BAK_RE;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackupFile {
    pub current_path: PathBuf,
    pub original_path: PathBuf,
    pub timestamp: String,
    #[allow(dead_code)]
    pub group_key: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackupGroup {
    pub group_key: String,
    pub files: Vec<BackupFile>,
}

/// Scans directory for .BAK backup files and groups them by session timestamp.
pub fn scan_backups(dir: &Path) -> Result<Vec<BackupGroup>> {
    let mut files_by_time: BTreeMap<String, Vec<BackupFile>> = BTreeMap::new();

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if let Some(caps) = BAK_RE.captures(file_name) {
                    if let (Some(orig), Some(ts)) = (caps.get(1), caps.get(2)) {
                        let original_name = orig.as_str();
                        let full_timestamp = ts.as_str();
                        let group_key = full_timestamp.to_string();
                        let original_path = path.with_file_name(original_name);

                        files_by_time.entry(group_key.clone()).or_default().push(BackupFile {
                            current_path: path.to_path_buf(),
                            original_path,
                            timestamp: full_timestamp.to_string(),
                            group_key,
                        });
                    }
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

/// Restores modified files to the specified session state and deletes subsequent backups.
pub fn execute_rollback(dir: &Path, target_group_key: &str) -> Result<()> {
    let all_groups = scan_backups(dir)?;

    let mut found = false;
    let mut all_candidates: Vec<BackupFile> = Vec::new();
    let mut files_to_delete: Vec<PathBuf> = Vec::new();

    for group in all_groups {
        if group.group_key.as_str() == target_group_key {
            found = true;
        }
        if group.group_key.as_str() >= target_group_key {
            for bf in group.files {
                files_to_delete.push(bf.current_path.clone());
                all_candidates.push(bf);
            }
        }
    }

    if !found {
        return Err(anyhow!("Backup group not found: {}", target_group_key));
    }

    let mut earliest_per_file: HashMap<PathBuf, BackupFile> = HashMap::new();
    for bf in all_candidates {
        let key = bf.original_path.clone();
        match earliest_per_file.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if bf.timestamp < entry.get().timestamp {
                    entry.insert(bf);
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(bf);
            }
        }
    }

    // Verify backup source files exist before mutating the filesystem.
    for (_, bf) in &earliest_per_file {
        if !bf.current_path.exists() {
            return Err(anyhow!("Backup source file missing: {}", bf.current_path.display()));
        }
    }

    // Restore files or delete newly injected files (tracked with 0-byte markers).
    for (original_path, bf) in &earliest_per_file {
        if let Ok(meta) = fs::metadata(&bf.current_path) {
            if meta.len() == 0 {
                if original_path.exists() {
                    fs::remove_file(original_path)?;
                    log::info!("Deleted added file during rollback: {}", original_path.display());
                }
                continue;
            }
        }
        if let Some(parent) = original_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::copy(&bf.current_path, original_path)?;
        log::info!("Restored: {} (from backup {})", original_path.display(), bf.timestamp);
    }

    // Clean up processed backup files.
    for bak_path in &files_to_delete {
        if bak_path.exists() {
            match fs::remove_file(bak_path) {
                Ok(_) => log::info!("Cleaned up: {}", bak_path.display()),
                Err(e) => log::warn!("Failed to clean {}: {}", bak_path.display(), e),
            }
        }
    }
    Ok(())
}

/// Computes total backup storage footprint, resolving zero-byte markers to target file sizes.
pub fn calculate_backup_size(dir: &Path) -> Result<(u64, usize)> {
    let mut total_size = 0;
    let mut total_count = 0;

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(caps) = BAK_RE.captures(file_name) else {
            continue;
        };
        let Ok(metadata) = fs::metadata(path) else { continue };

        total_count += 1;

        if metadata.len() > 0 {
            total_size += metadata.len();
        } else if let Some(orig) = caps.get(1) {
            let original_name = orig.as_str();
            let original_path = path.with_file_name(original_name);
            if let Ok(orig_meta) = fs::metadata(&original_path) {
                total_size += orig_meta.len();
            }
        }
    }

    Ok((total_size, total_count))
}

/// Deletes all .BAK backup files within the specified directory.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_and_rollback() -> Result<()> {
        let temp_dir = std::env::temp_dir().join(format!(
            "test_rollback_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir)?;

        let target_file = temp_dir.join("test.ini");
        let added_file = temp_dir.join("added.dds");

        // Simulate session backup: test.ini modified, added.dds created (0-byte marker)
        let t1 = "2026-08-29 01-00-00";
        let bak1 = temp_dir.join(format!("test.ini_{}.BAK", t1));
        let added_bak = temp_dir.join(format!("added.dds_{}.BAK", t1));

        fs::write(&target_file, "version 2")?;
        fs::write(&added_file, "new content")?;
        fs::write(&bak1, "version 1")?;
        fs::File::create(&added_bak)?;

        let groups = scan_backups(&temp_dir)?;
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].group_key, t1);
        assert_eq!(groups[0].files.len(), 2);

        let (size, count) = calculate_backup_size(&temp_dir)?;
        assert_eq!(count, 2);
        assert!(size > 0);

        execute_rollback(&temp_dir, t1)?;

        let content = fs::read_to_string(&target_file)?;
        assert_eq!(content, "version 1");
        assert!(!added_file.exists());
        assert!(!bak1.exists());
        assert!(!added_bak.exists());

        let _ = fs::remove_dir_all(&temp_dir);
        Ok(())
    }
}
