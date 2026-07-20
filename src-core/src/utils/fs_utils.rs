use log::{debug, info};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::errors::FixerError;
use crate::t;

pub fn check_write_permission(path: &Path) -> Result<(), FixerError> {
    let temp_file_name = format!(".tmp_permission_check_{}", std::process::id());
    let temp_file_path = path.join(temp_file_name);

    match fs::File::create(&temp_file_path) {
        Ok(_) => {
            if let Err(e) = fs::remove_file(&temp_file_path) {
                Err(FixerError::PermissionRemoveFailed {
                    path: temp_file_path,
                    error: e,
                })
            } else {
                Ok(())
            }
        }
        Err(e) => Err(FixerError::PermissionCreateFailed {
            path: path.to_path_buf(),
            error: e,
        }),
    }
}

pub fn create_backup(path: &Path) -> Result<PathBuf, FixerError> {
    let datetime = chrono::Local::now().format("%Y-%m-%d %H-%M-%S").to_string();
    if let Some(file_name) = path.file_name() {
        if let Some(name) = file_name.to_str() {
            let backup_name = format!("{}_{}.BAK", name, datetime);
            let backup_path = path.with_file_name(backup_name);
            fs::copy(path, &backup_path)?;
            info!("{}", t!(backup_created, backup_path = backup_path.display()));
            return Ok(backup_path);
        }
    }
    Err(FixerError::BackupFailed {
        path: path.to_path_buf(),
    })
}

/// Like `create_backup`, but skips if `path` was already backed up in this run.
/// This prevents backing up intermediate (already-modified) states when
/// multiple fix stages (VGs remap, stride fix) modify the same .buf file.
pub fn create_backup_once(path: &Path, backed_up: &mut HashSet<PathBuf>) -> Result<PathBuf, FixerError> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if backed_up.contains(&canonical) {
        debug!("Skipping duplicate backup for: {}", path.display());
        return Ok(path.to_path_buf()); // already backed up, skip
    }
    let result = create_backup(path)?;
    backed_up.insert(canonical);
    Ok(result)
}

/// Create a 0-byte backup for a newly created file (which didn't exist before).
/// This is used for rolling back operations that create new files.
pub fn create_new_file_backup(path: &Path, backed_up: &mut HashSet<PathBuf>) -> Result<(), FixerError> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if backed_up.contains(&canonical) {
        return Ok(());
    }

    let datetime = chrono::Local::now().format("%Y-%m-%d %H-%M-%S").to_string();
    if let Some(file_name) = path.file_name() {
        if let Some(name) = file_name.to_str() {
            let backup_name = format!("{}_{}.BAK", name, datetime);
            let backup_path = path.with_file_name(backup_name);
            fs::File::create(&backup_path)?;
            info!("Create new file backup: {}", backup_path.display());
            backed_up.insert(canonical);
            return Ok(());
        }
    }
    Err(FixerError::BackupFailed {
        path: path.to_path_buf(),
    })
}

pub fn ensure_subdir(base_dir: &Path, sub_dir: &str) -> Result<PathBuf, FixerError> {
    let dir_path = base_dir.join(sub_dir);
    if !dir_path.exists() {
        fs::create_dir_all(&dir_path)?;
    }
    Ok(dir_path)
}
