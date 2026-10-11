use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use log::{debug, info};

use crate::{errors::FixerError, t};

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

pub fn create_backup_with_time(path: &Path, datetime: &str) -> Result<PathBuf, FixerError> {
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

pub fn create_backup(path: &Path) -> Result<PathBuf, FixerError> {
    let datetime = chrono::Local::now().format("%Y-%m-%d %H-%M-%S").to_string();
    create_backup_with_time(path, &datetime)
}

/// Like `create_backup`, but skips if `path` was already backed up in this run.
/// This prevents backing up intermediate (already-modified) states when
/// multiple fix stages (VGs remap, stride fix) modify the same .buf file.
pub fn create_backup_once_with_time(
    path: &Path,
    backed_up: &mut HashSet<PathBuf>,
    datetime: &str,
) -> Result<PathBuf, FixerError> {
    let canonical = if path.exists() {
        path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
    } else {
        path.to_path_buf()
    };
    if backed_up.contains(&canonical) {
        debug!("Skipping duplicate backup for: {}", path.display());
        return Ok(path.to_path_buf()); // already backed up, skip
    }
    let result = create_backup_with_time(path, datetime)?;
    backed_up.insert(canonical);
    Ok(result)
}

pub fn create_backup_once(path: &Path, backed_up: &mut HashSet<PathBuf>) -> Result<PathBuf, FixerError> {
    let datetime = chrono::Local::now().format("%Y-%m-%d %H-%M-%S").to_string();
    create_backup_once_with_time(path, backed_up, &datetime)
}

/// Create a 0-byte backup for a newly created file (which didn't exist before).
/// This is used for rolling back operations that create new files.
pub fn create_new_file_backup_with_time(
    path: &Path,
    backed_up: &mut HashSet<PathBuf>,
    datetime: &str,
) -> Result<(), FixerError> {
    let canonical = if path.exists() {
        path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
    } else {
        path.to_path_buf()
    };
    if backed_up.contains(&canonical) {
        return Ok(());
    }

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

pub fn create_new_file_backup(path: &Path, backed_up: &mut HashSet<PathBuf>) -> Result<(), FixerError> {
    let datetime = chrono::Local::now().format("%Y-%m-%d %H-%M-%S").to_string();
    create_new_file_backup_with_time(path, backed_up, &datetime)
}

pub fn ensure_subdir(base_dir: &Path, sub_dir: &str) -> Result<PathBuf, FixerError> {
    let dir_path = base_dir.join(sub_dir);
    if !dir_path.exists() {
        fs::create_dir_all(&dir_path)?;
    }
    Ok(dir_path)
}

/// Safely resolves a relative path against a base directory, trimming whitespace, quotes, and leading slashes.
pub fn resolve_relative_path(base_dir: &Path, raw_path: &str) -> Option<PathBuf> {
    let clean = raw_path.trim().trim_matches('"');
    let clean = clean.trim_start_matches(|c: char| c == '/' || c == '\\');
    if clean.is_empty() {
        return None;
    }
    Some(base_dir.join(clean))
}
