use wuwa_mod_core as core;
use crate::error::AppError;

#[tauri::command]
pub async fn scan_backups(path: String) -> Result<Vec<core::rollback::BackupGroup>, AppError> {
    tokio::task::spawn_blocking(move || {
        core::rollback::scan_backups(std::path::Path::new(&path))
            .map_err(|e| AppError::Io(e.to_string()))
    })
    .await
    .unwrap_or_else(|_| Err(AppError::Internal("Task panicked".to_string())))
}

#[tauri::command]
pub async fn do_rollback(path: String, group_key: String) -> Result<(), AppError> {
    tokio::task::spawn_blocking(move || {
        core::rollback::execute_rollback(std::path::Path::new(&path), &group_key)
            .map_err(|e| AppError::Io(e.to_string()))
    })
    .await
    .unwrap_or_else(|_| Err(AppError::Internal("Task panicked".to_string())))
}

#[tauri::command]
pub async fn get_backup_size(path: String) -> Result<(u64, usize), AppError> {
    tokio::task::spawn_blocking(move || {
        core::rollback::calculate_backup_size(std::path::Path::new(&path))
            .map_err(|e| AppError::Io(e.to_string()))
    })
    .await
    .unwrap_or_else(|_| Err(AppError::Internal("Task panicked".to_string())))
}

#[tauri::command]
pub async fn clean_backups(path: String) -> Result<(), AppError> {
    tokio::task::spawn_blocking(move || {
        core::rollback::delete_all_backups(std::path::Path::new(&path))
            .map_err(|e| AppError::Io(e.to_string()))
    })
    .await
    .unwrap_or_else(|_| Err(AppError::Internal("Task panicked".to_string())))
}