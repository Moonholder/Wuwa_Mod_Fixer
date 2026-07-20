use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FixerError {
    #[error("Failed to read file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Permission check failed: could not create temp file at {path}")]
    PermissionCreateFailed {
        path: PathBuf,
        #[source]
        error: std::io::Error,
    },

    #[error("Permission check failed: could not remove temp file at {path}")]
    PermissionRemoveFailed {
        path: PathBuf,
        #[source]
        error: std::io::Error,
    },

    #[error("Failed to create backup for {path}")]
    BackupFailed { path: PathBuf },

    #[error(transparent)]
    AnyhowError(#[from] anyhow::Error),
}

#[derive(Error, Debug)]
pub enum ShapeKeyError {
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Internal shape key error: {0}")]
    InternalError(String),
}
