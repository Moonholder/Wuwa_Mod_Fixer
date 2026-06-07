// src-tauri/src/error.rs
// Structured error type for Tauri commands — frontend can distinguish error kinds

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error, Serialize)]
#[serde(tag = "kind", content = "message")]
pub enum AppError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Config parse error: {0}")]
    ConfigParse(String),

    #[error("File locked: {0}")]
    FileLocked(String),

    #[error("Update error: {0}")]
    Update(String),

    #[error("Internal error: {0}")]
    Internal(String),
}



// Convenience conversions
impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::ConfigParse(e.to_string())
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}

impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> Self {
        AppError::Network(e.to_string())
    }
}

impl From<semver::Error> for AppError {
    fn from(e: semver::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}
