// src-core/src/domain/context.rs

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use crate::{domain::cst::IniCstDocument, errors::FixerError, utils::fs_utils};

/// Aggregate root and unit of work managing CST state, buffer caches, and writeback transactions.
pub struct ModContext {
    pub file_path: PathBuf,
    pub mod_dir: PathBuf,
    pub ini: IniCstDocument,
    pub original_content: String,
    pub original_hashes: HashSet<String>,
    pub backed_up: HashSet<PathBuf>,
    pub ini_modified: bool,
    pub session_time: Option<String>,

    pub enable_stable_texture: bool,
    pub enable_fix_aemeath_mech: bool,
    pub enable_rendering33_fix: bool,
    pub aero_fix_mode: u8,
    pub enable_texture_override: bool,

    indices_cache: OnceLock<HashMap<u8, (usize, usize)>>,
    vg_offsets_cache: OnceLock<HashMap<u8, u16>>,

    buffer_cache: HashMap<PathBuf, Vec<u8>>,
    modified_buffers: HashMap<PathBuf, Vec<u8>>,
}

impl ModContext {
    pub fn new(
        file_path: &Path,
        content: String,
        original_hashes: HashSet<String>,
        enable_stable_texture: bool,
        enable_fix_aemeath_mech: bool,
        enable_rendering33_fix: bool,
        aero_fix_mode: u8,
        enable_texture_override: bool,
    ) -> Self {
        let mod_dir = file_path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
        let ini = IniCstDocument::parse(&content);

        Self {
            file_path: file_path.to_path_buf(),
            mod_dir,
            ini,
            original_content: content,
            original_hashes,
            backed_up: HashSet::new(),
            ini_modified: false,
            session_time: None,
            enable_stable_texture,
            enable_fix_aemeath_mech,
            enable_rendering33_fix,
            aero_fix_mode,
            enable_texture_override,
            indices_cache: OnceLock::new(),
            vg_offsets_cache: OnceLock::new(),
            buffer_cache: HashMap::new(),
            modified_buffers: HashMap::new(),
        }
    }

    /// Creates an idempotent backup of the target file tagged with the session timestamp.
    pub fn backup_file(&mut self, path: &Path) -> Result<PathBuf, FixerError> {
        if let Some(ref st) = self.session_time {
            fs_utils::create_backup_once_with_time(path, &mut self.backed_up, st)
        } else {
            fs_utils::create_backup_once(path, &mut self.backed_up)
        }
    }

    /// Records a zero-byte marker backup for newly created files to support full rollback.
    pub fn backup_new_file(&mut self, path: &Path) -> Result<(), FixerError> {
        if let Some(ref st) = self.session_time {
            fs_utils::create_new_file_backup_with_time(path, &mut self.backed_up, st)
        } else {
            fs_utils::create_new_file_backup(path, &mut self.backed_up)
        }
    }

    /// Returns parsed component indices, lazily cached from the CST document.
    pub fn component_indices(&self) -> &HashMap<u8, (usize, usize)> {
        self.indices_cache.get_or_init(|| self.ini.collect_component_indices())
    }

    /// Returns parsed vertex group offsets, lazily cached from the CST document.
    pub fn vg_offsets(&self) -> &HashMap<u8, u16> {
        self.vg_offsets_cache.get_or_init(|| self.ini.collect_vg_offsets())
    }

    /// Reads buffer content, serving from memory cache when available.
    pub fn read_buffer(&mut self, path: &Path) -> Result<&[u8], FixerError> {
        let canon = path.to_path_buf();
        if self.modified_buffers.contains_key(&canon) {
            return self.modified_buffers.get(&canon).map(|b| b.as_slice()).ok_or_else(|| {
                FixerError::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Buffer not found: {}", path.display()),
                ))
            });
        }
        if !self.buffer_cache.contains_key(&canon) {
            let data = std::fs::read(path)?;
            self.buffer_cache.insert(canon.clone(), data);
        }
        self.buffer_cache.get(&canon).map(|b| b.as_slice()).ok_or_else(|| {
            FixerError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Buffer not found: {}", path.display()),
            ))
        })
    }

    /// Retrieves a mutable reference to buffer data, queueing it for transactional writeback.
    pub fn get_buffer_mut(&mut self, path: &Path) -> Result<&mut Vec<u8>, FixerError> {
        let canon = path.to_path_buf();
        if !self.modified_buffers.contains_key(&canon) {
            let data = if let Some(cached) = self.buffer_cache.get(&canon) {
                cached.clone()
            } else {
                std::fs::read(path)?
            };
            self.modified_buffers.insert(canon.clone(), data);
        }
        self.modified_buffers.get_mut(&canon).ok_or_else(|| {
            FixerError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Buffer not found: {}", path.display()),
            ))
        })
    }

    /// Stages modified buffer data for commit.
    pub fn write_buffer_bytes(&mut self, path: &Path, data: Vec<u8>) {
        self.modified_buffers.insert(path.to_path_buf(), data);
    }

    /// Marks the INI document as modified.
    pub fn mark_ini_modified(&mut self) {
        self.ini_modified = true;
    }

    /// Backward-compatible alias for mark_ini_modified.
    pub fn mark_modified(&mut self) {
        self.ini_modified = true;
    }

    /// Commits staged mutations, writing dirty buffers and INI changes to disk with backups.
    pub fn commit(&mut self) -> Result<bool, FixerError> {
        let has_buffer_changes = !self.modified_buffers.is_empty();
        if !self.ini_modified && !has_buffer_changes {
            return Ok(false);
        }

        // Flush dirty buffer files with backups.
        for (buf_path, buf_data) in &self.modified_buffers {
            if let Some(ref st) = self.session_time {
                fs_utils::create_backup_once_with_time(buf_path, &mut self.backed_up, st)?;
            } else {
                fs_utils::create_backup_once(buf_path, &mut self.backed_up)?;
            }
            std::fs::write(buf_path, buf_data)?;
        }

        // Flush INI document if marked modified.
        if self.ini_modified {
            if let Some(ref st) = self.session_time {
                fs_utils::create_backup_once_with_time(&self.file_path, &mut self.backed_up, st)?;
            } else {
                fs_utils::create_backup_once(&self.file_path, &mut self.backed_up)?;
            }
            std::fs::write(&self.file_path, self.ini.to_string())?;
        }

        Ok(true)
    }
}
