// src-core/src/fixers/traits.rs

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use crate::{
    config_loader::CharacterConfig,
    domain::{context::ModContext, cst::IniCstDocument, pipeline::PipelineFixer},
    errors::FixerError,
};

/// Execution context passed to fixers, holding references to ModContext and character config.
pub struct FixerContext<'a> {
    pub mod_ctx: &'a mut ModContext,
    pub config: &'a CharacterConfig,
    pub char_name: &'a str,
}

impl<'a> FixerContext<'a> {
    pub fn new(mod_ctx: &'a mut ModContext, config: &'a CharacterConfig, char_name: &'a str) -> Self {
        Self {
            mod_ctx,
            config,
            char_name,
        }
    }

    #[inline]
    pub fn file_path(&self) -> &Path {
        &self.mod_ctx.file_path
    }

    #[inline]
    pub fn original_content(&self) -> &str {
        &self.mod_ctx.original_content
    }

    #[inline]
    pub fn original_hashes(&self) -> &HashSet<String> {
        &self.mod_ctx.original_hashes
    }

    #[inline]
    pub fn backed_up(&mut self) -> &mut HashSet<PathBuf> {
        &mut self.mod_ctx.backed_up
    }

    #[inline]
    pub fn session_time(&self) -> Option<&str> {
        self.mod_ctx.session_time.as_deref()
    }

    #[inline]
    pub fn backup_file(&mut self, path: &Path) -> Result<PathBuf, FixerError> {
        self.mod_ctx.backup_file(path)
    }

    #[inline]
    pub fn backup_new_file(&mut self, path: &Path) -> Result<(), FixerError> {
        self.mod_ctx.backup_new_file(path)
    }

    #[inline]
    pub fn ini(&self) -> &IniCstDocument {
        &self.mod_ctx.ini
    }

    #[inline]
    pub fn ini_mut(&mut self) -> &mut IniCstDocument {
        &mut self.mod_ctx.ini
    }

    #[inline]
    pub fn mark_ini_modified(&mut self) {
        self.mod_ctx.mark_ini_modified();
    }

    #[inline]
    pub fn mark_modified(&mut self) {
        self.mod_ctx.mark_ini_modified();
    }

    #[inline]
    pub fn component_indices(&self) -> &HashMap<u8, (usize, usize)> {
        self.mod_ctx.component_indices()
    }

    #[inline]
    pub fn vg_offsets(&self) -> &HashMap<u8, u16> {
        self.mod_ctx.vg_offsets()
    }

    #[inline]
    pub fn read_buffer(&mut self, path: &Path) -> Result<&[u8], FixerError> {
        self.mod_ctx.read_buffer(path)
    }

    #[inline]
    pub fn get_buffer_mut(&mut self, path: &Path) -> Result<&mut Vec<u8>, FixerError> {
        self.mod_ctx.get_buffer_mut(path)
    }

    #[inline]
    pub fn write_buffer_bytes(&mut self, path: &Path, data: Vec<u8>) {
        self.mod_ctx.write_buffer_bytes(path, data);
    }

    #[inline]
    pub fn collect_resource_buffers(&self, buf_type: crate::collector::BufferType) -> Vec<(PathBuf, Option<usize>)> {
        self.mod_ctx
            .ini
            .collect_resource_buffers(buf_type, &self.mod_ctx.file_path)
    }
}

pub trait Fixer: Send + Sync {
    /// Executes repair pass. Returns Ok(true) if modifications were made.
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError>;
}

// Blanket implementation of Fixer for all PipelineFixer types.
impl<T: PipelineFixer> Fixer for T {
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError> {
        PipelineFixer::run(self, ctx)
    }
}
