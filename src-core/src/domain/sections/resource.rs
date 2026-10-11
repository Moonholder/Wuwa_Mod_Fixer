// src-core/src/domain/sections/resource.rs

use std::path::{Path, PathBuf};

use crate::domain::cst::IniCstSection;

pub struct ResourceSectionView<'a> {
    pub section: &'a mut IniCstSection,
}

impl<'a> ResourceSectionView<'a> {
    pub fn new(section: &'a mut IniCstSection) -> Self {
        Self { section }
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.section.name
    }

    pub fn filename(&self) -> Option<String> {
        self.section.get_unquoted_value("filename")
    }

    pub fn set_filename(&mut self, filename: &str) {
        let normalized = filename.replace('\\', "/");
        self.section.set_key_value("filename", &normalized, "");
    }

    pub fn resource_type(&self) -> Option<String> {
        self.section.get_unquoted_value("type")
    }

    pub fn stride(&self) -> Option<usize> {
        self.section.get_value("stride").and_then(|s| s.parse().ok())
    }

    pub fn set_stride(&mut self, stride: usize) {
        self.section.set_key_value("stride", &stride.to_string(), "");
    }

    /// Ensures target stride value is set, returning true if modified.
    pub fn ensure_stride(&mut self, target_stride: usize) -> bool {
        if self.stride() != Some(target_stride) {
            self.set_stride(target_stride);
            true
        } else {
            false
        }
    }

    /// Checks whether section represents a standard blend buffer resource.
    pub fn is_blend_buffer(&self) -> bool {
        let lower = self.section.name.to_ascii_lowercase();
        !lower.contains("override")
            && !lower.ends_with("rw")
            && !lower.ends_with("rw]")
            && lower != "resourceblendbuffernostride"
            && lower.starts_with("resourceblendbuffer")
    }

    /// Checks whether section represents a texture coordinate buffer resource.
    pub fn is_texcoord_buffer(&self) -> bool {
        let lower = self.section.name.to_ascii_lowercase();
        lower.starts_with("resourcetexcoordbuffer") || lower.starts_with("resourcetexcoord")
    }

    /// Checks whether section represents an index buffer resource.
    pub fn is_index_buffer(&self) -> bool {
        let lower = self.section.name.to_ascii_lowercase();
        lower.starts_with("resourceindexbuffer") || lower.starts_with("resourceindex")
    }

    /// Resolves relative target file path safely against base directory.
    pub fn resolved_path(&self, base_dir: &Path) -> Option<PathBuf> {
        self.filename()
            .and_then(|f| crate::utils::fs_utils::resolve_relative_path(base_dir, &f))
    }
}
