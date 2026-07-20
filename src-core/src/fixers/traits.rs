use crate::config_loader::CharacterConfig;
use crate::errors::FixerError;
use crate::utils::ini_parser::IniDocument;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct FixerContext<'a> {
    pub file_path: &'a Path,
    pub ini: &'a mut IniDocument,
    pub config: &'a CharacterConfig,
    pub char_name: &'a str,
    pub backed_up: &'a mut HashSet<PathBuf>,
    pub original_content: &'a str,
    pub original_hashes: &'a HashSet<String>,
    pub enable_stable_texture: bool,
    pub enable_fix_aemeath_mech: bool,
    pub aero_fix_mode: u8,
    pub enable_texture_override: bool,
}

pub trait Fixer {
    /// 执行修复逻辑。返回 Ok(true) 表示文件已被修改，需要保存。
    fn run(&self, ctx: &mut FixerContext) -> Result<bool, FixerError>;
}
