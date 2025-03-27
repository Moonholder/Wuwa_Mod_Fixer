#[macro_use]
extern crate log;

mod localization;
use localization::config::get_lang;
mod config_loader;
use config_loader::{CharacterConfig, Replacement, ReplacementRule, VertexRemapConfig};

use anyhow::{Error, Result};
use backtrace::Backtrace;
use inquire::{Confirm, Text};
use log::LevelFilter;
use regex::Regex;
use std::borrow::Cow;
use std::io::Write;
use std::panic;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

struct ModFixer {
    characters: HashMap<String, CharacterConfig>,
    enable_texture_override: bool,
    checksum_regex: Regex,
}

impl ModFixer {
    fn new(characters: &HashMap<String, CharacterConfig>, enable_texture_override: bool) -> Self {
        Self {
            characters: characters.clone(),
            enable_texture_override,
            checksum_regex: Regex::new(r"(checksum\s*=\s*)\d+").unwrap(),
        }
    }

    fn process_directory(&self, path: &Path) -> Result<()> {
        info!("{}", t!(start_processing, mod_folder_path = path.display()));

        let mut success = 0;
        let mut skipped = 0;

        for entry in WalkDir::new(path) {
            let entry = entry?;
            let path = entry.path();

            if !self.is_target_file(path) {
                continue;
            }

            match self.process_file(path) {
                Ok(true) => {
                    success += 1;
                }
                Ok(false) => {
                    skipped += 1;
                }
                Err(e) => {
                    error!(
                        "{}",
                        t!(
                            process_file_error,
                            file_path = path.display(),
                            exception = e.to_string()
                        )
                    );
                    skipped += 1;
                }
            }
            info!("---------------------------------------------")
        }

        info!(
            "{}",
            t!(
                process_folder_done,
                folder_path = path.display(),
                success_count = success,
                failure_count = skipped
            )
        );
        Ok(())
    }

    fn process_file(&self, path: &Path) -> Result<bool> {
        let content = fs::read_to_string(path)?;
        let mut modified = false;
        let mut match_old_mod = false;
        let mut new_content = content.clone();
        let mut match_vg_maps = Option::<&Vec<VertexRemapConfig>>::None;
        info!("{}", t!(process_file_start, file_path = path.display()));

        // 处理每个角色的哈希替换
        for (char_name, config) in &self.characters {
            // 检查vb0哈希
            let Some(vb0) = config.main_hashes.first() else {
                continue;
            };

            if !self.any_match(&content, vb0) {
                if let Some(shape_key_hashes) = config.main_hashes.get(1) {
                    if self.any_match(&content, shape_key_hashes) {
                        info!("{}", t!(found_old_mod));
                        match_old_mod = true;
                    }
                }
                if !match_old_mod {
                    continue;
                }
            }

            info!("{}", t!(match_character_prompt, character = char_name));

            // 主哈希和贴图哈希替换
            modified |= self.replace_hashes(&mut new_content, &config.main_hashes);
            modified |= self.replace_hashes(&mut new_content, &config.texture_hashes);

            if let Some(checksum) = &config.checksum {
                if !content.contains(&format!("checksum = {}", checksum)) {
                    new_content = self
                        .checksum_regex
                        .replace_all(&new_content, &format!("checksum = {}", checksum))
                        .into_owned();
                    info!(
                        "checksum_replaced: {char_name} = {checksum}",
                        char_name = char_name,
                        checksum = checksum
                    );
                    modified = true;
                }
            }

            // vertex_offset_count 替换
            modified |= self.replace_vertex_offset_count(&mut new_content, &config.rules);

            // 战损,湿身修复
            if self.enable_texture_override {
                if let Some(char_states) = &config.states {
                    for state_name in char_states.keys() {
                        if let Some(state_map) = char_states.get(state_name) {
                            modified |= self.texture_override_redirection(
                                &mut new_content,
                                state_map,
                                state_name.as_str(),
                            )?;
                        }
                    }
                }
            }

            match_vg_maps = config.vg_remaps.as_ref();

            break;
        }

        // 处理顶点组和组件重映射
        let mut buf_files_modified = false;
        if let Some(vg_maps) = match_vg_maps {
            buf_files_modified = self.remaps(&content, path, vg_maps)?;
        }

        if modified {
            let backup_path = self.create_backup(path)?;
            info!(
                "{}",
                t!(backup_created, backup_path = backup_path.display())
            );
            fs::write(path, new_content)?;
            info!("{}", t!(process_file_done, file_path = path.display()));
        }

        if !modified && !buf_files_modified {
            info!("{}", t!(no_need_fix));
        }

        Ok(modified || buf_files_modified)
    }

    fn replace_hashes(&self, content: &mut String, hashes: &[Replacement]) -> bool {
        let mut modified = false;
        for hr in hashes {
            for old_hash in &hr.old {
                if content.contains(old_hash) {
                    let re = Regex::new(&format!(r"\bhash\s*=\s*{}\b", regex::escape(old_hash)))
                        .unwrap();
                    *content = re
                        .replace_all(content, &format!("hash = {}", hr.new))
                        .to_string();
                    modified = true;
                    info!(
                        "{old_hash} -> {new_hash}",
                        old_hash = old_hash,
                        new_hash = hr.new
                    );
                }
            }
        }
        modified
    }

    fn texture_override_redirection(
        &self,
        content: &mut String,
        tex_override_map: &HashMap<String, String>,
        header_suffix: &str,
    ) -> Result<bool> {
        let mut new_fix_sections: Vec<String> = Vec::new();

        for (changed_hash, original_hash) in tex_override_map {
            if !content.contains(original_hash) || content.contains(changed_hash) {
                continue;
            }

            let match_texture_override_content =
                self.get_texture_override_content_after_match_priority(original_hash, content)?;
            let clone_content = match_texture_override_content.content.trim();
            // 检查是否有需要修复的TextureOverrideTexture节
            if !clone_content.is_empty() {
                let mut section_header = match_texture_override_content.section_header.trim();
                if let Some(stripped) = section_header
                    .strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                {
                    section_header = stripped;
                } else {
                    warn!("Invalid section header format: {}", section_header);
                    continue;
                }
                info!("{} -> {}: {}", changed_hash, original_hash, section_header);
                let texture_override_section = &format!("[{}_{}]", section_header, header_suffix);
                let new_section_content = format!(
                    "{}\nhash = {}\nmatch_priority = 0\n{}",
                    texture_override_section, changed_hash, clone_content
                );
                new_fix_sections.push(new_section_content);
            }
        }

        if new_fix_sections.is_empty() {
            return Ok(false);
        }

        content.push_str(&format!("\n{}\n", new_fix_sections.join("\n\n")));

        Ok(true)
    }

    fn get_texture_override_content_after_match_priority(
        &self,
        original_hash: &str,
        content: &str,
    ) -> Result<MatchTextureOverrideContent> {
        let lines = content.trim().split('\n');

        let mut found_section = false;
        let mut match_priority_found = false;
        let mut section_header = String::new();
        let mut content = Vec::new();

        for line in lines {
            let line = line.trim();

            // 检查是否是以 [TextureOverride 开头的节
            if !match_priority_found && line.starts_with("[TextureOverride") {
                section_header = line.to_string();
                found_section = false; // 每次新节开始，重置标记
                continue; // 继续到下一行
            }

            // 如果找到了对应的节
            if found_section {
                // 如果找到match_priority则可以开始提取内容
                if line.starts_with("match_priority") {
                    match_priority_found = true;
                    continue;
                }

                // 一旦找到了match_priority后，继续收集内容
                if match_priority_found {
                    // 如果找到新的节，则结束收集
                    if line.starts_with('[') {
                        break;
                    }
                    if !line.starts_with(";") {
                        content.push(line.to_string());
                    }
                }
            }

            if line.contains(original_hash) {
                // 如果当前行中包含所需的hash，表示在相应的节中
                found_section = true;
            }
        }

        Ok(MatchTextureOverrideContent {
            section_header,
            content: content.join("\n"),
        })
    }

    fn any_match(&self, content: &str, vb0: &Replacement) -> bool {
        vb0.old.iter().any(|h| content.contains(h)) || content.contains(&vb0.new)
    }

    fn create_backup(&self, path: &Path) -> Result<PathBuf, Error> {
        let datetime = chrono::Local::now().format("%Y-%m-%d %H-%M-%S").to_string();
        if let Some(file_name) = path.file_name() {
            if let Some(name) = file_name.to_str() {
                let backup_name = format!("{}_{}.BAK", name, datetime);
                let backup_path = path.with_file_name(backup_name);
                fs::copy(path, &backup_path)?;
                return Ok(backup_path);
            }
        }
        Err(Error::msg(t!(backup_failed, file_path = path.display())))
    }

    fn is_target_file(&self, path: &Path) -> bool {
        let exclude = ["desktop", "ntuser", "disabled_backup", "disabled"];
        if let Some(file_name) = path.file_name() {
            if let Some(name_str) = file_name.to_str() {
                let name = name_str.to_lowercase();
                return path.extension().map_or(false, |e| e == "ini")
                    && !exclude.iter().any(|kw| name.contains(kw));
            }
        }
        false
    }

    fn replace_vertex_offset_count(
        &self,
        content: &mut String,
        rules_option: &Option<Vec<ReplacementRule>>,
    ) -> bool {
        let mut modified = false;
        let mut new_content = String::with_capacity(content.len());
        if let Some(rules) = rules_option {
            for (line_num, line) in content.lines().enumerate() {
                let mut cow_line = Cow::Borrowed(line);
                let mut log_message = None;

                'rule_loop: for rule in rules {
                    // 快速跳过不匹配的前缀
                    if !cow_line.trim_start().starts_with(&rule.line_prefix) {
                        continue;
                    }

                    for replacement in &rule.replacements {
                        for old_val in &replacement.old {
                            if let Some(pos) = cow_line.find(old_val) {
                                let mut new_line = String::with_capacity(cow_line.len());
                                new_line.push_str(&cow_line[..pos]);
                                new_line.push_str(&replacement.new);
                                new_line.push_str(&cow_line[pos + old_val.len()..]);

                                cow_line = Cow::Owned(new_line);
                                log_message = Some(format!(
                                    "[L{}] {} -> {}",
                                    line_num + 1,
                                    old_val,
                                    replacement.new
                                ));
                                break 'rule_loop;
                            }
                        }
                    }
                }

                if let Some(msg) = log_message {
                    info!("{}", msg);
                    modified = true;
                }
                new_content.push_str(&cow_line);
                new_content.push('\n');
            }
            if modified {
                *content = new_content;
            }
        };
        return modified;
    }

    fn remaps(
        &self,
        content: &String,
        file_path: &Path,
        vg_remaps: &[VertexRemapConfig],
    ) -> Result<bool> {
        let mut modified = false;
        let meshes_folder = Path::new(file_path.parent().unwrap()).join("Meshes");
        let blend_files: Vec<String> = if meshes_folder.is_dir() {
            fs::read_dir(&meshes_folder)
                .map(|entries| {
                    entries
                        .filter_map(|entry| {
                            let path = entry.ok()?.path();
                            if !path.is_file() {
                                return None;
                            }

                            let name = path.file_name()?.to_str()?.to_lowercase();
                            if name.contains("blend")
                                && name.contains(".buf")
                                && !name.ends_with(".bak")
                            {
                                Some(path.file_name()?.to_str()?.to_string())
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let use_merged_skeleton = content.contains("[ResourceMergedSkeleton]");

        for blend_file in blend_files {
            let blend_path = meshes_folder.join(&blend_file);
            let blend_data = fs::read(&blend_path)?;
            let mut blend_data = blend_data.to_vec();
            let mut match_flag = false;
            let mut apply_flag = false;

            for vg_remap in vg_remaps {
                if match_flag || vg_remap.trigger_hash.iter().any(|h| content.contains(h)) {
                    apply_flag = vg_remap.apply_remap(&mut blend_data, use_merged_skeleton);
                    match_flag = true;
                }
            }

            if apply_flag {
                modified = true;
                info!("{}", t!(remapped_successfully));
                let backup_path = self.create_backup(&blend_path)?;
                info!(
                    "{}",
                    t!(backup_created, backup_path = backup_path.display())
                );
                fs::write(&blend_path, blend_data)?;
            }
        }
        return Ok(modified);
    }
}

struct MatchTextureOverrideContent {
    section_header: String,
    content: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .format(|buf, record| {
            let level_style = buf.default_level_style(record.level());
            writeln!(
                buf,
                "[{}] {}",
                level_style.value(record.level()),
                record.args()
            )
        })
        .init();

    // 加载配置
    config_loader::init_config().await;
    // 版本检查
    let available = match config_loader::check_version() {
        Ok(msg) => {
            println!(
                "✅ {}: {}\n",
                if get_lang() == "zh" {
                    "版本检查通过"
                } else {
                    "Version check passed"
                },
                msg
            );
            true
        }
        Err(e) => {
            eprintln!(
                "❌ {}: {}\n",
                if get_lang() == "zh" {
                    "版本检查失败"
                } else {
                    "Version check failed"
                },
                e
            );
            false
        }
    };

    if !available {
        let _ = std::io::stdin().read_line(&mut String::new());
        return Ok(());
    }

    // 显示标题
    println!("{}", t!(title));
    println!("{}", t!(intro));
    println!("{}", t!(intro_note));
    println!("{}", t!(compatibility_note));
    println!("{}", t!(graphics_setting_note));
    println!("{}", t!(graphics_quality_note));
    println!("\n");

    // 用户输入
    let path = Text::new(t!(input_folder_prompt))
        .with_default(".")
        .prompt()?;

    println!("{}", t!(texture_override_note));

    let enable_texture_override = Confirm::new(t!(texture_override_prompt))
        .with_default(false)
        .prompt()?;

    // 处理文件
    let fixer = ModFixer::new(config_loader::characters(), enable_texture_override);
    panic::set_hook(Box::new(|info| {
        let backtrace = Backtrace::new();
        error!("{}", t!(error_occurred, error = info.to_string()));
        debug!("{:?}", backtrace);
    }));

    let result = panic::catch_unwind(|| {
        let _ = fixer.process_directory(Path::new(&path));
        info!("{}", t!(all_done));
    });

    if let Err(_) = result {
        error!("{}", t!(error_prompt));
    }

    let _ = std::io::stdin().read_line(&mut String::new()); // 等待按键
    Ok(())
}
