#[macro_use]
extern crate log;

#[macro_use]
mod localization;
mod config_loader;
use config_loader::{CharacterConfig, Replacement, ReplacementRule, VertexRemapConfig};
mod collector;

use anyhow::{Error, Result, anyhow};
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

const EARLY_CHARACTERS: [&str; 20] = [
    "RoverFemale",
    "RoverMale",
    "Yangyang",
    "Baizhi",
    "Chixia",
    "Jianxin",
    "Danjin",
    "Lingyang",
    "Encore",
    "Sanhua",
    "Verina",
    "Taoqi",
    "Calcharo",
    "Yuanwu",
    "Mortefi",
    "Aalto",
    "Jiyan",
    "Yinlin",
    "Jinhsi",
    "Changli",
];

struct ModFixer {
    characters: HashMap<String, CharacterConfig>,
    hash_to_character: HashMap<String, String>,
    enable_texture_override: bool,
    checksum_regex: Regex,
    hash_re: Regex,
    blend_block_re: Regex,
    stride_re: Regex,
}

impl ModFixer {
    fn new(characters: &HashMap<String, CharacterConfig>, enable_texture_override: bool) -> Self {
        let mut hash_to_character = HashMap::new();

        for (char_name, config) in characters.iter() {
            let static_hashes = config.main_hashes.iter();
            for replacement in static_hashes {
                for old_hash in &replacement.old {
                    hash_to_character.insert(old_hash.clone(), char_name.clone());
                }
                hash_to_character.insert(replacement.new.clone(), char_name.clone());
            }

            for (base_hash, node) in &config.textures {
                hash_to_character.insert(base_hash.clone(), char_name.clone());

                for old_hash in &node.replace {
                    hash_to_character.insert(old_hash.clone(), char_name.clone());
                }

                for target_hashes in node.derive.values() {
                    for target_hash in target_hashes {
                        hash_to_character.insert(target_hash.clone(), char_name.clone());
                    }
                }
            }
        }

        Self {
            characters: characters.clone(),
            hash_to_character,
            enable_texture_override,
            checksum_regex: Regex::new(r"(checksum\s*=\s*)\d+").unwrap(),
            hash_re: Regex::new(r"hash\s*=\s*([0-9a-fA-F]{8,16})\b").unwrap(),
            blend_block_re: Regex::new(r"\[ResourceBlendBuffer\][^\[]+").unwrap(),
            stride_re: Regex::new(r"stride\s*=\s*8").unwrap(),
        }
    }

    /// 检查对指定路径的写权限
    fn check_write_permission(&self, path: &Path) -> Result<()> {
        let temp_file_name = format!(".tmp_permission_check_{}", std::process::id());
        let temp_file_path = path.join(temp_file_name);

        match fs::File::create(&temp_file_path) {
            Ok(_) => {
                if let Err(e) = fs::remove_file(&temp_file_path) {
                    Err(anyhow!(t!(
                        permission_check_remove_failed,
                        path = temp_file_path.display(),
                        error = e
                    )))
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(anyhow!(t!(
                permission_check_create_failed,
                path = path.display(),
                error = e
            ))),
        }
    }

    fn process_directory(&self, path: &Path) -> Result<()> {
        if !path.is_dir() {
            error!("{}", t!(path_not_a_directory, path = path.display()));
            return Ok(());
        }

        if let Err(e) = self.check_write_permission(path) {
            error!("{}", e);
            warn!("{}", t!(admin_prompt_suggestion));
            return Ok(());
        }

        info!("{}", t!(start_processing, mod_folder_path = path.display()));

        let mut success = 0;
        let mut skipped = 0;
        let mut errors = 0;

        for entry in WalkDir::new(path) {
            let path = match entry {
                Ok(entry) => entry.into_path(),
                Err(e) => {
                    error!(
                        "{}",
                        t!(
                            traversal_error,
                            path = e.path().unwrap_or(path).display(),
                            error = e
                        )
                    );
                    errors += 1;
                    continue;
                }
            };

            if !path.is_file() || !self.is_target_file(&path) {
                continue;
            }

            match self.process_file(&path) {
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
                    errors += 1;
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
                failure_count = skipped + errors
            )
        );
        Ok(())
    }

    fn process_file(&self, path: &Path) -> Result<bool> {
        let content = fs::read_to_string(path)?;
        let mut modified = false;
        let mut ini_modified = false;
        let mut buf_files_modified = false;
        let mut new_content = content.clone();
        info!("{}", t!(process_file_start, file_path = path.display()));
        let settings = config_loader::settings();

        let mut potential_chars = std::collections::HashSet::new();
        for cap in self.hash_re.captures_iter(&content) {
            if let Some(char_name) = self.hash_to_character.get(&cap[1]) {
                potential_chars.insert(char_name.clone());
            }
        }

        if potential_chars.is_empty() {
            info!("{}", t!(no_need_fix));
            return Ok(false);
        }

        let mut all_aggregated_states: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut should_process_derive = false;

        for char_name in &potential_chars {
            let config = self.characters.get(char_name).unwrap();

            if char_name == "RoverMale" && content.contains("FixAeroRoverFemale") {
                continue;
            }

            info!("{}", t!(match_character_prompt, character = char_name));

            // --- 哈希替换 (Replace Logic) ---
            ini_modified |= self.replace_hashes_list(&mut new_content, &config.main_hashes);

            for (base_hash, node) in &config.textures {
                if !node.replace.is_empty() {
                    ini_modified |=
                        self.replace_hash_single_target(&mut new_content, &node.replace, base_hash);
                }
            }

            // --- (Derive Logic - Collect Phase) ---
            if self.enable_texture_override || settings.state_texture_removers.contains(char_name)
            {
                should_process_derive = true;
                for (base_hash, node) in &config.textures {
                    for (state_name, target_hashes) in &node.derive {
                        let entry = all_aggregated_states.entry(state_name.clone()).or_default();
                        for target in target_hashes {
                            entry.insert(target.clone(), base_hash.clone());
                        }
                    }
                }
            }

            if self.is_character_match(&content, char_name, config) {
                // Checksum
                if let Some(checksum) = &config.checksum {
                    let new_content_replaced = self
                        .checksum_regex
                        .replace_all(&new_content, &format!("checksum = {}", checksum));

                    if new_content_replaced.as_ref() != new_content {
                        new_content = new_content_replaced.into_owned();
                        info!("checksum_replaced: {char_name} = {checksum}");
                        ini_modified = true;
                    }
                }

                // Rules
                ini_modified |= self.replace_index_offset_count(&mut new_content, &config.rules);

                // --- VGs Remaps ---
                if let Some(vg_maps) = &config.vg_remaps {
                    buf_files_modified |= self.remaps(&content, path, vg_maps)?;
                }

                // ... Aero Rover Fix logic ...
                let enable_aero_rover_fix =
                    if settings.enable_aero_rover_fix && char_name == "RoverFemale" {
                        println!();
                        Confirm::new(t!(aero_rover_female_eyes_prompt))
                            .with_default(false)
                            .prompt()?
                    } else {
                        false
                    };

                if enable_aero_rover_fix {
                    let texcoord_modified =
                        self.fix_aero_rover_female_eyes_with_texcoord(path, &content)?;
                    if !texcoord_modified {
                        let texture_section_added =
                            self.fix_aero_rover_female_eyes_with_texture(path, &mut new_content)?;
                        ini_modified |= texture_section_added;
                    }
                    buf_files_modified |= texcoord_modified;
                    info!("{}", t!(aero_rover_female_eyes_fixed));
                }

                // ... Stride Fix logic (driven by config.stride_fix) ...
                if let Some(stride_fix) = &config.stride_fix {
                    let should_apply = stride_fix.trigger_hash.iter().any(|h| content.contains(h));
                    
                    if should_apply {
                        let replaced_content =
                            self.blend_block_re
                                .replace_all(&new_content, |cap: &regex::Captures| {
                                    let original_block = cap[0].to_string();
                                    self.stride_re
                                        .replace_all(&original_block, "stride = 16")
                                        .to_string()
                                });

                        if replaced_content != new_content {
                            ini_modified = true;
                            new_content = replaced_content.into_owned();

                            let blend_buf_matches = collector::parse_resouce_buffer_path(
                                &content,
                                collector::BufferType::Blend,
                                &path,
                            );

                            for (blend_path, _) in blend_buf_matches {
                                if !blend_path.exists() {
                                    continue;
                                }
                                let blend_data = fs::read(&blend_path)?;
                                let expanded_data = self.expand_blend_stride_to_16(&blend_data);
                                self.create_backup(&blend_path)?;
                                fs::write(&blend_path, expanded_data)?;
                                buf_files_modified = true;
                            }
                        }
                    }
                }
            }
        }

        // --- 状态重定向 (Derive Logic - Process Phase) ---
        if should_process_derive && !all_aggregated_states.is_empty() {
            let state_suffixes: Vec<&str> = all_aggregated_states.keys().map(|s| s.as_str()).collect();
            
            let required_hashes: std::collections::HashSet<String> = all_aggregated_states
                .values()
                .flat_map(|state_map| state_map.keys().cloned())
                .collect();
            
            let (existing_count, existing_hashes) = self.collect_existing_derive_hashes(&new_content, &state_suffixes);
            
            let needs_remove: Vec<_> = existing_hashes.difference(&required_hashes).collect();
            
            if !needs_remove.is_empty() {
                debug!("Found {} outdated hashes to remove: {:?}", needs_remove.len(), needs_remove);
                self.remove_outdated_derive_sections(&mut new_content, &state_suffixes);
                
                for (state_name, state_map) in all_aggregated_states {
                    ini_modified |= self.texture_override_redirection(
                        &mut new_content,
                        &state_map,
                        &state_name,
                    )?;
                }
            } else if existing_count == 0 {
                for (state_name, state_map) in all_aggregated_states {
                    ini_modified |= self.texture_override_redirection(
                        &mut new_content,
                        &state_map,
                        &state_name,
                    )?;
                }
            }
        }

        if ini_modified {
            self.create_backup(path)?;
            fs::write(path, new_content)?;
            info!("{}", t!(process_file_done, file_path = path.display()));
        }

        modified |= ini_modified;
        modified |= buf_files_modified;

        if !modified {
            info!("{}", t!(no_need_fix));
        }

        Ok(modified)
    }

    fn is_character_match(&self, content: &str, char_name: &str, config: &CharacterConfig) -> bool {
        // Rule 1: Check for vb0 hash in [TextureOverrideComponent...]
        if let Some(vb0) = config.main_hashes.first() {
            for hash in vb0.old.iter().chain(std::iter::once(&vb0.new)) {
                let re = Regex::new(&format!(
                    r"\[TextureOverrideComponent\w*\][^\[]*?hash\s*=\s*{}",
                    hash
                ))
                .unwrap();
                if re.is_match(content) {
                    return true;
                }
            }
        }

        // Rule 2: For EARLY_CHARACTERS, also check for shape_key_hashes in [TextureOverrideShapeKey...]
        if EARLY_CHARACTERS.contains(&char_name) {
            if let Some(shape_key_hashes) = config.main_hashes.get(1) {
                for hash in shape_key_hashes
                    .old
                    .iter()
                    .chain(std::iter::once(&shape_key_hashes.new))
                {
                    let re = Regex::new(&format!(
                        r"\[TextureOverrideShapeKey\w*\][^\[]*?hash\s*=\s*{}",
                        hash
                    ))
                    .unwrap();
                    if re.is_match(content) {
                        info!("{}", t!(found_old_mod));
                        return true;
                    }
                }
            }
        }

        false
    }

    fn replace_hashes_list(&self, content: &mut String, hashes: &[Replacement]) -> bool {
        let mut modified = false;
        for hr in hashes {
            for old_hash in hr.old.iter().rev() {
                if old_hash != &hr.new && content.contains(&format!("hash = {}", &old_hash)) {
                    let re = Regex::new(&format!(r"\bhash\s*=\s*{}\b", regex::escape(old_hash)))
                        .unwrap();
                    *content = re
                        .replace_all(content, &format!("hash = {}", hr.new))
                        .to_string();
                    modified = true;
                    info!("{} -> {}", old_hash, hr.new);
                    break;
                }
            }
        }
        modified
    }

    fn replace_hash_single_target(
        &self,
        content: &mut String,
        old_hashes: &[String],
        new_hash: &str,
    ) -> bool {
        let mut modified = false;
        for old_hash in old_hashes.iter().rev() {
            if old_hash != new_hash && content.contains(&format!("hash = {}", &old_hash)) {
                let re =
                    Regex::new(&format!(r"\bhash\s*=\s*{}\b", regex::escape(old_hash))).unwrap();
                *content = re
                    .replace_all(content, &format!("hash = {}", new_hash))
                    .to_string();
                modified = true;
                info!("{} -> {}", old_hash, new_hash);
                break;
            }
        }
        modified
    }

    /// 收集文件末尾派生节中的所有 hash
    /// 返回 (需要检查的派生节数量, hash 集合)
    fn collect_existing_derive_hashes(
        &self,
        content: &str,
        state_suffixes: &[&str],
    ) -> (usize, std::collections::HashSet<String>) {
        let lines: Vec<&str> = content.lines().collect();
        let mut existing_hashes = std::collections::HashSet::new();
        let mut derive_section_count = 0;

        if lines.is_empty() {
            return (0, existing_hashes);
        }

        // 找到所有节的起始位置
        let mut section_starts: Vec<usize> = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                section_starts.push(i);
            }
        }

        if section_starts.is_empty() {
            return (0, existing_hashes);
        }

        // 从最后一个节开始，向前收集派生节的 hash
        for &section_start in section_starts.iter().rev() {
            let header_line = lines[section_start].trim();
            let header = &header_line[1..header_line.len() - 1];
            
            // 检查是否是派生节
            let is_derive_header = state_suffixes.iter().any(|suffix| {
                header.contains(&format!("_{}", suffix))
            });

            if !is_derive_header {
                break;
            }

            // 检查该节是否包含 match_priority = 0
            let section_end = section_starts
                .iter()
                .find(|&&s| s > section_start)
                .copied()
                .unwrap_or(lines.len());
            
            let mut has_match_priority_zero = false;
            let mut section_hash: Option<String> = None;
            
            for i in (section_start + 1)..section_end {
                let line = lines[i].trim();
                if line.starts_with("match_priority") && line.contains("=") && line.contains("0") {
                    has_match_priority_zero = true;
                }
                if line.starts_with("hash") && line.contains("=") {
                    if let Some(hash_val) = line.split('=').nth(1) {
                        let hash = hash_val.split(';').next().unwrap_or("").trim();
                        if !hash.is_empty() {
                            section_hash = Some(hash.to_string());
                        }
                    }
                }
            }

            if has_match_priority_zero {
                derive_section_count += 1;
                if let Some(h) = section_hash {
                    existing_hashes.insert(h);
                }
            } else {
                break;
            }
        }

        (derive_section_count, existing_hashes)
    }

    /// 删除由本工具生成的旧派生节（状态重定向节）
    /// 安全策略：只从文件末尾向前扫描，删除末尾连续的派生节
    /// 一旦遇到非派生节就停止   
    /// 识别特征：节头包含状态后缀（如 _LOD, _wet 等）且包含 match_priority = 0
    fn remove_outdated_derive_sections(
        &self,
        content: &mut String,
        state_suffixes: &[&str],
    ) -> bool {
        let lines: Vec<&str> = content.lines().collect();
        if lines.is_empty() {
            return false;
        }

        // 从末尾向前找到所有节的起始位置
        let mut section_starts: Vec<usize> = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                section_starts.push(i);
            }
        }

        if section_starts.is_empty() {
            return false;
        }

        // 从最后一个节开始，向前检查哪些是需要删除的派生节
        let mut sections_to_remove: Vec<usize> = Vec::new();
        
        for &section_start in section_starts.iter().rev() {
            let header_line = lines[section_start].trim();
            let header = &header_line[1..header_line.len() - 1];
            
            // 检查是否是派生节（节头包含状态后缀，如 _LOD, _LOD_0, _wet 等）
            let is_derive_header = state_suffixes.iter().any(|suffix| {
                header.contains(&format!("_{}", suffix))
            });

            if !is_derive_header {
                break;
            }

            // 检查该节是否包含 match_priority = 0
            let section_end = section_starts
                .iter()
                .find(|&&s| s > section_start)
                .copied()
                .unwrap_or(lines.len());
            
            let mut has_match_priority_zero = false;
            for i in (section_start + 1)..section_end {
                let line = lines[i].trim();
                if line.starts_with("match_priority") 
                    && line.contains("=") 
                    && line.contains("0") 
                {
                    has_match_priority_zero = true;
                    break;
                }
            }

            if has_match_priority_zero {
                sections_to_remove.push(section_start);
                info!("Removing outdated derive section: {}", header);
            } else {
                break;
            }
        }

        if sections_to_remove.is_empty() {
            return false;
        }

        // 找到最早需要删除的节的起始位置，截断文件
        let first_remove_line = *sections_to_remove.iter().min().unwrap();
        
        // 向前跳过空行，找到真正的截断点
        let mut truncate_line = first_remove_line;
        while truncate_line > 0 && lines[truncate_line - 1].trim().is_empty() {
            truncate_line -= 1;
        }

        // 构建新内容
        let new_lines: Vec<&str> = lines[..truncate_line].to_vec();
        
        *content = new_lines.join("\n");
        if !content.ends_with('\n') && !content.is_empty() {
            content.push('\n');
        }
        
        info!("Removed {} outdated derive section(s) from end of file", sections_to_remove.len());
        true
    }

    fn texture_override_redirection(
        &self,
        content: &mut String,
        tex_override_map: &HashMap<String, String>,
        header_suffix: &str,
    ) -> Result<bool> {
        let mut new_fix_sections: Vec<String> = Vec::new();

        let mut existing_headers: std::collections::HashSet<String> = content
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.starts_with('[') && trimmed.ends_with(']') {
                    Some(trimmed[1..trimmed.len() - 1].to_string())
                } else {
                    None
                }
            })
            .collect();

        let mut grouped_map: HashMap<&String, Vec<&String>> = HashMap::new();
        for (changed_hash, original_hash) in tex_override_map {
            grouped_map
                .entry(original_hash)
                .or_default()
                .push(changed_hash);
        }

        for (original_hash, changed_hashes) in grouped_map {
            let mut needed_hashes: Vec<&String> = changed_hashes
                .iter()
                .filter(|&&h| !content.contains(h))
                .cloned()
                .collect();
            needed_hashes.sort();

            if needed_hashes.is_empty() {
                continue;
            }

            let match_res =
                self.get_texture_override_content_after_match_priority(original_hash, content);

            if let Ok(match_data) = match_res {
                let clone_content = match_data.content.trim();
                
                if clone_content.is_empty() {
                    continue;
                }

                let base_header = match_data.section_header.trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']');
                
                if base_header.is_empty() { continue; }

                for changed_hash in needed_hashes {
                    let mut candidate_header = format!("{}_{}", base_header, header_suffix);
                    let mut counter = 0;

                    while existing_headers.contains(&candidate_header) {
                        candidate_header = format!("{}_{}_{}", base_header, header_suffix, counter);
                        counter += 1;
                    }

                    existing_headers.insert(candidate_header.clone());

                    info!(
                        "Generating section: [{}] for hash {}",
                        candidate_header, changed_hash
                    );

                    let new_section_content = format!(
                        "[{}]\nhash = {}\nmatch_priority = 0\n{}",
                        candidate_header, changed_hash, clone_content
                    );
                    new_fix_sections.push(new_section_content);
                }
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
        let mut current_header = String::new();
        let mut current_body_lines: Vec<&str> = Vec::new();
        let mut found_target_hash_in_section = false;
        let mut in_texture_override_section = false;

        let finalize_content = |lines: &[&str]| -> String {
            lines.join("\n")
        };

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with(';') {
                if trimmed.starts_with(';') {
                    continue; 
                }
            }

            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                if in_texture_override_section && found_target_hash_in_section {
                    return Ok(MatchTextureOverrideContent {
                        section_header: current_header,
                        content: finalize_content(&current_body_lines),
                    });
                }

                // --- 新节开始，重置状态 ---
                current_header = trimmed.to_string();
                current_body_lines.clear();
                found_target_hash_in_section = false;
                
                in_texture_override_section = current_header.starts_with("[TextureOverride");
                continue;
            }

            if !in_texture_override_section {
                continue;
            }

            if let Some((key, value)) = trimmed.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                if key.eq_ignore_ascii_case("hash") {
                    let clean_value = value.split(';').next().unwrap_or("").trim();
                    
                    if clean_value == original_hash {
                        found_target_hash_in_section = true;
                    }
                    continue; 
                }

                if key.eq_ignore_ascii_case("match_priority") {
                    continue;
                }
            }

            current_body_lines.push(trimmed); 
        }

        if in_texture_override_section && found_target_hash_in_section {
            return Ok(MatchTextureOverrideContent {
                section_header: current_header,
                content: finalize_content(&current_body_lines),
            });
        }

        Err(Error::msg(format!(
            "No suitable content found for hash: {}",
            original_hash
        )))
    }

    fn create_backup(&self, path: &Path) -> Result<PathBuf, Error> {
        let datetime = chrono::Local::now().format("%Y-%m-%d %H-%M-%S%.3f").to_string();
        if let Some(file_name) = path.file_name() {
            if let Some(name) = file_name.to_str() {
                let backup_name = format!("{}_{}.BAK", name, datetime);
                let backup_path = path.with_file_name(backup_name);
                fs::copy(path, &backup_path)?;
                info!(
                    "{}",
                    t!(backup_created, backup_path = backup_path.display())
                );
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

    fn replace_index_offset_count(
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
                        for old_val in replacement.old.iter().rev() {
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
        let blend_buf_matches =
            collector::parse_resouce_buffer_path(content, collector::BufferType::Blend, file_path);

        debug!("{:?}", blend_buf_matches);

        let use_merged_skeleton = content.contains("[ResourceMergedSkeleton]");
        let multiple_blend_files = blend_buf_matches.len() > (1 as usize);

        for (blend_path, stride) in blend_buf_matches {
            if !blend_path.exists() {
                warn!("{} not found", blend_path.display());
                continue;
            }

            let mut match_flag = false;
            let mut apply_flag = false;

            let mut blend_data = fs::read(&blend_path)?;

            for vg_remap in vg_remaps {
                if match_flag
                    || vg_remap
                        .trigger_hash
                        .iter()
                        .any(|h| content.contains(&format!("hash = {}", h)))
                {
                    let remap_result = if use_merged_skeleton {
                        vg_remap.apply_remap_merged(&mut blend_data, stride)
                    } else {
                        vg_remap.apply_remap_component(
                            &mut blend_data,
                            &blend_path,
                            &content,
                            multiple_blend_files,
                            stride,
                        )
                    };

                    apply_flag |= match remap_result {
                        Ok(true) => true,
                        Ok(false) => {
                            info!("skip remap for {}", &blend_path.display());
                            false
                        }
                        Err(e) => {
                            error!("{:?}", e);
                            false
                        }
                    };
                    match_flag = true;
                }
            }

            if apply_flag {
                info!("{}", t!(remapped_successfully));
                self.create_backup(&blend_path)?;
                fs::write(&blend_path, &blend_data)?;
                modified = true;
            }
        }
        return Ok(modified);
    }

    fn fix_aero_rover_female_eyes_with_texcoord(
        &self,
        ini_path: &Path,
        content: &str,
    ) -> Result<bool> {
        let component_indices = collector::parse_component_indices(&content);
        if !component_indices.contains_key(&5) {
            return Ok(false);
        }

        let &(index_count, index_offset) = component_indices
            .get(&5)
            .ok_or_else(|| anyhow!("Failed to find component indices"))?;

        let texcoord_buf_matches = collector::parse_resouce_buffer_path(
            &content,
            collector::BufferType::TexCoord,
            &ini_path,
        );

        let mut ret = false;

        for (tex_coord_path, stride) in texcoord_buf_matches {
            if !tex_coord_path.exists() {
                continue;
            }

            let index_path =
                collector::combile_buf_path(&tex_coord_path, &collector::BufferType::Index);

            let index_data = fs::read(index_path)?;

            let (start, end) =
                collector::get_byte_range_in_buffer(index_count, index_offset, &index_data, stride)
                    .map_err(|e| anyhow!("Failed to get byte range in buffer: {}", e))?;

            let fixed_data = include_bytes!("resources/RoverFemale_Componet5_TexCoord.buf");

            debug!(
                "start: {}, end: {}, range_len: {}, fixed_len: {}, stride: {}",
                start,
                end,
                end - start,
                fixed_data.len(),
                stride
            );

            let mut tex_coord_data = fs::read(&tex_coord_path)?;
            let range_len = end - start;
            if range_len % stride != 0 {
                warn!(
                    "texcoord range length {} is not divisible by stride {} - skip",
                    range_len, stride
                );
                continue;
            }

            let vertex_count = range_len / stride;

            if vertex_count == 0 {
                continue;
            }

            if fixed_data.len() % vertex_count != 0 {
                warn!(
                    "fixed data length {} is not divisible by vertex count {} - skip",
                    fixed_data.len(),
                    vertex_count
                );
                continue;
            }

            let src_stride = fixed_data.len() / vertex_count;
            let texcoord1_offset_in_src = 8usize;
            let texcoord1_size = 4usize;

            if texcoord1_offset_in_src + texcoord1_size > src_stride {
                warn!(
                    "texcoord1 (offset {} + size {}) out of src stride {} - skip",
                    texcoord1_offset_in_src, texcoord1_size, src_stride
                );
                continue;
            }

            let dst_texcoord1_offset = 8usize;

            if dst_texcoord1_offset + texcoord1_size > stride {
                warn!(
                    "dst texcoord1 (offset {} + size {}) out of dst stride {} - skip",
                    dst_texcoord1_offset, texcoord1_size, stride
                );
                continue;
            }

            for i in 0..vertex_count {
                let src_start = i * src_stride + texcoord1_offset_in_src;
                let src_end = src_start + texcoord1_size;
                let dst_start = start + i * stride + dst_texcoord1_offset;
                let dst_end = dst_start + texcoord1_size;

                if src_end > fixed_data.len() || dst_end > tex_coord_data.len() {
                    warn!(
                        "index out of bounds while copying texcoord1 for vertex {} - skip remaining",
                        i
                    );
                    break;
                }

                tex_coord_data[dst_start..dst_end].copy_from_slice(&fixed_data[src_start..src_end]);
            }

            self.create_backup(&tex_coord_path)?;
            fs::write(&tex_coord_path, &tex_coord_data)?;
            ret = true;
        }
        return Ok(ret);
    }

    fn fix_aero_rover_female_eyes_with_texture(
        &self,
        ini_path: &Path,
        new_content: &mut String,
    ) -> Result<bool> {
        let texture_path = ini_path.parent().unwrap().join("Textures");
        if !texture_path.exists() {
            fs::create_dir_all(&texture_path)?;
        }

        let fixed_data = include_bytes!("resources/FixAeroRoverFemaleChargedEyesMap.dds");
        let file_name = "FixAeroRoverFemaleChargedEyesMap.dds";
        fs::write(texture_path.join(file_name), fixed_data)?;

        let new_section_content = format!(
            r#"
        [Constants]
        global $charged = 0
        global $rf_state = 0

        [TextureOverride_Normal]
        hash = 52c18227
        $charged = 0

        [TextureOverride_Charged]
        hash = 70d7428b
        $charged = 1

        [TextureOverride_RoverMale]
        if $charged == 1
        hash = b22dacf9
        $rf_state = 0
        endif

        [TextureOverride_RoverFemale]
        if $charged == 1
        hash = 06482222
        $rf_state = 1
        endif

        [ResourceTexture_AeroRoverFemaleEyes]
        filename = Textures/{}

        [TextureOverrideTexture_AeroRoverFemaleEyes]
        if $charged == 1 && $rf_state == 1
        hash = {}
        match_priority = 0
        this = ResourceTexture_AeroRoverFemaleEyes
        endif
        "#,
            file_name, "29304593"
        )
        .replace(&" ".repeat(8), "");

        new_content.push_str(&new_section_content);
        return Ok(true);
    }

    fn expand_blend_stride_to_16(&self, blend_data: &[u8]) -> Vec<u8> {
        let mut buf_data: Vec<u8> = Vec::with_capacity(blend_data.len() * 2);
        for chunk in blend_data.chunks_exact(8) {
            let (indices, weights) = chunk.split_at(4);
            buf_data.extend_from_slice(indices);
            buf_data.extend_from_slice(&[0u8; 4]);
            buf_data.extend_from_slice(weights);
            buf_data.extend_from_slice(&[0u8; 4]);
        }
        return buf_data;
    }
}

struct MatchTextureOverrideContent {
    section_header: String,
    content: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logger();
    init_panic_hook();

    config_loader::init_config().await;

    if !check_version() {
        let _ = std::io::stdin().read_line(&mut String::new());
        return Ok(());
    }

    show_intro();
    run_interactive();

    Ok(())
}

/// 初始化日志
fn init_logger() {
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
}

/// 全局 panic 处理
fn init_panic_hook() {
    panic::set_hook(Box::new(|info| {
        let backtrace = Backtrace::new();
        error!("{}", t!(error_occurred, error = info.to_string()));
        debug!("Backtrace:\n{:?}", backtrace);
    }));
}

/// 版本检查
fn check_version() -> bool {
    match config_loader::check_version() {
        Ok(msg) => {
            println!("{}", t!(version_check_passed, msg = msg));
            true
        }
        Err(e) => {
            eprintln!("{}", t!(version_check_failed, error = e));
            false
        }
    }
}

/// 显示标题
fn show_intro() {
    println!("{}", t!(title));
    println!("{}", t!(intro));
    println!("{}", t!(intro_note));
    println!("{}", t!(compatibility_note));
    println!("{}", t!(graphics_setting_note));
    println!("\n");
}

/// 运行交互逻辑
fn run_interactive() {
    let input_path = Text::new(t!(input_folder_prompt))
        .with_default(".")
        .prompt()
        .unwrap();

    println!("{}", t!(texture_override_note));
    let enable_texture_override = Confirm::new(t!(texture_override_prompt))
        .with_default(false)
        .prompt()
        .unwrap();

    let fixer = ModFixer::new(config_loader::characters(), enable_texture_override);
    let result = panic::catch_unwind(|| {
        let _ = fixer.process_directory(Path::new(&input_path));
        info!("{}", t!(all_done));
    });

    if let Err(_) = result {
        error!("{}", t!(error_prompt));
    }

    let _ = std::io::stdin().read_line(&mut String::new()); // 等待按键
}
