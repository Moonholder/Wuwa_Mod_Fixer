#[macro_use]
extern crate log;

mod localization;
use localization::config::get_lang;
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
        let mut ini_modified = false;
        let mut buf_files_modified = false;
        let mut match_old_mod = false;
        let mut new_content = content.clone();
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
            ini_modified |= self.replace_hashes(&mut new_content, &config.main_hashes);
            ini_modified |= self.replace_hashes(&mut new_content, &config.texture_hashes);

            if let Some(checksum) = &config.checksum {
                let new_content_replaced = self
                    .checksum_regex
                    .replace_all(&new_content, &format!("checksum = {}", checksum));

                if new_content_replaced.as_ref() != new_content {
                    new_content = new_content_replaced.into_owned();
                    info!(
                        "checksum_replaced: {char_name} = {checksum}",
                        char_name = char_name,
                        checksum = checksum
                    );
                    ini_modified = true;
                }
            }

            // replace component match_first_index and match_first_count
            ini_modified |= self.replace_index_offset_count(&mut new_content, &config.rules);

            // 受损表现移除
            if self.enable_texture_override {
                if let Some(char_states) = &config.states {
                    for state_name in char_states.keys() {
                        if let Some(state_map) = char_states.get(state_name) {
                            ini_modified |= self.texture_override_redirection(
                                &mut new_content,
                                state_map,
                                state_name.as_str(),
                            )?;
                        }
                    }
                }
            }

            // 顶点组重映射
            if let Some(vg_maps) = &config.vg_remaps {
                buf_files_modified |= self.remaps(&content, path, vg_maps)?;
            }

            let enable_aero_rover_fix = if char_name == "RoverFemale" {
                println!();
                Confirm::new(t!(aero_rover_female_eyes_prompt))
                    .with_default(false)
                    .prompt()?
            } else {
                false
            };

            // 修复风主满共鸣能量眼睛异常
            if enable_aero_rover_fix {
                buf_files_modified |=
                    self.fix_aero_rover_female_eyes_with_texcoord(path, &content)?;

                if !buf_files_modified {
                    ini_modified |=
                        self.fix_aero_rover_female_eyes_with_texture(path, &mut new_content)?;
                }

                info!("{}", t!(aero_rover_female_eyes_fixed));
            }

            break;
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

    fn replace_hashes(&self, content: &mut String, hashes: &[Replacement]) -> bool {
        let mut modified = false;
        for hr in hashes {
            for old_hash in &hr.old {
                if old_hash != &hr.new && content.contains(&format!("hash = {}", &old_hash)) {
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
        let blend_buffer_matches =
            collector::parse_resouce_buffer_path(content, collector::BufferType::Blend, file_path);

        debug!("{:?}", blend_buffer_matches);

        let use_merged_skeleton = content.contains("[ResourceMergedSkeleton]");
        let multiple_blend_files = blend_buffer_matches.len() > (1 as usize);

        for blend_path in blend_buffer_matches {
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
                        vg_remap.apply_remap_merged(&mut blend_data)
                    } else {
                        vg_remap.apply_remap_component(
                            &mut blend_data,
                            &blend_path,
                            &content,
                            multiple_blend_files,
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
        let component_indices =
            collector::parse_component_indices(&content).map_err(|e| anyhow!(e))?;
        let &(index_count, index_offset) = component_indices
            .get(&5)
            .ok_or_else(|| anyhow!("Failed to find component indices"))?;

        let tex_coord_paths = collector::parse_resouce_buffer_path(
            &content,
            collector::BufferType::TexCoord,
            &ini_path,
        );

        let mut ret = false;

        for tex_coord_path in tex_coord_paths {
            if !tex_coord_path.exists() {
                continue;
            }

            let index_path =
                collector::combile_buf_path(&tex_coord_path, &collector::BufferType::Index);

            let index_data = fs::read(index_path)?;

            let (start, end) = collector::get_byte_range_in_buffer(
                index_count,
                index_offset,
                &index_data,
                collector::TEXCOORD_STRIDE,
            )
            .map_err(|e| anyhow!("Failed to get byte range in buffer: {}", e))?;

            let fixed_data = include_bytes!("resources/RoverFemale_Componet5_TexCoord.buf");

            debug!(
                "start: {}, end: {}, count: {}, len: {}",
                start,
                end,
                end - start,
                fixed_data.len()
            );

            let mut tex_coord_data = fs::read(&tex_coord_path)?;

            if end - start == fixed_data.len() {
                tex_coord_data[start..end].copy_from_slice(fixed_data);

                self.create_backup(&tex_coord_path)?;
                fs::write(&tex_coord_path, &tex_coord_data)?;

                ret = true;
            }
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

        let fixed_data = include_bytes!("resources/FixAeroRoverFemaleEyesMap=fa3f84a8.dds");
        let file_name = "FixAeroRoverFemaleEyesMap=fa3f84a8.dds";
        fs::write(texture_path.join(file_name), fixed_data)?;

        let new_section_content = format!(
            r#"
        [Constants]
        global $charged = 0
        global $rf_state = 0

        [TextureOverride_Normal]
        hash = a2207e11
        $charged = 0

        [TextureOverride_Charged]
        hash = fa3f84a8
        $charged = 1

        [TextureOverride_RoverMale]
        if $charged == 1
        hash = e18ca2cc
        $rf_state = 0
        endif

        [TextureOverride_RoverFemale]
        if $charged == 1
        hash = 3533a957
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
            file_name, "fa3f84a8"
        )
        .replace(&" ".repeat(8), "");

        new_content.push_str(&new_section_content);
        return Ok(true);
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
