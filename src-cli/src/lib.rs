// src-cli/src/lib.rs
// Standalone, headless CLI crate for Wuwa Mod Fixer.
// Decoupled from all GUI / Tauri dependencies.

pub mod i18n;

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use clap::{Parser, ValueEnum};
use i18n::tr;
use inquire::{
    Confirm, MultiSelect, Select, Text,
    validator::{ErrorMessage, Validation},
};
use serde::{Deserialize, Serialize};
use wuwa_mod_core::{
    self as core,
    settings::{UserSettings, load_settings, save_settings},
};

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum CliEvent<'a> {
    Start {
        mode: &'a str,
        total: usize,
    },
    Progress {
        current: usize,
        total: usize,
        percent: f64,
    },
    #[allow(dead_code)]
    Log {
        level: &'a str,
        message: &'a str,
    },
    Finish {
        success: bool,
        message: String,
    },
}

pub fn emit_json_event(event: &CliEvent) {
    if let Ok(json) = serde_json::to_string(event) {
        println!("{json}");
    }
}

pub fn emit_json_finish(success: bool, message: impl Into<String>) {
    emit_json_event(&CliEvent::Finish {
        success,
        message: message.into(),
    });
}

#[derive(Clone)]
pub struct CliProgressReporter {
    current: Arc<AtomicUsize>,
    total: Arc<AtomicUsize>,
    format: OutputFormat,
}

impl CliProgressReporter {
    pub fn new(format: OutputFormat) -> Self {
        Self {
            current: Arc::new(AtomicUsize::new(0)),
            total: Arc::new(AtomicUsize::new(0)),
            format,
        }
    }
}

impl core::ProgressReporter for CliProgressReporter {
    fn set_total(&self, total: usize) {
        self.total.store(total, Ordering::Relaxed);
        if self.format == OutputFormat::Json {
            emit_json_event(&CliEvent::Start { mode: "fix", total });
        }
    }

    fn increment(&self) {
        let cur = self.current.fetch_add(1, Ordering::Relaxed) + 1;
        let tot = self.total.load(Ordering::Relaxed);
        if self.format == OutputFormat::Json {
            let percent = if tot > 0 {
                (cur as f64 / tot as f64 * 100.0 * 10.0).round() / 10.0
            } else {
                100.0
            };
            emit_json_event(&CliEvent::Progress {
                current: cur,
                total: tot,
                percent,
            });
        }
    }

    fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }

    fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }
}

impl core::EventSink for CliProgressReporter {
    fn emit(&self, event: core::PipelineEvent) {
        match &event {
            core::PipelineEvent::Start { total, .. } => {
                self.total.store(*total, Ordering::Relaxed);
            }
            core::PipelineEvent::Progress { current, total, .. } => {
                self.current.store(*current, Ordering::Relaxed);
                self.total.store(*total, Ordering::Relaxed);
            }
            _ => {}
        }

        if self.format == OutputFormat::Json {
            if let Ok(json) = serde_json::to_string(&event) {
                println!("{json}");
            }
        } else {
            match event {
                core::PipelineEvent::FileStart {
                    path,
                    current,
                    total,
                    percent,
                } => {
                    println!("  \x1b[90m[{}/{}] ({:.1}%)\x1b[0m {}", current, total, percent, path);
                }
                core::PipelineEvent::FileSuccess {
                    path,
                    character,
                    current: _,
                    total: _,
                    percent: _,
                } => {
                    if let Some(char_name) = character {
                        println!("  \x1b[32m✓\x1b[0m {} \x1b[36m[{}]\x1b[0m", path, char_name);
                    } else {
                        println!("  \x1b[32m✓\x1b[0m {}", path);
                    }
                }
                core::PipelineEvent::FileSkipped { path, reason, .. } => {
                    println!("  \x1b[90m- {} ({})\x1b[0m", path, reason);
                }
                core::PipelineEvent::FileError { path, error, .. } => {
                    eprintln!("  \x1b[31m✗\x1b[0m {} ({})", path, error);
                }
                core::PipelineEvent::Log { level, message, .. } => {
                    println!("  \x1b[90m[{}]\x1b[0m {}", level, message);
                }
                core::PipelineEvent::Finish { summary, .. } => {
                    if let Some(s) = summary {
                        println!(
                            "\n  \x1b[32m{}: {}\x1b[0m | \x1b[90m{}: {}\x1b[0m | \x1b[31m{}: {}\x1b[0m  ({}ms)",
                            tr("成功", "success"),
                            s.success_count,
                            tr("跳过", "skipped"),
                            s.skipped_count,
                            tr("失败", "failed"),
                            s.failure_count,
                            s.elapsed_ms
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

#[derive(Parser, Debug, Clone, Default)]
#[command(
    name = "Wuwa_Mod_Fixer",
    author,
    version,
    about = "Automated pipeline fixer for Wuthering Waves mods",
    long_about = None
)]
pub struct CliArgs {
    /// Target directory containing mods to fix or rollback
    #[arg(long, value_name = "DIR")]
    pub path: Option<String>,

    /// Path to custom config file
    #[arg(long, value_name = "FILE")]
    pub config: Option<String>,

    /// Enable derived LOD texture hash replacements
    #[arg(long)]
    pub derived_hashes: bool,

    /// Enable stable texture hash replacements
    #[arg(long)]
    pub stable_texture: bool,

    /// Fix abnormal model geometry for Aemeath Mech
    #[arg(long)]
    pub aemeath_mech: bool,

    /// Enable Rendering 3.3 pipeline fix
    #[arg(long)]
    pub rendering_33: bool,

    /// Aero fix mode: 1 (TexCoord Override) or 2 (Texture Mirror Flip)
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8))]
    pub aero_fix: u8,

    /// Fetch latest remote configuration online
    #[arg(long)]
    pub online: bool,

    /// Rollback target directory using existing backups
    #[arg(long)]
    pub rollback: bool,

    /// Run in command-line interface mode
    #[arg(long)]
    pub cli: bool,

    /// Output format for stdout stream (text, json)
    #[arg(long, value_enum, default_value = "text")]
    pub format: OutputFormat,
}

impl CliArgs {
    pub fn is_cli_mode(&self) -> bool {
        self.cli
            || self.path.is_some()
            || self.rollback
            || self.config.is_some()
            || self.derived_hashes
            || self.stable_texture
            || self.aemeath_mech
            || self.rendering_33
            || self.aero_fix > 0
            || self.online
            || self.format == OutputFormat::Json
    }
}

pub fn parse_args() -> CliArgs {
    match CliArgs::try_parse() {
        Ok(args) => {
            if args.aero_fix > 2 {
                if args.format == OutputFormat::Json {
                    emit_json_finish(
                        false,
                        "Error: --aero-fix accepts only 1 (TexCoord Override) or 2 (Texture Mirror Flip).",
                    );
                } else {
                    eprintln!(
                        "\x1b[31m{}\x1b[0m",
                        tr(
                            "错误：--aero-fix 仅接受 1 (TexCoord 覆盖) 或 2 (贴图镜像反转)。",
                            "Error: --aero-fix accepts only 1 (TexCoord Override) or 2 (Texture Mirror Flip)."
                        )
                    );
                }
                std::process::exit(1);
            }
            args
        }
        Err(err) => {
            err.exit();
        }
    }
}

pub fn run(args: CliArgs, is_dev: bool) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    if let Some(config_path) = &args.config {
        core::config_loader::set_config_override_path(config_path);
    }

    if args.path.is_none() && args.format == OutputFormat::Json {
        emit_json_finish(false, "Missing required argument '--path' for headless json format.");
        std::process::exit(1);
    }

    if args.path.is_some() && args.rollback {
        run_direct_rollback(&args);
    } else {
        rt.block_on(core::config_loader::init_config());
        if args.path.is_some() {
            if !is_dev && args.online {
                let _ = rt.block_on(core::config_loader::force_reload_remote_config());
            }
            log::info!(
                "Config: {}",
                core::config_loader::config().version_ref().current_version
            );
            run_direct_fix(&args);
        } else {
            use std::io::IsTerminal;
            if !std::io::stdin().is_terminal() {
                eprintln!(
                    "{}",
                    tr(
                        "错误：未检测到交互式终端 (Non-TTY)。自动化调用请提供 '--path <DIR>' 参数。",
                        "Error: Non-interactive terminal (Non-TTY) detected. For automated invocations, please specify '--path <DIR>'."
                    )
                );
                std::process::exit(1);
            }

            if !is_dev && ask_load_remote() {
                let _ = rt.block_on(core::config_loader::force_reload_remote_config());
            }
            run_interactive(&rt);
        }
    }
}

pub fn ask_load_remote() -> bool {
    Confirm::new(tr("联网获取最新配置?", "Fetch latest config from internet?"))
        .with_default(true)
        .prompt()
        .unwrap_or(false)
}

pub fn run_direct_fix(args: &CliArgs) {
    let is_json = args.format == OutputFormat::Json;
    let path = clean_path(args.path.as_ref().unwrap());
    if !Path::new(&path).is_dir() {
        if is_json {
            emit_json_finish(false, "Invalid directory path.");
        } else {
            eprintln!(
                "\x1b[31m{}\x1b[0m",
                tr("错误：无效的文件夹路径。", "Error: Invalid directory path.")
            );
        }
        std::process::exit(1);
    }

    if args.derived_hashes && args.stable_texture {
        if is_json {
            emit_json_finish(
                false,
                "'--derived-hashes' and '--stable-texture' are mutually exclusive.",
            );
        } else {
            eprintln!(
                "\x1b[31m{}\x1b[0m",
                tr(
                    "错误：'--derived-hashes' 与 '--stable-texture' 不能同时启用。",
                    "Error: '--derived-hashes' and '--stable-texture' are mutually exclusive."
                )
            );
        }
        std::process::exit(1);
    }

    if !is_json {
        println!(
            "\x1b[1m{}\x1b[0m",
            tr("Wuwa Mod Fixer - 直接修复模式", "Wuwa Mod Fixer - Direct Fix Mode")
        );
        println!("\x1b[90m--------------------------------------------------\x1b[0m");
        println!("  {}: {}", tr("路径", "Path"), path);
        println!(
            "  {}: {}",
            tr("补全贴图状态", "Derived Hashes"),
            if args.derived_hashes { "✓" } else { "✗" }
        );
        println!(
            "  {}: {}",
            tr("应用稳定纹理", "Stable Texture"),
            if args.stable_texture { "✓" } else { "✗" }
        );
        println!(
            "  {}: {}",
            tr("修复爱弥斯机兵", "Aemeath Mech Fix"),
            if args.aemeath_mech { "✓" } else { "✗" }
        );
        println!(
            "  {}: {}",
            tr("模组破洞/部位缺失修复", "Fix Mesh Holes/Missing Parts"),
            if args.rendering_33 { "✓" } else { "✗" }
        );
        println!(
            "  {}: {}",
            tr("风主眼部修复", "Aero Eye Fix"),
            match args.aero_fix {
                1 => tr("TexCoord 覆盖", "TexCoord Override"),
                2 => tr("贴图镜像反转", "Texture Mirror Flip"),
                _ => tr("关闭", "Disabled"),
            }
        );
        println!("\x1b[90m--------------------------------------------------\x1b[0m");
        println!("\n\x1b[90m{}\x1b[0m", tr("处理中...", "Processing..."));
    }

    let progress = Arc::new(CliProgressReporter::new(args.format));
    let cancel_token = Arc::new(AtomicBool::new(false));
    let fixer = core::ModFixer::with_event_sink(
        core::config_loader::config().characters_ref(),
        args.derived_hashes,
        args.stable_texture,
        args.aemeath_mech,
        args.rendering_33,
        args.aero_fix,
        progress,
        cancel_token,
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixer.process_directory(Path::new(&path))
    }));

    match result {
        Ok(summary) => {
            if summary.total_files == 0 && !is_json {
                println!(
                    "\n\x1b[33m{}\x1b[0m",
                    tr(
                        "未在目标目录中找到可处理的 .ini 文件，请确认路径正确且已解压。",
                        "No processable .ini files found in target directory. Please verify the path and ensure it is extracted."
                    )
                );
            }
            if summary.failure_count > 0 {
                std::process::exit(1);
            }
        }
        Err(e) => {
            if is_json {
                let err_msg = e
                    .downcast_ref::<String>()
                    .map(|s| s.as_str())
                    .or_else(|| e.downcast_ref::<&str>().copied())
                    .unwrap_or("Unexpected error during mod fixing");
                emit_json_finish(false, err_msg);
            } else {
                eprintln!("\x1b[31m{}\x1b[0m", tr("发生未预期异常", "Unexpected error"));
            }
            std::process::exit(1);
        }
    }
}

pub fn run_direct_rollback(args: &CliArgs) {
    let is_json = args.format == OutputFormat::Json;
    let path = clean_path(args.path.as_ref().unwrap());
    let dir = Path::new(&path);

    if !dir.is_dir() {
        if is_json {
            emit_json_finish(false, "Invalid directory path.");
        } else {
            eprintln!(
                "\x1b[31m{}\x1b[0m",
                tr("错误：无效的文件夹路径。", "Error: Invalid directory path.")
            );
        }
        std::process::exit(1);
    }

    let has_fix_options =
        args.derived_hashes || args.stable_texture || args.aemeath_mech || args.rendering_33 || args.aero_fix > 0;
    if has_fix_options {
        if is_json {
            emit_json_finish(
                false,
                "'--rollback' cannot be used with fix options. Run rollback separately.",
            );
        } else {
            eprintln!(
                "\x1b[31m{}\x1b[0m",
                tr(
                    "错误：'--rollback' 不能与修复选项同时使用，请单独执行回滚。",
                    "Error: '--rollback' cannot be used with fix options. Run rollback separately."
                )
            );
        }
        std::process::exit(1);
    }

    if !is_json {
        println!(
            "\x1b[1m{}\x1b[0m",
            tr("Wuwa Mod Fixer - 回滚模式", "Wuwa Mod Fixer - Rollback Mode")
        );
        println!("\x1b[90m--------------------------------------------------\x1b[0m");
        println!("  {}: {}", tr("路径", "Path"), path);
        println!("\x1b[90m{}\x1b[0m", tr("扫描备份文件...", "Scanning backup files..."));
    }

    let backups = core::rollback::scan_backups(dir).unwrap_or_default();
    if backups.is_empty() {
        if is_json {
            emit_json_finish(true, "No backup files found. Nothing to rollback.");
        } else {
            println!(
                "\x1b[33m{}\x1b[0m",
                tr(
                    "未找到可用的备份文件 (.BAK)，无需回滚。",
                    "No backup files (.BAK) found. Nothing to rollback."
                )
            );
        }
        return;
    }

    let latest = &backups[0];
    if is_json {
        emit_json_event(&CliEvent::Start {
            mode: "rollback",
            total: latest.files.len(),
        });
    } else {
        println!(
            "  {}: {}  ({} {})",
            tr("回滚目标", "Rollback target"),
            latest.group_key,
            latest.files.len(),
            tr("个文件", "files")
        );
        println!("\x1b[90m--------------------------------------------------\x1b[0m");
        println!("\n\x1b[90m{}\x1b[0m", tr("正在回滚...", "Rolling back..."));
    }

    match core::rollback::execute_rollback(dir, &latest.group_key) {
        Ok(_) => {
            if is_json {
                emit_json_finish(true, "Rollback completed.");
            } else {
                println!("\x1b[32m{}\x1b[0m", tr("回滚完成。", "Rollback completed."));
            }
        }
        Err(e) => {
            if is_json {
                emit_json_finish(false, e.to_string());
            } else {
                eprintln!("\x1b[31m{} {}\x1b[0m", tr("回滚失败:", "Rollback failed:"), e);
            }
            std::process::exit(1);
        }
    }
}

pub fn run_interactive(rt: &tokio::runtime::Runtime) {
    let mut settings = load_settings();

    show_intro();

    loop {
        let opt_fix = tr("一键修复", "Start Fix").to_string();
        let opt_rollback = tr("回滚管理", "Rollback Manager").to_string();
        let opt_update = tr("更新配置", "Update Config").to_string();
        let opt_notes = tr("更新说明", "View Update Notes & Notice").to_string();
        let opt_exit = tr("退出程序", "Exit").to_string();

        let options = vec![
            opt_fix.clone(),
            opt_rollback.clone(),
            opt_update.clone(),
            opt_notes.clone(),
            opt_exit.clone(),
        ];

        let ans = Select::new(tr("请选择操作:", "Select Action:"), options).prompt();
        match ans {
            Ok(choice) if choice == opt_fix => run_fix_flow(&mut settings),
            Ok(choice) if choice == opt_rollback => run_rollback_flow(&mut settings),
            Ok(choice) if choice == opt_update => run_update_flow(rt),
            Ok(choice) if choice == opt_notes => show_detailed_notes(),
            Ok(choice) if choice == opt_exit => break,
            Err(_) => break,
            _ => {}
        }
    }
}

fn run_fix_flow(settings: &mut UserSettings) {
    let default = settings.last_folder.as_deref().unwrap_or(".");
    let prompt_msg = if let Some(last) = &settings.last_folder {
        format!(
            "{} [{}]:",
            tr(
                "输入 Mod 文件夹路径 (支持拖放，回车使用上次路径)",
                "Enter Mod folder path (drag & drop supported, Enter to use last)"
            ),
            last
        )
    } else {
        tr(
            "输入 Mod 文件夹路径 (可直接拖放):",
            "Enter Mod folder path (drag & drop supported):",
        )
        .to_string()
    };

    let path = loop {
        match Text::new(&prompt_msg).with_default(default).prompt() {
            Ok(p) => {
                let c = clean_path(&p);
                if Path::new(&c).is_dir() {
                    break c;
                }
                println!(
                    "\x1b[31m{}\x1b[0m",
                    tr("错误：无效的文件夹路径。", "Error: Invalid directory path.")
                );
            }
            Err(_) => return,
        }
    };

    let dir = Path::new(&path);
    // Pre-flight inspection: scan for candidate .ini files
    let mut ini_count = 0;
    for entry in walkdir::WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Some(ext) = entry.path().extension() {
                if ext.eq_ignore_ascii_case("ini") {
                    let path_str = entry.path().to_string_lossy().to_lowercase();
                    if !path_str.ends_with(".bak") && !path_str.contains(".bak.") {
                        ini_count += 1;
                    }
                }
            }
        }
    }

    if ini_count == 0 {
        println!(
            "\n\x1b[33m{}\x1b[0m\n",
            tr(
                "未在目标目录中找到可处理的 .ini 文件，请确认路径正确且已解压。",
                "No processable .ini files found in target directory. Please verify the path and ensure it is extracted."
            )
        );
        return;
    }

    println!(
        "\n  \x1b[32m✓\x1b[0m {} ({} {})",
        tr("目标目录已识别", "Target directory verified"),
        ini_count,
        tr("个 Mod 配置文件", "mod .ini file(s)")
    );

    settings.last_folder = Some(path.clone());
    save_settings(settings);

    // Show option descriptions
    println!("\n\x1b[1m{}\x1b[0m", tr("-- 修复选项说明 --", "-- Fix Options Info --"));

    println!("  \x1b[1m{}\x1b[0m", tr("补全贴图状态", "Add Derived Hashes"));
    println!(
        "    \x1b[90m{}\x1b[0m",
        tr(
            "为模组补全缺失的贴图状态Hash (如坎特蕾拉湿身、千咲强化E、爱弥斯满充能等) (部分角色未添加)",
            "Add missing texture state hashes (e.g. Cantarella wet, Chisa Enhanced E, Aemeath Charged) so character mod textures display correctly (some characters not added)"
        )
    );

    println!("  \x1b[1m{}\x1b[0m", tr("应用稳定纹理", "Apply Stable Texture"));
    println!(
        "    \x1b[90m{}\x1b[0m",
        tr(
            "使用 RabbitFX 为角色设置稳定纹理 (目前仅坎特蕾拉、千咲、卡提、夏空...)，需安装最新的RabbitFX",
            "Use RabbitFX to set stable textures for characters (currently Cantarella, Chisa, Cartethyia, Ciaccona...). Requires latest RabbitFX"
        )
    );

    println!(
        "  \x1b[1m{}\x1b[0m",
        tr("修复爱弥斯机兵形态的模型异常", "Fix Aemeath's mech form model error")
    );
    println!(
        "    \x1b[90m{}\x1b[0m",
        tr(
            "不要对正常的爱弥斯机兵模组启用此功能，不要重复修复",
            "Do not enable this function for Aemeath mech mods that are already normal, do not repeat the fix"
        )
    );

    println!(
        "  \x1b[1m{}\x1b[0m",
        tr("模组破洞/部位缺失修复", "Fix Mesh Holes / Missing Parts")
    );
    println!(
        "    \x1b[90m{}\x1b[0m",
        tr(
            "修复在游戏 3.3 版本后因为旧Mod中Color1的脏数据导致身体部位未显示或破洞的问题。",
            "Fix missing body parts or mesh holes caused by old WWMI export data after version 3.3+."
        )
    );

    println!(
        "  \x1b[1m{}\x1b[0m",
        tr("女漂-风主形态眼部修复", "Aero FemaleRover Eye Fix")
    );
    println!(
        "    \x1b[90m{}\x1b[0m\n",
        tr(
            "确保你的 mod 存在此问题，否则不要开启!",
            "Make sure your mod has this problem, otherwise don't enable!"
        )
    );

    let opt_tex = tr("补全贴图状态", "Add Derived Hashes").to_string();
    let opt_stable = tr("应用稳定纹理", "Apply Stable Texture").to_string();
    let opt_aemeath = tr("修复爱弥斯机兵形态的模型异常", "Fix Aemeath's mech form model error").to_string();
    let opt_rendering = tr("模组破洞/部位缺失修复", "Fix Mesh Holes / Missing Parts").to_string();
    let opt_aero = tr("女漂-风主形态眼部修复", "Aero FemaleRover Eye Fix").to_string();

    let opt_tx2 = opt_tex.clone();
    let opt_st2 = opt_stable.clone();
    let validator = move |ans: &[inquire::list_option::ListOption<&&String>]| {
        let has_tx = ans.iter().any(|o| o.value.as_str() == opt_tx2.as_str());
        let has_st = ans.iter().any(|o| o.value.as_str() == opt_st2.as_str());
        if has_tx && has_st {
            Ok(Validation::Invalid(ErrorMessage::Custom(
                tr(
                    "'补全贴图状态' 与 '应用稳定纹理' 不能同时勾选。",
                    "'Add Derived Hashes' and 'Apply Stable Texture' are mutually exclusive.",
                )
                .to_string(),
            )))
        } else {
            Ok(Validation::Valid)
        }
    };

    // Default to 0: derived hashes, 3: rendering 3.3
    let default_indices: Vec<usize> = vec![0, 3];

    let selected = match MultiSelect::new(
        tr(
            "选择额外修复选项 (空格勾选/取消, 回车确认):",
            "Select extra fix options (Space toggle, Enter confirm):",
        ),
        vec![&opt_tex, &opt_stable, &opt_aemeath, &opt_rendering, &opt_aero],
    )
    .with_default(&default_indices)
    .with_validator(validator)
    .prompt()
    {
        Ok(s) => s,
        Err(_) => return,
    };

    let enable_tex = selected.contains(&&opt_tex);
    let enable_stable = selected.contains(&&opt_stable);
    let enable_aemeath = selected.contains(&&opt_aemeath);
    let enable_rendering = selected.contains(&&opt_rendering);
    let enable_aero = selected.contains(&&opt_aero);

    let aero_mode = if enable_aero {
        let m1 = tr("TexCoord 覆盖", "TexCoord Override").to_string();
        let m2 = tr("贴图镜像反转", "Texture Mirror Flip").to_string();
        let sel = Select::new(
            tr(
                "选择风主眼部修复方式 (若一种无效请回滚换另一种):",
                "Select Aero fix method (if issues occur, rollback and try the other):",
            ),
            vec![m1.clone(), m2.clone()],
        )
        .prompt()
        .unwrap_or_else(|_| m1.clone());
        if sel == m1 { 1u8 } else { 2u8 }
    } else {
        0
    };

    println!("\n\x1b[90m{}\x1b[0m", tr("处理中...", "Processing..."));
    let progress = Arc::new(CliProgressReporter::new(OutputFormat::Text));
    let cancel_token = Arc::new(AtomicBool::new(false));
    let fixer = core::ModFixer::with_event_sink(
        core::config_loader::config().characters_ref(),
        enable_tex,
        enable_stable,
        enable_aemeath,
        enable_rendering,
        aero_mode,
        progress,
        cancel_token,
    );
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixer.process_directory(Path::new(&path))
    }));

    println!(
        "\n  \x1b[90m{}\x1b[0m\n",
        tr(
            "提示：修改已保存，游戏内按 F10 即可热重载生效。若效果异常可随时在主菜单中使用「回滚管理」一键还原。",
            "Notice: Fix applied. Press F10 in-game to reload. If issues occur, use 'Rollback Manager' in main menu to revert."
        )
    );
}

fn run_rollback_flow(settings: &mut UserSettings) {
    let default = settings.last_folder.as_deref().unwrap_or(".");
    let path = loop {
        match Text::new(tr(
            "输入 Mod 文件夹路径以扫描备份:",
            "Enter Mod folder to scan backups:",
        ))
        .with_default(default)
        .prompt()
        {
            Ok(p) => {
                let c = clean_path(&p);
                if Path::new(&c).is_dir() {
                    break c;
                }
                println!(
                    "\x1b[31m{}\x1b[0m",
                    tr("错误：无效的文件夹路径。", "Error: Invalid directory path.")
                );
            }
            Err(_) => return,
        }
    };
    settings.last_folder = Some(path.clone());
    save_settings(settings);

    let dir = Path::new(&path);
    println!("\x1b[90m{}\x1b[0m", tr("扫描中...", "Scanning..."));
    let backups = core::rollback::scan_backups(dir).unwrap_or_default();

    if backups.is_empty() {
        println!(
            "\x1b[33m{}\x1b[0m\n",
            tr(
                "未找到可用的备份文件 (.BAK)，无需回滚。",
                "No backup files (.BAK) found. Nothing to rollback."
            )
        );
        return;
    }

    let opt_restore_all = tr("全部还原 (还原到最初状态)", "Restore All (to earliest)").to_string();
    let opt_back = tr("返回上一级", "Go Back").to_string();

    let mut options = vec![opt_restore_all.clone()];
    for b in &backups {
        let display_time = if b.group_key.len() >= 16 {
            let mut s = b.group_key.clone();
            s.replace_range(13..14, ":");
            s
        } else {
            b.group_key.clone()
        };
        options.push(format!(
            "{}  ({} {})",
            display_time,
            b.files.len(),
            tr("个文件", "files")
        ));
    }
    options.push(opt_back.clone());

    if let Ok(choice) = Select::new(tr("选择要回滚的备份:", "Select backup to restore:"), options.clone()).prompt()
    {
        if choice == opt_back {
            return;
        }
        if !Confirm::new(tr(
            "确定要执行回滚吗？(当前修复将被覆盖)",
            "Are you sure? (Current fixes will be overwritten)",
        ))
        .with_default(false)
        .prompt()
        .unwrap_or(false)
        {
            println!("\x1b[90m{}\x1b[0m\n", tr("已取消。", "Canceled."));
            return;
        }

        let (group_key, msg) = if choice == opt_restore_all {
            (
                &backups.last().unwrap().group_key,
                tr("正在还原全部...", "Restoring all..."),
            )
        } else {
            let idx = options.iter().position(|x| x == &choice).unwrap() - 1;
            (&backups[idx].group_key, tr("正在回滚...", "Rolling back..."))
        };

        println!("\x1b[90m{} {}\x1b[0m", msg, group_key);
        match core::rollback::execute_rollback(dir, group_key) {
            Ok(_) => println!("\x1b[32m{}\x1b[0m\n", tr("回滚完成。", "Rollback completed.")),
            Err(e) => println!("\x1b[31m{} {}\x1b[0m\n", tr("回滚失败:", "Rollback failed:"), e),
        }
    }
}

fn run_update_flow(rt: &tokio::runtime::Runtime) {
    println!("\x1b[90m{}\x1b[0m", tr("检查更新中...", "Checking for updates..."));
    rt.block_on(async {
        let _ = core::config_loader::force_reload_remote_config().await;
        match core::config_loader::check_update_status() {
            core::config_loader::UpdateStatus::NoUpdate => {
                println!(
                    "\x1b[32m{}\x1b[0m\n",
                    tr("配置与程序均已是最新。", "Config and program are up-to-date.")
                );
                show_intro();
            }
            core::config_loader::UpdateStatus::OptionalUpdate(ver, url) => println!(
                "\x1b[33m{} v{}\n{}: {}\x1b[0m\n",
                tr("发现新版本", "New version"),
                ver,
                tr("下载", "Download"),
                url
            ),
            core::config_loader::UpdateStatus::MandatoryUpdate(ver, url) => println!(
                "\x1b[31m{} v{}\n{}: {}\x1b[0m\n",
                tr("必须更新以适配配置", "Mandatory update"),
                ver,
                tr("下载", "Download"),
                url
            ),
        }
    });
}

pub fn show_intro() {
    let lang = core::localization::config::get_lang();
    let config_ver = core::config_loader::try_config()
        .map(|c| c.version_ref().current_version.clone())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    println!(
        "\x1b[1;36m{} v{}\x1b[0m \x1b[90m(规则库 v{})\x1b[0m",
        tr("Wuwa Mod Fixer - 命令行模式", "Wuwa Mod Fixer - CLI Mode"),
        env!("CARGO_PKG_VERSION"),
        config_ver
    );

    let intro = core::localization::config::get_text("intro", &lang);
    if !intro.is_empty() && intro != "intro" {
        println!("\x1b[90m--------------------------------------------------\x1b[0m");
        for line in intro.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                if trimmed.starts_with('*') || trimmed.starts_with('-') {
                    println!("  \x1b[32m{}\x1b[0m", trimmed);
                } else {
                    println!("  \x1b[1m{}\x1b[0m", trimmed);
                }
            }
        }
        println!("\x1b[90m--------------------------------------------------\x1b[0m");
    }
    println!();
}

fn format_terminal_markdown(text: &str) -> String {
    let mut out = String::new();
    let mut in_code_block = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_code_block = !in_code_block;
            if in_code_block {
                out.push_str("    \x1b[90m┌── [Engine.ini] ────────────────────────\x1b[0m\n");
            } else {
                out.push_str("    \x1b[90m└────────────────────────────────────────\x1b[0m\n");
            }
            continue;
        }

        if in_code_block {
            let colored_line = if trimmed.starts_with('[') && trimmed.ends_with(']') {
                format!("    \x1b[90m│\x1b[0m \x1b[1;33m{}\x1b[0m", trimmed)
            } else if trimmed.contains('=') {
                let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
                format!(
                    "    \x1b[90m│\x1b[0m \x1b[32m{}\x1b[0m=\x1b[36m{}\x1b[0m",
                    parts[0], parts[1]
                )
            } else {
                format!("    \x1b[90m│\x1b[0m \x1b[37m{}\x1b[0m", trimmed)
            };
            out.push_str(&colored_line);
            out.push('\n');
            continue;
        }

        // Inline markdown formatting for bold and code
        let mut formatted = line.to_string();
        // Replace `code` with cyan
        while let Some(start) = formatted.find('`') {
            if let Some(end) = formatted[start + 1..].find('`') {
                let code_content = &formatted[start + 1..start + 1 + end];
                let replacement = format!("\x1b[36m{}\x1b[0m", code_content);
                formatted.replace_range(start..start + 2 + end, &replacement);
            } else {
                break;
            }
        }
        // Replace **bold** with bold white
        while let Some(start) = formatted.find("**") {
            if let Some(end) = formatted[start + 2..].find("**") {
                let bold_content = &formatted[start + 2..start + 2 + end];
                let replacement = format!("\x1b[1;37m{}\x1b[0m", bold_content);
                formatted.replace_range(start..start + 4 + end, &replacement);
            } else {
                break;
            }
        }

        if formatted.trim_start().starts_with('>') {
            let clean = formatted.trim_start().trim_start_matches('>').trim();
            out.push_str(&format!("    \x1b[36m│\x1b[0m \x1b[90m{}\x1b[0m\n", clean));
        } else {
            out.push_str(&format!("    {}\n", formatted.trim_end()));
        }
    }
    out
}

fn show_detailed_notes() {
    let lang = core::localization::config::get_lang();
    println!("\n\x1b[1m{}\x1b[0m", tr("-- 更新说明 --", "-- Update Notes --"));
    println!("\x1b[90m--------------------------------------------------\x1b[0m");

    let intro = core::localization::config::get_text("intro", &lang);
    if !intro.is_empty() && intro != "intro" {
        println!(
            "  \x1b[1;32m{}\x1b[0m:\n{}",
            tr("当前版本修复更新内容", "Current Version Fix Updates"),
            format_terminal_markdown(intro.trim())
        );
    }

    let intro_note = core::localization::config::get_text("intro_note", &lang);
    if !intro_note.is_empty() && intro_note != "intro_note" {
        println!(
            "\n  \x1b[1;33m{}\x1b[0m:\n{}",
            tr(
                "游戏资源与 Engine.ini 设置要求",
                "Game Resources & Engine.ini Requirements"
            ),
            format_terminal_markdown(&intro_note)
        );
    }

    let graphics_note = core::localization::config::get_text("graphics_setting_note", &lang);
    if !graphics_note.is_empty() && graphics_note != "graphics_setting_note" {
        println!(
            "\n  \x1b[1;33m{}\x1b[0m:\n  {}",
            tr("画质预设注意事项", "Preset Notice"),
            graphics_note.trim()
        );
    }

    let compat_note = core::localization::config::get_text("compatibility_note", &lang);
    if !compat_note.is_empty() && compat_note != "compatibility_note" {
        println!(
            "\n  \x1b[90m{}\x1b[0m:\n{}",
            tr("旧版兼容模式说明", "Compatibility Mode Note"),
            format_terminal_markdown(&compat_note)
        );
    }

    println!(
        "\n  \x1b[36m{}\x1b[0m:\n  {}",
        tr("热重载提示", "Hot Reload Tip"),
        tr(
            "Mod 修复完成后，在游戏内按 F10 即可重新载入生效，无需重启游戏。",
            "After fixing, press F10 in-game to reload mods without restarting."
        )
    );

    println!("\x1b[90m--------------------------------------------------\x1b[0m\n");
}

pub fn clean_path(p: &str) -> String {
    let mut cleaned = p.trim().to_string();

    // 1. Remove PowerShell drag-and-drop leading '&'
    if cleaned.starts_with('&') {
        cleaned = cleaned[1..].trim().to_string();
    }

    // 2. Strip quotes
    cleaned = cleaned.trim_matches('\'').trim_matches('"').trim().to_string();

    // 3. Normalize slashes & trim trailing slashes (except root "C:\" or "/")
    if cleaned.len() > 3 {
        while cleaned.ends_with('\\') || cleaned.ends_with('/') {
            cleaned.pop();
        }
    }

    // 4. Resolve canonical or absolute path if directory exists
    if let Ok(canonical) = std::fs::canonicalize(&cleaned) {
        let s = canonical.to_string_lossy().to_string();
        if let Some(stripped) = s.strip_prefix(r"\\?\") {
            return stripped.to_string();
        }
        return s;
    }

    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_path_variations() {
        assert_eq!(clean_path(r#"  "D:\Games\Mods\"  "#), r#"D:\Games\Mods"#);
        assert_eq!(clean_path(r#"& 'C:\MyMods/sub/' "#), r#"C:\MyMods/sub"#);
        assert_eq!(clean_path(r#"'D:/test'"#), r#"D:/test"#);
    }

    #[test]
    fn test_cli_args_parsing_defaults() {
        let args = CliArgs::try_parse_from(["Wuwa_Mod_Fixer"]).unwrap();
        assert_eq!(args.format, OutputFormat::Text);
        assert!(!args.is_cli_mode());
    }

    #[test]
    fn test_cli_args_parsing_json_format() {
        let args = CliArgs::try_parse_from([
            "Wuwa_Mod_Fixer",
            "--path",
            "C:/mods",
            "--format",
            "json",
            "--rendering-33",
        ])
        .unwrap();

        assert_eq!(args.format, OutputFormat::Json);
        assert_eq!(args.path.as_deref(), Some("C:/mods"));
        assert!(args.rendering_33);
        assert!(args.is_cli_mode());
    }

    #[test]
    fn test_json_event_serialization() {
        let start_ev = CliEvent::Start { mode: "fix", total: 10 };
        let start_json = serde_json::to_string(&start_ev).unwrap();
        assert_eq!(start_json, r#"{"event":"start","mode":"fix","total":10}"#);

        let progress_ev = CliEvent::Progress {
            current: 5,
            total: 10,
            percent: 50.0,
        };
        let prog_json = serde_json::to_string(&progress_ev).unwrap();
        assert_eq!(
            prog_json,
            r#"{"event":"progress","current":5,"total":10,"percent":50.0}"#
        );

        let finish_ev = CliEvent::Finish {
            success: true,
            message: "Done".to_string(),
        };
        let finish_json = serde_json::to_string(&finish_ev).unwrap();
        assert_eq!(finish_json, r#"{"event":"finish","success":true,"message":"Done"}"#);
    }

    #[test]
    fn test_cli_progress_reporter() {
        use wuwa_mod_core::ProgressReporter;
        let reporter = CliProgressReporter::new(OutputFormat::Json);
        reporter.set_total(20);
        assert_eq!(reporter.total(), 20);
        assert_eq!(reporter.current(), 0);

        reporter.increment();
        assert_eq!(reporter.current(), 1);
        reporter.increment();
        assert_eq!(reporter.current(), 2);
    }

    #[test]
    fn test_cli_event_sink_pipeline_events() {
        use wuwa_mod_core::EventSink;
        let reporter = CliProgressReporter::new(OutputFormat::Text);
        reporter.emit(core::PipelineEvent::Start {
            mode: "fix".to_string(),
            total: 10,
            session_time: None,
        });
        assert_eq!(core::ProgressReporter::total(&reporter), 10);

        reporter.emit(core::PipelineEvent::Progress {
            current: 4,
            total: 10,
            percent: 40.0,
            status_text: None,
        });
        assert_eq!(core::ProgressReporter::current(&reporter), 4);
    }
}
