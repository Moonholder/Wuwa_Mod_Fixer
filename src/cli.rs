use inquire::{validator::Validation, validator::ErrorMessage, Confirm, MultiSelect, Select, Text};
use std::path::Path;

use crate::settings::{load_settings, save_settings, UserSettings};
use crate::ModFixer;

// ---------------------------------------------------------------------------
// Non-interactive CLI argument parsing
// ---------------------------------------------------------------------------

pub struct CliArgs {
    pub path: Option<String>,
    pub derived_hashes: bool,
    pub stable_texture: bool,
    pub aemeath_mech: bool,
    pub texcoord_color: bool,
    pub aero_fix: u8, // 0 = disabled, 1 = TexCoord, 2 = Mirror
    pub online: bool,
    pub rollback: bool,
}

pub fn parse_cli_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut result = CliArgs {
        path: None,
        derived_hashes: false,
        stable_texture: false,
        aemeath_mech: false,
        texcoord_color: false,
        aero_fix: 0,
        online: false,
        rollback: false,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--path" => {
                if i + 1 < args.len() {
                    result.path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("\x1b[31m{}\x1b[0m", tr!(
                        "错误：--path 需要一个文件夹路径参数。",
                        "Error: --path requires a directory argument."
                    ));
                    std::process::exit(1);
                }
            }
            "--derived-hashes" => {
                result.derived_hashes = true;
                i += 1;
            }
            "--stable-texture" => {
                result.stable_texture = true;
                i += 1;
            }
            "--aemeath-mech" => {
                result.aemeath_mech = true;
                i += 1;
            }
            "--texcoord-color" => {
                result.texcoord_color = true;
                i += 1;
            }
            "--aero-fix" => {
                if i + 1 < args.len() {
                    match args[i + 1].as_str() {
                        "1" => result.aero_fix = 1,
                        "2" => result.aero_fix = 2,
                        _ => {
                            eprintln!("\x1b[31m{}\x1b[0m", tr!(
                                "错误：--aero-fix 仅接受 1 (TexCoord 覆盖) 或 2 (贴图镜像反转)。",
                                "Error: --aero-fix accepts only 1 (TexCoord Override) or 2 (Texture Mirror Flip)."
                            ));
                            std::process::exit(1);
                        }
                    }
                    i += 2;
                } else {
                    eprintln!("\x1b[31m{}\x1b[0m", tr!(
                        "错误：--aero-fix 需要一个参数 (1 或 2)。",
                        "Error: --aero-fix requires an argument (1 or 2)."
                    ));
                    std::process::exit(1);
                }
            }
            "--online" => {
                result.online = true;
                i += 1;
            }
            "--rollback" => {
                result.rollback = true;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    result
}

pub fn run_direct_fix(args: &CliArgs) {
    let path = args.path.as_ref().unwrap();
    let clean_path = path
        .trim()
        .trim_start_matches('&')
        .trim()
        .trim_matches('\'')
        .trim_matches('"')
        .to_string();

    if !Path::new(&clean_path).is_dir() {
        eprintln!(
            "\x1b[31m{}\x1b[0m",
            tr!("错误：无效的文件夹路径。", "Error: Invalid directory path.")
        );
        std::process::exit(1);
    }

    if args.derived_hashes && args.stable_texture {
        eprintln!(
            "\x1b[31m{}\x1b[0m",
            tr!(
                "错误：'--derived-hashes' 与 '--stable-texture' 不能同时启用。",
                "Error: '--derived-hashes' and '--stable-texture' are mutually exclusive."
            )
        );
        std::process::exit(1);
    }

    if args.rollback {
        eprintln!(
            "\x1b[31m{}\x1b[0m",
            tr!(
                "错误：'--rollback' 不能与修复选项同时使用，请单独执行回滚。",
                "Error: '--rollback' cannot be used with fix options. Run rollback separately."
            )
        );
        std::process::exit(1);
    }

    println!(
        "\x1b[1m{}\x1b[0m",
        tr!(
            "Wuwa Mod Fixer - 直接修复模式",
            "Wuwa Mod Fixer - Direct Fix Mode"
        )
    );
    println!("\x1b[90m--------------------------------------------------\x1b[0m");
    println!("  {}: {}", tr!("路径", "Path"), clean_path);
    println!(
        "  {}: {}",
        tr!("补全贴图状态", "Derived Hashes"),
        if args.derived_hashes { "✓" } else { "✗" }
    );
    println!(
        "  {}: {}",
        tr!("应用稳定纹理", "Stable Texture"),
        if args.stable_texture { "✓" } else { "✗" }
    );
    println!(
        "  {}: {}",
        tr!("修复爱弥斯机兵", "Aemeath Mech Fix"),
        if args.aemeath_mech { "✓" } else { "✗" }
    );
    println!(
        "  {}: {}",
        tr!("修复 TexCoord COLOR1", "TexCoord COLOR1 Fix"),
        if args.texcoord_color { "✓" } else { "✗" }
    );
    println!(
        "  {}: {}",
        tr!("风主眼部修复", "Aero Eye Fix"),
        match args.aero_fix {
            1 => tr!("TexCoord 覆盖", "TexCoord Override"),
            2 => tr!("贴图镜像反转", "Texture Mirror Flip"),
            _ => tr!("关闭", "Disabled"),
        }
    );
    println!("\x1b[90m--------------------------------------------------\x1b[0m");

    println!(
        "\n\x1b[90m{}\x1b[0m",
        tr!("处理中...", "Processing...")
    );

    let fixer = ModFixer::new(
        crate::config_loader::characters(),
        args.derived_hashes,
        args.stable_texture,
        args.aemeath_mech,
        args.texcoord_color,
        args.aero_fix,
    );

    crate::reset_progress();
    let result = std::panic::catch_unwind(|| {
        let _ = fixer.process_directory(Path::new(&clean_path));
    });

    if result.is_err() {
        eprintln!("\x1b[31m{}\x1b[0m", t!(error_prompt));
        std::process::exit(1);
    } else {
        println!("\x1b[32m{}\x1b[0m", t!(all_done));
    }
}

pub fn run_direct_rollback(args: &CliArgs) {
    let path = args.path.as_ref().unwrap();
    let clean_path = path
        .trim()
        .trim_start_matches('&')
        .trim()
        .trim_matches('\'')
        .trim_matches('"')
        .to_string();

    if !Path::new(&clean_path).is_dir() {
        eprintln!(
            "\x1b[31m{}\x1b[0m",
            tr!("错误：无效的文件夹路径。", "Error: Invalid directory path.")
        );
        std::process::exit(1);
    }

    let has_fix_options = args.derived_hashes || args.stable_texture || args.aemeath_mech || args.texcoord_color || args.aero_fix > 0;
    if has_fix_options {
        eprintln!(
            "\x1b[31m{}\x1b[0m",
            tr!(
                "错误：'--rollback' 不能与修复选项同时使用，请单独执行回滚。",
                "Error: '--rollback' cannot be used with fix options. Run rollback separately."
            )
        );
        std::process::exit(1);
    }

    let dir = Path::new(&clean_path);
    println!(
        "\x1b[1m{}\x1b[0m",
        tr!(
            "Wuwa Mod Fixer - 回滚模式",
            "Wuwa Mod Fixer - Rollback Mode"
        )
    );
    println!("\x1b[90m--------------------------------------------------\x1b[0m");
    println!("  {}: {}", tr!("路径", "Path"), clean_path);

    println!(
        "\x1b[90m{}\x1b[0m",
        tr!("扫描备份文件...", "Scanning backup files...")
    );
    let backups = crate::rollback::scan_backups(dir).unwrap_or_default();

    if backups.is_empty() {
        println!(
            "\x1b[33m{}\x1b[0m",
            tr!(
                "未找到可用的备份文件 (.BAK)，无需回滚。",
                "No backup files (.BAK) found. Nothing to rollback."
            )
        );
        return;
    }

    // Safety: only rollback the most recent fix (first group = newest)
    let latest = &backups[0];
    println!(
        "  {}: {}  ({} {})",
        tr!("回滚目标", "Rollback target"),
        latest.group_key,
        latest.files.len(),
        tr!("个文件", "files")
    );
    println!("\x1b[90m--------------------------------------------------\x1b[0m");

    println!(
        "\n\x1b[90m{}\x1b[0m",
        tr!("正在回滚...", "Rolling back...")
    );

    match crate::rollback::execute_rollback(dir, &latest.group_key) {
        Ok(_) => println!(
            "\x1b[32m{}\x1b[0m",
            tr!("回滚完成。", "Rollback completed.")
        ),
        Err(e) => {
            eprintln!(
                "\x1b[31m{} {}\x1b[0m",
                tr!("回滚失败:", "Rollback failed:"),
                e
            );
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Interactive CLI mode (original behavior)
// ---------------------------------------------------------------------------

pub fn run_interactive(rt: &tokio::runtime::Runtime) {
    let mut settings = load_settings();

    println!("\x1b[1m{}\x1b[0m", tr!("Wuwa Mod Fixer - 命令行模式", "Wuwa Mod Fixer - CLI Mode"));
    println!("\x1b[90m--------------------------------------------------\x1b[0m");
    show_intro();
    println!("\x1b[90m--------------------------------------------------\x1b[0m\n");

    loop {
        let opt_fix = tr!("一键修复", "Start Fix").to_string();
        let opt_rollback = tr!("回滚管理", "Rollback Manager").to_string();
        let opt_update = tr!("更新配置", "Update Config").to_string();
        let opt_exit = tr!("退出程序", "Exit").to_string();

        let options = vec![opt_fix.clone(), opt_rollback.clone(), opt_update.clone(), opt_exit.clone()];

        let ans = Select::new(tr!("请选择操作:", "Select Action:"), options).prompt();

        match ans {
            Ok(choice) if choice == opt_fix => run_fix_flow(&mut settings),
            Ok(choice) if choice == opt_rollback => run_rollback_flow(&settings),
            Ok(choice) if choice == opt_update => run_update_flow(rt),
            Ok(choice) if choice == opt_exit => break,
            Err(_) => break,
            _ => {}
        }
    }
}

fn run_fix_flow(settings: &mut UserSettings) {
    let default_path = settings.last_folder.as_deref().unwrap_or(".");
    
    let input_path = loop {
        match Text::new(tr!("输入 Mod 文件夹路径 (可直接拖放):", "Enter Mod folder path (drag & drop supported):"))
            .with_default(default_path)
            .prompt() 
        {
            Ok(p) => {
                let clean_p = p.trim().trim_start_matches('&').trim().trim_matches('\'').trim_matches('"').to_string();
                if Path::new(&clean_p).is_dir() { break clean_p; } 
                else { println!("\x1b[31m{}\x1b[0m", tr!("错误：无效的文件夹路径。", "Error: Invalid directory path.")); }
            }
            Err(_) => return,
        }
    };

    settings.last_folder = Some(input_path.clone());
    save_settings(settings);

    println!("\n\x1b[1m{}\x1b[0m", tr!("-- 修复选项说明 --", "-- Fix Options Info --"));
    
    println!("  \x1b[1m{}\x1b[0m", tr!("补全贴图状态", "Add Derived Hashes"));
    println!("    \x1b[90m{}\x1b[0m", tr!("为模组补全缺失的贴图状态Hash (如画面细节高/中、坎特蕾拉湿身、千咲强化E、爱弥斯满充能等) (部分角色未添加)", "Add missing texture state hashes (e.g. LOD Bias High/Medium, Cantarella wet, Chisa Enhanced E, Aemeath Charged) so character mod textures display correctly (some characters not added)"));
    
    println!("  \x1b[1m{}\x1b[0m", tr!("应用稳定纹理", "Apply Stable Texture"));
    println!("    \x1b[90m{}\x1b[0m", tr!("使用 RabbitFX 为角色设置稳定纹理 (目前仅坎特蕾拉、千咲、卡提、夏空...)，需安装最新的RabbitFX", "Use RabbitFX to set stable textures for characters (currently Cantarella, Chisa, Cartethyia, Ciaccona...). Requires latest RabbitFX"));
    
    println!("  \x1b[1m{}\x1b[0m", tr!("修复爱弥斯机兵形态的模型异常", "Fix Aemeath's mech form model error"));
    println!("    \x1b[90m{}\x1b[0m", tr!("不要对正常的爱弥斯机兵模组启用此功能，不要重复修复", "Do not enable this function for Aemeath mech mods that are already normal, do not repeat the fix"));
    
    println!("  \x1b[1m{}\x1b[0m", tr!("女漂-风主形态眼部修复", "Aero FemaleRover Eye Fix (eyes glitch when resonance energy is full)"));
    println!("    \x1b[90m{}\x1b[0m", tr!("确保你的 mod 存在此问题，否则不要开启!", "Make sure your mod has this problem, otherwise don't enable!"));

    println!("  \x1b[1m{}\x1b[0m", tr!("修复3.3版本爱弥斯 莫宁 琳奈等角色部分模组某些部位不显示的问题", "Fix some parts of mods for Aemeath&Mornye etc. characters not rendering in 3.3"));
    println!("    \x1b[90m{}\x1b[0m\n", tr!("不建议对正常模组启用此选项，以避免可能的副作用", "Do not enable this option for normal mods to avoid possible side effects)"));

    let opt_tex = tr!("补全贴图状态", "Added Derived Hashes").to_string();
    let opt_stable = tr!("应用稳定纹理", "Apply Stable Texture").to_string();
    let opt_aemeath = tr!("修复爱弥斯机兵形态的模型异常", "Fix Aemeath's mech form model error").to_string();
    let opt_aero = tr!("女漂-风主形态眼部修复", "Aero FemaleRover Eye Fix (eyes glitch when resonance energy is full)").to_string();
    let opt_texcoord_color = tr!("修复3.3版本爱弥斯 莫宁 琳奈等角色部分模组某些部位不显示的问题", "Fix some parts of mods for Aemeath&Mornye etc. characters not rendering in 3.3").to_string();
    
    let options = vec![
        opt_tex.clone(),
        opt_stable.clone(),
        opt_aemeath.clone(),
        opt_texcoord_color.clone(),
        opt_aero.clone(),
    ];

    let opt_tex_c = opt_tex.clone();
    let opt_stable_c = opt_stable.clone();
    let validator = move |ans: &[inquire::list_option::ListOption<&String>]| {
        let has_tex = ans.iter().any(|o| o.value == &opt_tex_c);
        let has_stable = ans.iter().any(|o| o.value == &opt_stable_c);
        if has_tex && has_stable {
            Ok(Validation::Invalid(ErrorMessage::Custom(
                tr!("'补全贴图状态' 与 '应用稳定纹理' 不能同时勾选。", "'Complete Texture States' and 'Apply Stable Texture' are mutually exclusive.").to_string()
            )))
        } else {
            Ok(Validation::Valid)
        }
    };

    let ext_ans = match MultiSelect::new(
        tr!("选择额外修复选项 (空格勾选, 回车确认):", "Select extra fix options (Space toggle, Enter confirm):"),
        options
    )
    .with_validator(validator)
    .prompt() {
        Ok(ans) => ans,
        Err(_) => return,
    };

    let enable_tex = ext_ans.contains(&opt_tex);
    let enable_stable = ext_ans.contains(&opt_stable);
    let enable_aemeath = ext_ans.contains(&opt_aemeath);
    let enable_texcoord_color = ext_ans.contains(&opt_texcoord_color);
    let enable_aero = ext_ans.contains(&opt_aero);

    let mut aero_mode = 0;
    if enable_aero {
        let opt_m1 = tr!("TexCoord 覆盖", "TexCoord Override").to_string();
        let opt_m2 = tr!("贴图镜像反转", "Texture Mirror Flip").to_string();
        
        let sel_aero = Select::new(
            tr!("选择风主眼部修复方式 (若一种无效请回滚换另一种):", "Select Aero fix method (if issues occur, rollback and try the other):"),
            vec![opt_m1.clone(), opt_m2.clone()]
        ).prompt().unwrap_or_else(|_| opt_m1.clone());

        aero_mode = if sel_aero == opt_m1 { 1 } else { 2 };
    }

    // 执行修复
    println!("\n\x1b[90m{}\x1b[0m", tr!("处理中...", "Processing..."));
    let fixer = ModFixer::new(
        crate::config_loader::characters(),
        enable_tex, enable_stable, enable_aemeath, enable_texcoord_color, aero_mode
    );

    crate::reset_progress();
    let result = std::panic::catch_unwind(|| { let _ = fixer.process_directory(Path::new(&input_path)); });

    if result.is_err() { 
        println!("\x1b[31m{}\x1b[0m\n", t!(error_prompt)); 
    } else { 
        println!("\x1b[32m{}\x1b[0m\n", t!(all_done)); 
    }
}

fn run_rollback_flow(settings: &UserSettings) {
    let default_path = settings.last_folder.as_deref().unwrap_or(".");
    let input_path = loop {
        match Text::new(tr!("输入 Mod 文件夹路径以扫描备份:", "Enter Mod folder to scan backups:"))
            .with_default(default_path).prompt() 
        {
            Ok(p) => {
                let clean_p = p.trim().trim_start_matches('&').trim().trim_matches('\'').trim_matches('"').to_string();
                if Path::new(&clean_p).is_dir() { break clean_p; } 
                else { println!("\x1b[31m{}\x1b[0m", tr!("错误：无效的文件夹路径。", "Error: Invalid directory path.")); }
            }
            Err(_) => return,
        }
    };

    let dir = Path::new(&input_path);
    println!("\x1b[90m{}\x1b[0m", tr!("扫描中...", "Scanning..."));
    let backups = crate::rollback::scan_backups(dir).unwrap_or_default();

    if backups.is_empty() {
        println!("\x1b[33m{}\x1b[0m\n", tr!("未找到可用的备份文件 (.BAK)", "No backup files (.BAK) found."));
        return;
    }

    let opt_restore_all = tr!("全部还原 (还原到最初状态)", "Restore All (to earliest)").to_string();
    let opt_back = tr!("返回上一级", "Go Back").to_string();

    let mut options = vec![opt_restore_all.clone()];
    for b in &backups {
        let display_time = if b.group_key.len() >= 16 {
            let mut s = b.group_key.clone();
            s.replace_range(13..14, ":"); s
        } else { b.group_key.clone() };
        options.push(format!("{}  ({} {})", display_time, b.files.len(), tr!("个文件", "files")));
    }
    options.push(opt_back.clone());

    if let Ok(choice) = Select::new(tr!("选择要回滚的备份:", "Select backup to restore:"), options.clone()).prompt() {
        if choice == opt_back { return; }
        if !Confirm::new(tr!("确定要执行回滚吗？(当前修复将被覆盖)", "Are you sure? (Current fixes will be overwritten)"))
            .with_default(false).prompt().unwrap_or(false) {
            println!("\x1b[90m{}\x1b[0m\n", tr!("已取消。", "Canceled.")); return;
        }

        let (group_key, msg) = if choice == opt_restore_all {
            (&backups.last().unwrap().group_key, tr!("正在还原全部...", "Restoring all..."))
        } else {
            let idx = options.iter().position(|x| x == &choice).unwrap() - 1;
            (&backups[idx].group_key, tr!("正在回滚...", "Rolling back..."))
        };

        println!("\x1b[90m{} {}\x1b[0m", msg, group_key);
        match crate::rollback::execute_rollback(dir, group_key) {
            Ok(_) => println!("\x1b[32m{}\x1b[0m\n", tr!("回滚完成。", "Rollback completed.")),
            Err(e) => println!("\x1b[31m{} {}\x1b[0m\n", tr!("回滚失败:", "Rollback failed:"), e),
        }
    }
}

fn run_update_flow(rt: &tokio::runtime::Runtime) {
    println!("\x1b[90m{}\x1b[0m", tr!("检查更新中...", "Checking for updates..."));
    rt.block_on(async {
        let _ = crate::config_loader::force_reload_remote_config().await;
        match crate::config_loader::check_update_status() {
            crate::config_loader::UpdateStatus::NoUpdate => println!("\x1b[32m{}\x1b[0m\n", tr!("配置与程序均已是最新。", "Config and program are up-to-date.")),
            crate::config_loader::UpdateStatus::OptionalUpdate(ver, url) => println!("\x1b[33m{} v{}\n{}: {}\x1b[0m\n", tr!("发现新版本", "New version"), ver, tr!("下载", "Download"), url),
            crate::config_loader::UpdateStatus::MandatoryUpdate(ver, url) => println!("\x1b[31m{} v{}\n{}: {}\x1b[0m\n", tr!("必须更新以适配配置", "Mandatory update"), ver, tr!("下载", "Download"), url),
        }
    });
}

fn show_intro() {
    println!("\x1b[1m{}\x1b[0m", t!(intro));
    println!("\x1b[90m{}\x1b[0m", t!(intro_note));
    println!("\x1b[90m{}\x1b[0m", t!(compatibility_note));
    println!("\x1b[90m{}\x1b[0m", t!(graphics_setting_note));
}