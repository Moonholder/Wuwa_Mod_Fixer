use iced::widget::{
    button, checkbox, column, container, radio, row, rule, scrollable,
    text, Column, Space,
};
use iced::widget::operation::snap_to;
use iced::{
    window, Alignment, Color, Element, Length,
    Subscription, Task, Theme,
};
use iced::font::Weight;
use iced::Font;
use once_cell::sync::Lazy;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::config_loader;
use crate::localization::config::get_lang;
use crate::rollback;
use crate::ModFixer;

// ---------------------------------------------------------------------------
// Log channel: worker thread -> GUI
// ---------------------------------------------------------------------------
type LogReceiver = std::sync::mpsc::Receiver<String>;

// ---------------------------------------------------------------------------
// Window icon — parsed from the actual icon.ico file
// Falls back to a programmatic gradient if ICO parsing fails.
// ---------------------------------------------------------------------------
const ICO_BYTES: &[u8] = include_bytes!("../icon.ico");

fn load_app_icon() -> Option<window::Icon> {
    parse_ico_to_rgba(ICO_BYTES)
        .and_then(|(rgba, w, h)| window::icon::from_rgba(rgba, w, h).ok())
        .or_else(create_fallback_icon)
}

fn parse_ico_to_rgba(data: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    if data.len() < 6 { return None; }
    let count = u16::from_le_bytes([data[4], data[5]]) as usize;

    // Find 32x32 entry, or fall back to the smallest available
    let mut best_idx = 0;
    let mut best_w = 0u32;
    for i in 0..count {
        let off = 6 + i * 16;
        if off + 16 > data.len() { return None; }
        let w = if data[off] == 0 { 256 } else { data[off] as u32 };
        if w == 32 { best_idx = i; break; }
        if best_w == 0 || w < best_w { best_idx = i; best_w = w; }
    }

    let ent = 6 + best_idx * 16;
    let w = if data[ent] == 0 { 256 } else { data[ent] as u32 };
    let h = if data[ent + 1] == 0 { 256 } else { data[ent + 1] as u32 };
    let img_size = u32::from_le_bytes([data[ent+8], data[ent+9], data[ent+10], data[ent+11]]) as usize;
    let img_off = u32::from_le_bytes([data[ent+12], data[ent+13], data[ent+14], data[ent+15]]) as usize;

    if img_off + img_size > data.len() { return None; }
    let img = &data[img_off..];

    // PNG signature check — can't parse without a library
    if img.len() >= 4 && img[0] == 0x89 && img[1] == 0x50 { return None; }

    // Parse DIB/BMP header
    if img.len() < 40 { return None; }
    let bpp = u16::from_le_bytes([img[14], img[15]]);
    if bpp != 32 { return None; } // Only 32-bit BGRA

    let header_sz = u32::from_le_bytes([img[0], img[1], img[2], img[3]]) as usize;
    let row_bytes = (w * 4) as usize;

    let mut rgba = vec![0u8; (w * h * 4) as usize];
    for y in 0..h {
        let src_row = header_sz + ((h - 1 - y) as usize) * row_bytes; // BMP is bottom-up
        for x in 0..w as usize {
            let s = src_row + x * 4;
            let d = ((y * w) as usize + x) * 4;
            if s + 3 >= img.len() { continue; }
            rgba[d]     = img[s + 2]; // B -> R
            rgba[d + 1] = img[s + 1]; // G
            rgba[d + 2] = img[s];     // R -> B
            rgba[d + 3] = img[s + 3]; // A
        }
    }
    Some((rgba, w, h))
}

fn create_fallback_icon() -> Option<window::Icon> {
    let size = 32u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        let t = y as f32 / size as f32;
        let r = (92.0 + (61.0 - 92.0) * t) as u8;
        let g = (173.0 + (133.0 - 173.0) * t) as u8;
        let b = (227.0 + (184.0 - 227.0) * t) as u8;
        for x in 0..size {
            let idx = ((y * size + x) * 4) as usize;
            rgba[idx] = r; rgba[idx+1] = g; rgba[idx+2] = b; rgba[idx+3] = 255;
        }
    }
    window::icon::from_rgba(rgba, size, size).ok()
}

// ---------------------------------------------------------------------------
// Custom accent colors
// ---------------------------------------------------------------------------
const ACCENT: Color = Color::from_rgb(0.36, 0.68, 0.89);       // #5CADE3 — calm blue
const ACCENT_DARK: Color = Color::from_rgb(0.24, 0.52, 0.72);  // #3D85B8
const SUCCESS: Color = Color::from_rgb(0.30, 0.78, 0.47);      // #4DC778
const DANGER: Color = Color::from_rgb(0.90, 0.35, 0.35);       // #E65959

// Dynamic colors based on theme
fn get_surface(theme: &Theme) -> Color {
    if theme == &Theme::Light { Color::from_rgb(0.96, 0.96, 0.98) } else { Color::from_rgb(0.12, 0.13, 0.15) }
}
fn get_surface_light(theme: &Theme) -> Color {
    if theme == &Theme::Light { Color::WHITE } else { Color::from_rgb(0.18, 0.19, 0.22) }
}
fn get_text_color(theme: &Theme) -> Color {
    if theme == &Theme::Light { Color::from_rgb(0.1, 0.1, 0.12) } else { Color::WHITE }
}
fn get_text_dim(theme: &Theme) -> Color {
    if theme == &Theme::Light { Color::from_rgb(0.40, 0.42, 0.48) } else { Color::from_rgb(0.55, 0.57, 0.62) }
}
fn get_border_color(theme: &Theme) -> Color {
    if theme == &Theme::Light { Color::from_rgb(0.88, 0.88, 0.90) } else { Color::from_rgb(0.20, 0.22, 0.25) }
}

const MAX_LOG_LINES: usize = 2000;

static LOG_SCROLL_ID: Lazy<iced::widget::Id> = Lazy::new(|| iced::widget::Id::new("log_scroll"));

// ---------------------------------------------------------------------------
// User settings — persisted to settings.json next to the executable
// ---------------------------------------------------------------------------
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct UserSettings {
    last_folder: Option<String>,
    light_theme: Option<bool>,
    window_width: Option<f32>,
    window_height: Option<f32>,
    window_x: Option<i32>,
    window_y: Option<i32>,
}

fn settings_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("settings.json")
}

fn load_settings() -> UserSettings {
    std::fs::read_to_string(settings_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_settings(settings: &UserSettings) {
    if let Ok(json) = serde_json::to_string_pretty(settings) {
        let _ = std::fs::write(settings_path(), json);
    }
}

// ---------------------------------------------------------------------------
// Bilingual helper
// ---------------------------------------------------------------------------
fn tr(zh: &str, en: &str) -> String {
    if get_lang() == "zh" { zh.to_string() } else { en.to_string() }
}

// ---------------------------------------------------------------------------
// Public entry — iced 0.14 functional API
// ---------------------------------------------------------------------------
pub fn run_gui() -> iced::Result {
    let settings = load_settings();

    fn app_title(_state: &WuwaModFixerApp) -> String {
        let base = format!("Wuwa Mod Fixer v{}", env!("CARGO_PKG_VERSION"));
        if crate::is_dev_mode() {
            format!("{} [DEV]", base)
        } else {
            base
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Force vulkan backend on linux to avoid llvmpipe/SVGA3D crashes
        if std::env::var("WGPU_BACKEND").is_err() {
            unsafe {
                std::env::set_var("WGPU_BACKEND", "vulkan");
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Force DX12/DX11 backends on Windows to avoid OpenGL driver bugs (e.g. LoadLibrary Error 126 on AMD)
        if std::env::var("WGPU_BACKEND").is_err() {
            unsafe {
                std::env::set_var("WGPU_BACKEND", "dx12,dx11");
            }
        }
    }

    fn app_theme(state: &WuwaModFixerApp) -> Theme {
        state.theme.clone()
    }

    let window_size = iced::Size::new(
        settings.window_width.unwrap_or(880.0).max(480.0),
        settings.window_height.unwrap_or(720.0).max(580.0),
    );

    let window_pos = if let (Some(x), Some(y)) = (settings.window_x, settings.window_y) {
        if x.abs() > 4000 || y.abs() > 4000 {
            window::Position::Centered
        } else {
            window::Position::Specific(iced::Point::new(x as f32, y as f32))
        }
    } else {
        window::Position::Centered
    };

    // application(boot, update, view) — boot is Fn() -> (State, Task)
    iced::application(WuwaModFixerApp::new, WuwaModFixerApp::update, WuwaModFixerApp::view)
        .title(app_title)
        .theme(app_theme)
        .subscription(WuwaModFixerApp::subscription)
        .window(window::Settings {
            size: window_size,
            position: window_pos,
            icon: load_app_icon(),
            ..Default::default()
        })
        .antialiasing(false)
        .run()
}

// ---------------------------------------------------------------------------
// View enum
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Main,
    Rollback,
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub enum Message {
    SelectFolder,
    FolderSelected(Option<PathBuf>),
    ToggleTextureOverride(bool),
    ToggleStableTexture(bool),
    SetAeroFixMode(u8),
    ToggleDebugLogs(bool),
    ClearLogs,
    ExportLogs,
    StartFix,
    FixFinished,
    LogTick,
    SwitchView(View),
    RefreshBackups,
    BackupsLoaded(Vec<rollback::BackupGroup>),
    ConfirmRollback(String),
    CancelRollback,
    ExecuteRollback(String),
    ConfirmRestoreAll,
    RollbackFinished(Result<(), String>),
    RefreshConfig,
    ConfigRefreshed(Result<String, String>),
    StartupCheckDone(crate::config_loader::UpdateStatus),
    OpenUpdateUrl,
    ToggleTheme,
    EventOccurred(iced::Event),
    OpenGithubUrl,
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------
struct WuwaModFixerApp {
    mod_path: Option<PathBuf>,
    enable_texture_override: bool,
    enable_stable_texture: bool,
    aero_fix_mode: u8,
    logs: Vec<String>,
    is_processing: bool,
    current_view: View,
    backup_groups: Vec<rollback::BackupGroup>,
    log_rx: Option<Arc<Mutex<LogReceiver>>>,
    update_info: crate::config_loader::UpdateStatus,
    config_ready: bool,
    pending_rollback: Option<String>,
    files_processed: usize,
    files_total: usize,
    show_debug_logs: bool,
    fix_just_completed: bool,
    intro_end_index: usize,
    theme: Theme,
}

impl WuwaModFixerApp {
    fn new() -> (Self, Task<Message>) {
        let settings = load_settings();
        let last_folder = settings.last_folder
            .map(PathBuf::from)
            .filter(|p| p.is_dir());

        let mut init_logs = vec![
            tr("=================================", "================================="),
            t!(intro).to_string(),
            t!(intro_note).to_string(),
            t!(compatibility_note).to_string(),
            t!(graphics_setting_note).to_string(),
            tr("=================================", "================================="),
        ];

        if let Some(ref p) = last_folder {
            init_logs.push(format!(
                "[*] {}: {}",
                tr("已加载上次使用的文件夹", "Loaded last used folder"),
                p.display()
            ));
        }
        init_logs.push(tr("准备就绪...", "Ready..."));

        let intro_end_index = init_logs.len();

        let app = Self {
            mod_path: last_folder,
            enable_texture_override: false,
            enable_stable_texture: false,
            aero_fix_mode: 0,
            logs: init_logs,
            is_processing: false,
            current_view: View::Main,
            backup_groups: Vec::new(),
            log_rx: None,
            update_info: crate::config_loader::UpdateStatus::NoUpdate,
            config_ready: false,
            pending_rollback: None,
            files_processed: 0,
            files_total: 0,
            show_debug_logs: false,
            fix_just_completed: false,
            intro_end_index,
            theme: if settings.light_theme == Some(true) { Theme::Light } else { Theme::Dark },
        };

        let startup_cmd = if crate::is_dev_mode() {
            Task::perform(
                async { crate::config_loader::check_update_status() },
                Message::StartupCheckDone,
            )
        } else {
            Task::perform(
                async {
                    let _ = crate::config_loader::force_reload_remote_config().await;
                    crate::config_loader::check_update_status()
                },
                Message::StartupCheckDone,
            )
        };

        (app, startup_cmd)
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::SelectFolder => {
                return Task::perform(
                    async {
                        let handle = rfd::AsyncFileDialog::new()
                            .set_title("Select Mod Folder")
                            .pick_folder()
                            .await;
                        handle.map(|h| h.path().to_path_buf())
                    },
                    Message::FolderSelected,
                );
            }
            Message::FolderSelected(path) => {
                if let Some(ref p) = path {
                    self.logs.push(format!(
                        "{}: {}",
                        tr("已选择", "Selected"),
                        p.display()
                    ));
                    let mut settings = load_settings();
                    settings.last_folder = Some(p.to_string_lossy().to_string());
                    settings.light_theme = Some(self.theme == Theme::Light);
                    save_settings(&settings);
                }
                self.mod_path = path;
            }

            Message::ToggleTextureOverride(v) => {
                self.enable_texture_override = v;
                if v { self.enable_stable_texture = false; }
            }
            Message::ToggleStableTexture(v) => {
                self.enable_stable_texture = v;
                if v { self.enable_texture_override = false; }
            }
            Message::SetAeroFixMode(mode) => {
                self.aero_fix_mode = mode;
            }

            Message::StartFix => {
                if let Some(ref path) = self.mod_path {
                    self.is_processing = true;
                    self.fix_just_completed = false;
                    self.files_processed = 0;
                    self.files_total = 0;
                    crate::reset_progress();

                    if !self.config_ready {
                        self.logs.push(tr(
                            "[WARN] 远程配置尚未加载完成，将使用本地配置",
                            "[WARN] Remote config not loaded yet, using local config",
                        ));
                    }

                    self.logs.push("─── START ───".to_string());

                    let (tx, rx) = std::sync::mpsc::channel::<String>();
                    self.log_rx = Some(Arc::new(Mutex::new(rx)));
                    crate::set_gui_log_sender(Some(tx));

                    let path = path.clone();
                    let enable_tex = self.enable_texture_override;
                    let enable_stable = self.enable_stable_texture;
                    let aero_mode = self.aero_fix_mode;

                    return Task::perform(
                        async move {
                            tokio::task::spawn_blocking(move || {
                                let characters = config_loader::characters();
                                let fixer = ModFixer::new(characters, enable_tex, enable_stable, true, aero_mode);

                                let mut opts = Vec::new();
                                if enable_tex { opts.push("TextureOverride"); }
                                if enable_stable { opts.push("StableTexture"); }
                                match aero_mode {
                                    1 => opts.push("AeroFix:TexCoord"),
                                    2 => opts.push("AeroFix:TextureMirror"),
                                    _ => {}
                                }
                                let opts_str = if opts.is_empty() { "default".to_string() } else { opts.join(", ") };
                                info!("Options: [{}]", opts_str);

                                match fixer.process_directory(&path) {
                                    Ok(_) => {
                                        info!("{}", tr("[OK] 修复完成!", "[OK] Fix completed!"));
                                    }
                                    Err(e) => {
                                        error!("[ERR] {}: {}", tr("修复出错", "Fix error"), e);
                                    }
                                }
                            })
                            .await
                            .ok();
                        },
                        |_| Message::FixFinished,
                    );
                }
            }
            Message::FixFinished => {
                if let Some(ref rx) = self.log_rx {
                    if let Ok(rx) = rx.lock() {
                        while let Ok(msg) = rx.try_recv() {
                            self.logs.push(msg);
                        }
                    }
                }
                self.is_processing = false;
                self.fix_just_completed = true;
                self.logs.push("─── DONE ───".to_string());
                crate::set_gui_log_sender(None);
                return snap_to(
                    LOG_SCROLL_ID.clone(),
                    scrollable::RelativeOffset { x: 0.0, y: 1.0 },
                );
            }

            Message::LogTick => {
                let mut new_msgs = false;
                if let Some(ref rx) = self.log_rx {
                    if let Ok(rx) = rx.lock() {
                        while let Ok(msg) = rx.try_recv() {
                            self.logs.push(msg);
                            new_msgs = true;
                        }
                    }
                }
                self.files_processed = crate::PROGRESS_CURRENT.load(std::sync::atomic::Ordering::Relaxed);
                self.files_total = crate::PROGRESS_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
                if self.logs.len() > MAX_LOG_LINES {
                    let drain_count = self.logs.len() - MAX_LOG_LINES;
                    self.logs.drain(0..drain_count);
                }
                if new_msgs {
                    return snap_to(
                        LOG_SCROLL_ID.clone(),
                        scrollable::RelativeOffset { x: 0.0, y: 1.0 },
                    );
                }
            }

            Message::SwitchView(view) => {
                self.current_view = view;
                if view == View::Rollback {
                    return self.refresh_backups_cmd();
                }
            }

            Message::RefreshBackups => {
                return self.refresh_backups_cmd();
            }
            Message::BackupsLoaded(groups) => {
                self.backup_groups = groups;
            }
            Message::ConfirmRollback(group_key) => {
                self.pending_rollback = Some(group_key);
            }
            Message::CancelRollback => {
                self.pending_rollback = None;
            }
            Message::ConfirmRestoreAll => {
                self.pending_rollback = Some("__RESTORE_ALL__".to_string());
            }
            Message::ExecuteRollback(group_key) => {
                self.pending_rollback = None;
                if let Some(ref path) = self.mod_path {
                    let dir = path.clone();
                    let actual_key = if group_key == "__RESTORE_ALL__" {
                        match self.backup_groups.last() {
                            Some(g) => g.group_key.clone(),
                            None => {
                                self.logs.push(tr("[WARN] 没有可回滚的备份", "[WARN] No backups to restore"));
                                return Task::none();
                            }
                        }
                    } else {
                        group_key.clone()
                    };
                    self.logs.push(format!(
                        "<< {} {} ...",
                        tr("正在回滚到", "Rolling back to"),
                        actual_key
                    ));
                    return Task::perform(
                        async move {
                            tokio::task::spawn_blocking(move || {
                                rollback::execute_rollback(&dir, &actual_key)
                                    .map_err(|e| e.to_string())
                            })
                            .await
                            .unwrap_or(Err("Task failed".to_string()))
                        },
                        Message::RollbackFinished,
                    );
                }
            }
            Message::RollbackFinished(result) => {
                match result {
                    Ok(_) => {
                        self.logs.push(tr("[OK] 回滚完成!", "[OK] Rollback completed!"));
                    }
                    Err(e) => {
                        self.logs.push(format!(
                            "[ERR] {}: {}",
                            tr("回滚失败", "Rollback failed"),
                            e
                        ));
                    }
                }
                return Task::batch([
                    self.refresh_backups_cmd(),
                    snap_to(LOG_SCROLL_ID.clone(), scrollable::RelativeOffset { x: 0.0, y: 1.0 })
                ]);
            }

            Message::RefreshConfig => {
                self.logs.push(tr(
                    "正在从远程获取最新配置...",
                    "Fetching latest config from remote...",
                ));
                return Task::batch([
                    Task::perform(
                        async {
                            match crate::config_loader::force_reload_remote_config().await {
                                Ok(_) => Ok(tr("[OK] 数据配置已最新", "[OK] Config updated")),
                                Err(e) => Err(format!("{:?}", e)),
                            }
                        },
                        Message::ConfigRefreshed,
                    ),
                    snap_to(LOG_SCROLL_ID.clone(), scrollable::RelativeOffset { x: 0.0, y: 1.0 })
                ]);
            }
            Message::ConfigRefreshed(result) => {
                match result {
                    Ok(msg) => { self.logs.push(msg); }
                    Err(e) => self.logs.push(format!(
                        "[ERR] {}: {}",
                        tr("配置刷新失败", "Config refresh failed"),
                        e
                    )),
                }
                return snap_to(
                    LOG_SCROLL_ID.clone(),
                    scrollable::RelativeOffset { x: 0.0, y: 1.0 },
                );
            }

            Message::StartupCheckDone(status) => {
                self.update_info = status;
                self.config_ready = true;
                let new_intro = vec![
                    tr("=================================", "================================="),
                    t!(intro).to_string(),
                    t!(intro_note).to_string(),
                    t!(compatibility_note).to_string(),
                    t!(graphics_setting_note).to_string(),
                    tr("=================================", "================================="),
                ];
                let new_end = new_intro.len();
                self.logs.splice(0..self.intro_end_index.min(self.logs.len()), new_intro);
                self.intro_end_index = new_end;
            }
            Message::OpenUpdateUrl => {
                match &self.update_info {
                    crate::config_loader::UpdateStatus::OptionalUpdate(_, url) => { let _ = open::that(url); },
                    crate::config_loader::UpdateStatus::MandatoryUpdate(_, url) => { let _ = open::that(url); },
                    _ => {}
                }
            }
            Message::ToggleDebugLogs(enabled) => {
                self.show_debug_logs = enabled;
                if enabled {
                    log::set_max_level(log::LevelFilter::Debug);
                    self.logs.push(tr("[INFO] 已启用调试日志", "[INFO] Debug logging enabled"));
                } else {
                    log::set_max_level(log::LevelFilter::Info);
                    self.logs.push(tr("[INFO] 已关闭调试日志", "[INFO] Debug logging disabled"));
                }
            }
            Message::ClearLogs => {
                self.logs.clear();
                self.logs.push(tr("日志已清空", "Logs cleared"));
            }
            Message::ExportLogs => {
                let export_start = self.intro_end_index.min(self.logs.len());
                let content = self.logs[export_start..].join("\n");
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let filename = format!("wwmi_fix_log_{}.txt", timestamp);
                let path = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.join(&filename)))
                    .unwrap_or_else(|| PathBuf::from(&filename));
                match std::fs::write(&path, &content) {
                    Ok(_) => self.logs.push(format!(
                        "[OK] {}: {}",
                        tr("日志已导出", "Logs exported to"),
                        path.display()
                    )),
                    Err(e) => self.logs.push(format!(
                        "[ERROR] {}: {}",
                        tr("导出失败", "Export failed"),
                        e
                    )),
                }
            }
            Message::ToggleTheme => {
                self.theme = if self.theme == Theme::Dark { Theme::Light } else { Theme::Dark };
                let mut settings = load_settings();
                settings.last_folder = self.mod_path.as_ref().map(|p| p.to_string_lossy().to_string());
                settings.light_theme = Some(self.theme == Theme::Light);
                save_settings(&settings);
            }
            Message::EventOccurred(event) => {
                match event {
                    iced::Event::Window(iced::window::Event::FileDropped(path)) => {
                        if path.is_dir() {
                            return Task::done(Message::FolderSelected(Some(path)));
                        }
                    }
                    iced::Event::Window(iced::window::Event::Resized(size)) => {
                        let mut settings = load_settings();
                        settings.window_width = Some(size.width);
                        settings.window_height = Some(size.height);
                        save_settings(&settings);
                    }
                    iced::Event::Window(iced::window::Event::Moved(point)) => {
                        if point.x.abs() < 10000.0 && point.y.abs() < 10000.0 {
                            let mut settings = load_settings();
                            settings.window_x = Some(point.x as i32);
                            settings.window_y = Some(point.y as i32);
                            save_settings(&settings);
                        }
                    }
                    _ => {}
                }
            }
            Message::OpenGithubUrl => {
                let _ = open::that("https://github.com/Moonholder/Wuwa_Mod_Fixer");
            }
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        if matches!(self.update_info, crate::config_loader::UpdateStatus::MandatoryUpdate(_, _)) {
            return self.view_mandatory_update();
        }

        let content: Element<Message> = match self.current_view {
            View::Main => self.view_main(),
            View::Rollback => self.view_rollback(),
        };

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(28)
            .style(main_container_style)
            .into()
    }

    fn subscription(&self) -> Subscription<Message> {
        let events = iced::event::listen().map(Message::EventOccurred);
        if self.is_processing {
            Subscription::batch([
                events,
                iced::time::every(std::time::Duration::from_millis(100)).map(|_| Message::LogTick)
            ])
        } else {
            events
        }
    }
}

// ---------------------------------------------------------------------------
// Style helpers
// ---------------------------------------------------------------------------
fn main_container_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(iced::Background::Color(get_surface(theme))),
        text_color: Some(get_text_color(theme)),
        border: iced::Border {
            radius: iced::border::Radius {
                top_left: 0.0,
                top_right: 0.0,
                bottom_right: 8.0,
                bottom_left: 8.0,
            },
            color: get_border_color(theme),
            width: 1.0,
        },
        ..Default::default()
    }
}

fn update_banner_style(theme: &Theme) -> container::Style {
    let bg = if theme == &Theme::Light {
        Color::from_rgb(1.0, 0.96, 0.88)
    } else {
        Color::from_rgb(0.25, 0.20, 0.10)
    };
    let border_color = if theme == &Theme::Light {
        Color::from_rgb(0.90, 0.75, 0.45)
    } else {
        Color::from_rgb(0.40, 0.30, 0.15)
    };
    
    container::Style {
        background: Some(iced::Background::Color(bg)),
        text_color: Some(get_text_color(theme)),
        border: iced::Border {
            radius: 10.0.into(),
            color: border_color,
            width: 1.0,
        },
        ..Default::default()
    }
}

fn inner_card_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(iced::Background::Color(get_surface_light(theme))),
        border: iced::Border {
            radius: 8.0.into(),
            color: get_border_color(theme),
            width: 1.0,
        },
        ..Default::default()
    }
}

fn log_container_style(theme: &Theme) -> container::Style {
    let bg = if theme == &Theme::Light {
        Color::from_rgba(0.05, 0.07, 0.1, 0.04)
    } else {
        Color::from_rgba(0.0, 0.0, 0.0, 0.25)
    };
    
    container::Style {
        background: Some(iced::Background::Color(bg)),
        border: iced::Border {
            radius: iced::border::Radius {
                top_left: 0.0,
                top_right: 0.0,
                bottom_right: 10.0,
                bottom_left: 10.0,
            },
            color: get_border_color(theme),
            width: 1.0,
        },
        ..Default::default()
    }
}

fn accent_button_style(color: Color, text_color: Color) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        let (bg, txt, border) = match status {
            button::Status::Hovered => (
                Color::from_rgb(
                    (color.r + 0.1).min(1.0),
                    (color.g + 0.1).min(1.0),
                    (color.b + 0.1).min(1.0),
                ),
                text_color,
                iced::Border { radius: 8.0.into(), ..Default::default() },
            ),
            button::Status::Pressed => (
                Color::from_rgb(
                    (color.r - 0.05).max(0.0),
                    (color.g - 0.05).max(0.0),
                    (color.b - 0.05).max(0.0),
                ),
                text_color,
                iced::Border { radius: 6.0.into(), ..Default::default() },
            ),
            button::Status::Disabled => (
                if theme == &Theme::Light { Color::from_rgb(0.9, 0.9, 0.92) } else { Color::from_rgb(0.22, 0.23, 0.26) },
                if theme == &Theme::Light { Color::from_rgb(0.6, 0.6, 0.6) } else { Color::from_rgb(0.45, 0.46, 0.50) },
                iced::Border { radius: 8.0.into(), ..Default::default() },
            ),
            _ => (
                color, 
                text_color,
                iced::Border { radius: 8.0.into(), ..Default::default() },
            ),
        };
        button::Style {
            background: Some(iced::Background::Color(bg)),
            text_color: txt,
            border,
            ..Default::default()
        }
    }
}

fn text_link_style(_theme: &Theme, status: iced::widget::button::Status) -> iced::widget::button::Style {
    iced::widget::button::Style {
        background: None,
        text_color: if status == iced::widget::button::Status::Hovered { Color::from_rgb(0.5, 0.8, 1.0) } else { ACCENT },
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Helper methods
// ---------------------------------------------------------------------------
impl WuwaModFixerApp {
    fn refresh_backups_cmd(&self) -> Task<Message> {
        if let Some(ref path) = self.mod_path {
            let dir = path.clone();
            Task::perform(
                async move {
                    tokio::task::spawn_blocking(move || {
                        rollback::scan_backups(&dir).unwrap_or_default()
                    })
                    .await
                    .unwrap_or_default()
                },
                Message::BackupsLoaded,
            )
        } else {
            Task::none()
        }
    }

    fn view_mandatory_update(&self) -> Element<'_, Message> {
        let title = text(tr("⚠️ 需要更新程序", "⚠️ Update Required"))
            .size(30)
            .color(DANGER);

        let msg = match &self.update_info {
            crate::config_loader::UpdateStatus::MandatoryUpdate(ver, _) => {
                format!("{}: v{}\n{}", tr("当前配置要求的最低版本", "Minimum required version"), ver, tr("点击下载最新版本以继续使用。", "Click download to continue using the tool."))
            },
            _ => String::new(),
        };

        let desc = text(msg).size(15).color(get_text_color(&self.theme));

        let download_btn = styled_button(tr("🚀 前往下载发版页面", "🚀 Go to Download Page"), ACCENT)
            .on_press(Message::OpenUpdateUrl);

        let content = column![title, desc, download_btn]
            .spacing(24)
            .align_x(Alignment::Center);

        container(content)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .padding(40)
            .style(main_container_style)
            .into()
    }

    fn view_main(&self) -> Element<'_, Message> {
        let config_ver = config_loader::version().current_version.as_str();
        let version_text = text(format!("{}  v{}   |   {} v{}   |   ", tr("WWMI模组修复工具", "WWMI Mod Fix Tool"), env!("CARGO_PKG_VERSION"), tr("配置版本", "Config"), config_ver))
            .size(14)
            .color(get_text_dim(&self.theme))
            .font(Font::DEFAULT);

        let author_link = button(text("by Moonholder").size(14).font(Font { weight: Weight::Bold, ..Font::DEFAULT }))
            .padding(0)
            .style(text_link_style)
            .on_press(Message::OpenGithubUrl);

        let header = row![version_text, author_link].align_y(Alignment::Center);

        // Folder selection
        let path_text = self.mod_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| tr("未选择文件夹", "No folder selected"));

        let path_label = text(path_text)
            .size(14)
            .color(if self.mod_path.is_some() { get_text_color(&self.theme) } else { get_text_dim(&self.theme) });

        let select_btn = styled_button(
            tr("[+] 选择 Mod 文件夹", "[+] Select Mod Folder"),
            ACCENT,
        )
        .on_press(Message::SelectFolder);

        let folder_inner = container(
            row![select_btn, path_label].spacing(16).align_y(Alignment::Center)
        )
        .padding(16)
        .width(Length::Fill)
        .style(inner_card_style);

        let folder_section = column![
            text(tr("-- 目标文件夹 --", "-- Target Folder --"))
                .size(13).color(get_text_dim(&self.theme)).font(Font { weight: Weight::Bold, ..Font::DEFAULT }),
            folder_inner,
        ]
        .spacing(8);

        // Settings
        let tex_cb = checkbox(self.enable_texture_override)
            .label(tr("添加派生Hash", "Add Derived Hashes"))
            .on_toggle(Message::ToggleTextureOverride)
            .size(16);
        let tex_desc = text(tr(
            "    为模组添加派生Hash，使角色模组贴图能在不添加 UseAllMips 的情况下在画面细节高/中下正常显示 (部分角色未更新)",
            "    Add derived hashes to the mod to allow character mods textures to display normally on High/Medium LOD Bias settings without adding UseAllMips (some characters not updated)",
        ))
        .size(11).color(get_text_dim(&self.theme));

        let stable_cb = checkbox(self.enable_stable_texture)
            .label(tr("应用稳定纹理", "Stable Texture"))
            .on_toggle(Message::ToggleStableTexture)
            .size(16);
        let stable_desc = text(tr(
            "    使用 RabbitFX 为角色设置稳定纹理 (目前仅坎特蕾拉、千咲、卡提、夏空...)，需安装最新的RabbitFX",
            "    Use RabbitFX to set stable textures for characters (currently Cantarella, Chisa, Cartethyia, Ciaccona...). Requires latest RabbitFX",
        ))
        .size(11).color(get_text_dim(&self.theme));

        let aero_enabled = self.aero_fix_mode > 0;
        let aero_cb = checkbox(aero_enabled)
            .label(tr(
                "女漂-风主形态眼部修复",
                "Aero FemaleRover Eye Fix (eyes glitch when resonance energy is full)",
            ))
            .on_toggle(move |checked| {
                if checked { Message::SetAeroFixMode(1) } else { Message::SetAeroFixMode(0) }
            })
            .size(18);

        let mut settings_col = column![
            tex_cb, tex_desc,
            Space::new().height(4),
            stable_cb, stable_desc,
            Space::new().height(4),
            rule::horizontal(1),
            Space::new().height(4),
            aero_cb,
        ]
        .spacing(6);

        if aero_enabled {
            let aero_warn = text(tr(
                "  [!] 确保你的 mod 存在此问题，否则不要开启!",
                "  [!] Make sure your mod has this problem, otherwise don't enable!",
            )).size(11).color(DANGER);

            let aero_texcoord = radio(
                tr("TexCoord 覆盖", "TexCoord Override"),
                1u8, Some(self.aero_fix_mode), Message::SetAeroFixMode,
            ).size(14);

            let aero_mirror = radio(
                tr("贴图镜像反转", "Texture Mirror Flip"),
                2u8, Some(self.aero_fix_mode), Message::SetAeroFixMode,
            ).size(14);

            let aero_tip = text(tr(
                "  如果一种方式修复后仍有问题，请先回滚再换另一种方式尝试",
                "  If one method still has issues, rollback first then try the other",
            )).size(11).color(get_text_dim(&self.theme));

            settings_col = settings_col
                .push(aero_warn)
                .push(row![aero_texcoord, aero_mirror].spacing(16))
                .push(aero_tip);
        }

        let settings_inner = container(settings_col)
            .padding(16)
            .width(Length::Fill)
            .style(inner_card_style);

        let settings_section = column![
            text(tr("-- 修复选项 --", "-- Fix Options --"))
                .size(13).color(get_text_dim(&self.theme)).font(Font { weight: Weight::Bold, ..Font::DEFAULT }),
            settings_inner,
        ].spacing(8);

        // Action buttons
        let (fix_label, fix_color) = if self.is_processing {
            if self.files_total > 0 {
                (format!("[...] {} ({}/{})", tr("修复中", "Fixing"), self.files_processed, self.files_total), ACCENT)
            } else {
                (tr("[...] 修复中", "[...] Fixing..."), ACCENT)
            }
        } else if self.fix_just_completed {
            (tr("[OK] 修复完成", "[OK] Fix Done!"), SUCCESS)
        } else {
            (tr("[>] 一键修复", "[>] Fix Mod"), SUCCESS)
        };

        let mut fix_btn = styled_button(fix_label, fix_color);
        if self.mod_path.is_some() && !self.is_processing {
            fix_btn = fix_btn.on_press(Message::StartFix);
        }

        let rollback_btn = styled_button(tr("[<<] 回滚管理", "[<<] Rollback"), ACCENT_DARK)
            .on_press(Message::SwitchView(View::Rollback));

        let actions = row![fix_btn, rollback_btn].spacing(10);

        // Bottom toolbar
        let theme_btn = mini_button(if self.theme == Theme::Light { "🌙".to_string() } else { "☀️".to_string() }, &self.theme)
            .on_press(Message::ToggleTheme);
        let config_btn = mini_button(tr("刷新数据配置", "Refresh Config Data"), &self.theme)
            .on_press(Message::RefreshConfig);
        let debug_cb = checkbox(self.show_debug_logs)
            .label(tr("调试日志", "Debug Logs"))
            .on_toggle(Message::ToggleDebugLogs)
            .size(14)
            .text_size(11);
        let clear_btn = mini_button(tr("清空日志", "Clear Logs"), &self.theme)
            .on_press(Message::ClearLogs);
        let export_btn = mini_button(tr("导出日志", "Export Logs"), &self.theme)
            .on_press(Message::ExportLogs);

        let toolbar = row![theme_btn, config_btn, Space::new().width(Length::Fill), export_btn, clear_btn, debug_cb]
            .spacing(8).align_y(Alignment::Center);

        // Log area
        let log_label = text(tr("-- 日志 --", "-- Log --")).size(12).color(get_text_dim(&self.theme));
        let log_content = self.build_log_view();

        let mut main_col = column![header].spacing(10);

        // Update banner
        if let crate::config_loader::UpdateStatus::OptionalUpdate(ref new_ver, _) = self.update_info {
            let banner_text = text(format!(
                "{}  v{}", tr("🎉 发现新版本", "🎉 New version available"), new_ver,
            )).size(14).font(Font { weight: Weight::Bold, ..Font::DEFAULT }).color(get_text_color(&self.theme));

            let download_btn = styled_button(
                tr("🚀 前往下载", "🚀 Download"),
                Color::from_rgb(0.85, 0.55, 0.15),
            ).on_press(Message::OpenUpdateUrl);

            let banner = container(
                row![banner_text, Space::new().width(Length::Fill), download_btn]
                    .spacing(12).align_y(Alignment::Center),
            )
            .padding([8, 14])
            .width(Length::Fill)
            .style(update_banner_style);

            main_col = main_col.push(banner);
        }

        main_col = main_col
            .push(rule::horizontal(1))
            .push(folder_section)
            .push(settings_section)
            .push(actions)
            .push(rule::horizontal(1))
            .push(toolbar)
            .push(log_label)
            .push(log_content);

        main_col.into()
    }

    fn view_rollback(&self) -> Element<'_, Message> {
        let title = text(tr("⏪ 回滚管理器", "⏪ Rollback Manager"))
            .size(28)
            .font(Font { weight: Weight::Bold, ..Font::DEFAULT });
        let back_btn = styled_button_with_text(tr("< 返回", "< Back"), get_surface_light(&self.theme), get_text_color(&self.theme))
            .on_press(Message::SwitchView(View::Main));
        let header = row![title, Space::new().width(Length::Fill), back_btn].align_y(Alignment::Center);

        if self.mod_path.is_none() {
            return column![
                header,
                rule::horizontal(1),
                text(tr("请先在主页选择 Mod 文件夹", "Please select a Mod folder first")).size(16),
            ].spacing(20).into();
        }

        let mut items = Column::new().spacing(6);

        if self.backup_groups.is_empty() {
            items = items.push(
                text(tr("当前目录下没有找到备份文件 (.BAK)", "No backup files (.BAK) found"))
                    .size(13).color(get_text_dim(&self.theme)),
            );
        } else {
            let base = self.mod_path.as_deref().unwrap_or(std::path::Path::new(""));

            for (idx, group) in self.backup_groups.iter().enumerate() {
                let display_time = if group.group_key.len() >= 16 {
                    let mut s = group.group_key.clone();
                    s.replace_range(13..14, ":");
                    s
                } else {
                    group.group_key.clone()
                };

                let mut by_dir: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
                for f in &group.files {
                    let rel = f.original_path.strip_prefix(base).unwrap_or(&f.original_path);
                    let parent = rel.parent()
                        .map(|p| { let s = p.to_string_lossy().to_string(); if s.is_empty() { ".".to_string() } else { s } })
                        .unwrap_or_else(|| ".".to_string());
                    let fname = rel.file_name().unwrap_or_default().to_string_lossy().to_string();
                    by_dir.entry(parent).or_default().push(fname);
                }

                let header_text = text(format!("[{}]  {} {}", display_time, group.files.len(), tr("个文件", "file(s)")))
                    .size(13).color(get_text_color(&self.theme)).font(Font { weight: Weight::Bold, ..Font::DEFAULT });

                let mut detail_col = Column::new().spacing(1);
                for (dir, files) in &by_dir {
                    detail_col = detail_col.push(
                        text(format!("  {}/  {}", dir, files.join(", ")))
                            .size(11).color(get_text_dim(&self.theme)),
                    );
                }

                let is_pending = self.pending_rollback.as_deref() == Some(&group.group_key);

                let action_row = if is_pending {
                    let newer_count = idx;
                    let mut scope_parts = vec![
                        tr("将恢复这些文件到修复前的状态", "Will restore these files to pre-fix state"),
                    ];
                    if newer_count > 0 {
                        scope_parts.push(format!("+ {} {}", newer_count,
                            tr("组更新的备份也将被清理", "newer backup group(s) will also be cleaned up")));
                    }
                    let scope_warning = text(scope_parts.join("\n"))
                        .size(11).color(Color::from_rgb(0.95, 0.75, 0.30));

                    let confirm_btn = styled_button(tr("确认回滚", "Confirm"), DANGER)
                        .on_press(Message::ExecuteRollback(group.group_key.clone()));
                    let cancel_btn = mini_button(tr("取消", "Cancel"), &self.theme)
                        .on_press(Message::CancelRollback);

                    column![
                        row![header_text, Space::new().width(Length::Fill), confirm_btn, cancel_btn].spacing(8).align_y(Alignment::Center),
                        detail_col,
                        scope_warning,
                    ].spacing(4)
                } else {
                    let restore_btn = mini_button(tr("恢复", "Restore"), &self.theme)
                        .on_press(Message::ConfirmRollback(group.group_key.clone()));
                    column![
                        row![header_text, Space::new().width(Length::Fill), restore_btn].spacing(8).align_y(Alignment::Center),
                        detail_col,
                    ].spacing(4)
                };

                items = items.push(
                    container(action_row)
                        .padding([12, 16])
                        .width(Length::Fill)
                        .style(inner_card_style),
                );
            }
        }

        let refresh_btn = styled_button_with_text(tr("🔄 刷新", "🔄 Refresh"), get_surface_light(&self.theme), get_text_color(&self.theme))
            .on_press(Message::RefreshBackups);

        let is_restore_all_pending = self.pending_rollback.as_deref() == Some("__RESTORE_ALL__");
        let restore_all_section: Element<Message> = if self.backup_groups.is_empty() {
            Space::new().height(0).into()
        } else if is_restore_all_pending {
            let total_files: usize = self.backup_groups.iter().map(|g| g.files.len()).sum();
            let warning = text(format!(
                "{} {} {} {} {}",
                tr("将还原所有文件到最早的备份状态，并删除全部", "Restore all files to earliest backup and delete all"),
                total_files,
                tr("个 .BAK 文件 (", "BAK files ("),
                self.backup_groups.len(),
                tr("组)", "group(s))"),
            )).size(12).color(Color::from_rgb(0.95, 0.75, 0.30));
            let confirm_btn = styled_button(tr("确认全部还原", "Confirm Restore All"), DANGER)
                .on_press(Message::ExecuteRollback("__RESTORE_ALL__".to_string()));
            let cancel_btn = mini_button(tr("取消", "Cancel"), &self.theme)
                .on_press(Message::CancelRollback);
            column![warning, row![confirm_btn, cancel_btn].spacing(8)].spacing(6).into()
        } else {
            styled_button(tr("🚨 全部还原", "🚨 Restore All"), DANGER)
                .on_press(Message::ConfirmRestoreAll).into()
        };

        let toolbar = row![refresh_btn, Space::new().width(Length::Fill), restore_all_section]
            .spacing(8).align_y(Alignment::Center);

        let log_content = self.build_log_view();

        column![
            header,
            rule::horizontal(1),
            toolbar,
            scrollable(items).height(Length::FillPortion(2)),
            rule::horizontal(1),
            text(tr("-- 日志 --", "-- Log --")).size(12).color(get_text_dim(&self.theme)),
            log_content,
        ].spacing(8).into()
    }

    fn build_log_view(&self) -> Element<'_, Message> {
        let log_lines: Vec<Element<Message>> = self.logs.iter().map(|l| {
            let color = if l.contains("[OK]") || l.contains("✅") {
                SUCCESS
            } else if l.contains("[INFO]") || l.starts_with("[*]") {
                ACCENT
            } else if l.contains("[ERR]") || l.contains("[ERROR]") || l.contains("❌") {
                DANGER
            } else if l.contains("[WARN]") || l.contains("⚠️") {
                Color::from_rgb(0.95, 0.75, 0.30)
            } else if l.contains("[DEBUG]") {
                Color::from_rgb(0.50, 0.52, 0.56)
            } else if l.starts_with("───") || l.starts_with("─") {
                get_text_dim(&self.theme)
            } else {
                get_text_color(&self.theme)
            };
            
            text(l)
                .size(12)
                .color(color)
                .font(Font::DEFAULT)
                .into()
        }).collect();

        container(
            scrollable(Column::with_children(log_lines).spacing(4))
                .id(LOG_SCROLL_ID.clone())
                .width(Length::Fill)
        )
        .padding(iced::Padding { top: 12.0, right: 6.0, bottom: 12.0, left: 12.0 })
        .style(log_container_style)
        .height(Length::FillPortion(3))
        .width(Length::Fill)
        .into()
    }
}

// ---------------------------------------------------------------------------
// Styled button helpers
// ---------------------------------------------------------------------------
fn styled_button(label: String, color: Color) -> iced::widget::Button<'static, Message> {
    button(text(label).size(14))
        .padding([8, 18])
        .style(accent_button_style(color, Color::WHITE))
}

fn styled_button_with_text(label: String, color: Color, txt_color: Color) -> iced::widget::Button<'static, Message> {
    button(text(label).size(14))
        .padding([8, 18])
        .style(accent_button_style(color, txt_color))
}

fn mini_button<'a>(label: String, theme: &Theme) -> iced::widget::Button<'a, Message> {
    button(text(label).size(12))
        .padding([4, 10])
        .style(accent_button_style(get_surface_light(theme), get_text_color(theme)))
}
