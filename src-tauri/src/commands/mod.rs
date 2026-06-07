pub mod fix;
pub mod rollback;
pub mod config;
pub mod settings;
pub mod updater;
pub mod shell;

pub fn generate_handlers() -> impl Fn(tauri::ipc::Invoke) -> bool {
    tauri::generate_handler![
        // Fix operations
        fix::start_fix,
        fix::cancel_fix,
        // Rollback
        rollback::scan_backups,
        rollback::do_rollback,
        rollback::get_backup_size,
        rollback::clean_backups,
        // Config & locale
        config::refresh_config,
        config::reload_remote_config,

        config::get_config_meta,
        config::get_intro_logs,
        config::get_update_status,
        config::get_detected_locale,
        config::is_chinese_mainland,
        // User settings
        settings::get_settings,
        settings::save_settings,
        // Updater
        updater::check_update,
        updater::download_and_apply_update,
        // Shell / filesystem
        shell::export_logs,
        shell::pick_folder,
        shell::open_url,
    ]
}