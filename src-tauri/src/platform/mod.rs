// src-tauri/src/platform/mod.rs

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(not(target_os = "windows"))]
pub fn detach_console() {}

#[cfg(not(target_os = "windows"))]
pub fn show_fatal_dialog(title: &str, body: &str) {
    eprintln!("[FATAL] {title}: {body}");
}

#[cfg(not(target_os = "windows"))]
pub fn ask_yes_no(title: &str, message: &str) -> bool {
    eprintln!("[{title}] {message}");
    false
}

#[cfg(not(target_os = "windows"))]
pub fn check_single_instance() -> bool {
    true
}

#[cfg(not(target_os = "windows"))]
pub fn cleanup_single_instance() {}

#[cfg(not(target_os = "windows"))]
pub fn alloc_console_and_redirect() {}

#[cfg(not(target_os = "windows"))]
pub fn install_seh_handler(_: unsafe extern "system" fn(*mut std::ffi::c_void) -> i32) {}

#[cfg(not(target_os = "windows"))]
pub fn is_webview2_installed() -> bool {
    true
}
