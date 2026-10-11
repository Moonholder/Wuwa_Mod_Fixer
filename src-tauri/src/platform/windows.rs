// src-tauri/src/platform/windows.rs
#![cfg(target_os = "windows")]

use std::{ffi::OsStr, os::windows::ffi::OsStrExt, sync::Mutex};

use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, GetLastError},
    Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
    System::{
        Console::{AllocConsole, FreeConsole, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle},
        Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW, RegQueryValueExW},
        Threading::CreateMutexW,
    },
};

static SINGLE_INSTANCE_MUTEX: Mutex<Option<usize>> = Mutex::new(None);

unsafe extern "system" {
    fn MessageBoxW(h: *mut std::ffi::c_void, text: *const u16, cap: *const u16, ty: u32) -> i32;
    fn SetUnhandledExceptionFilter(
        h: Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> i32>,
    ) -> Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> i32>;
}

unsafe extern "C" {
    fn freopen(path: *const u8, mode: *const u8, stream: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    fn __acrt_iob_func(index: u32) -> *mut std::ffi::c_void;
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain([0]).collect()
}

pub fn detach_console() {
    unsafe {
        FreeConsole();
    }
}

pub fn show_fatal_dialog(title: &str, body: &str) {
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide(body).as_ptr(),
            wide(title).as_ptr(),
            0x10, // MB_ICONERROR
        );
    }
}

pub fn ask_yes_no(title: &str, message: &str) -> bool {
    let result = unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide(message).as_ptr(),
            wide(title).as_ptr(),
            0x34, // MB_YESNO | MB_ICONWARNING
        )
    };
    result == 6 // IDYES
}

pub fn check_single_instance() -> bool {
    let mutex_name: Vec<u16> = wide("Local\\WuwaModFixerSingleInstanceMutex");

    unsafe {
        let handle = CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr());
        if handle.is_null() {
            return true;
        }
        let err = GetLastError();
        if err == ERROR_ALREADY_EXISTS {
            return false;
        }
        if let Ok(mut guard) = SINGLE_INSTANCE_MUTEX.lock() {
            *guard = Some(handle as usize);
        }
    }
    true
}

pub fn cleanup_single_instance() {
    if let Ok(mut guard) = SINGLE_INSTANCE_MUTEX.lock() {
        if let Some(handle) = guard.take() {
            unsafe {
                CloseHandle(handle as *mut std::ffi::c_void);
            }
        }
    }
}

pub fn alloc_console_and_redirect() {
    unsafe {
        if AllocConsole() != 0 {
            freopen(b"CONIN$\0".as_ptr(), b"r\0".as_ptr(), __acrt_iob_func(0));
            freopen(b"CONOUT$\0".as_ptr(), b"w\0".as_ptr(), __acrt_iob_func(1));
            freopen(b"CONOUT$\0".as_ptr(), b"w\0".as_ptr(), __acrt_iob_func(2));

            let conout_name = wide("CONOUT$");
            let conin_name = wide("CONIN$");

            let generic_read_write = 0x80000000 | 0x40000000;
            let h_out = CreateFileW(
                conout_name.as_ptr(),
                generic_read_write,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
            let h_in = CreateFileW(
                conin_name.as_ptr(),
                generic_read_write,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );

            SetStdHandle(STD_OUTPUT_HANDLE, h_out);
            SetStdHandle(STD_ERROR_HANDLE, h_out);
            SetStdHandle(STD_INPUT_HANDLE, h_in);
        }
    }
}

pub fn install_seh_handler(crash_callback: unsafe extern "system" fn(*mut std::ffi::c_void) -> i32) {
    unsafe {
        SetUnhandledExceptionFilter(Some(crash_callback));
    }
}

pub fn is_webview2_installed() -> bool {
    let subkeys = [
        r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
        r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
    ];

    let value_name = wide("pv");

    // Check HKEY_LOCAL_MACHINE
    for subkey in &subkeys {
        let wide_subkey = wide(subkey);
        let mut hkey = std::ptr::null_mut();
        let res = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide_subkey.as_ptr(), 0, KEY_READ, &mut hkey) };
        if res == ERROR_SUCCESS {
            let mut val_type = 0;
            let mut cb_data = 0;
            let val_res = unsafe {
                RegQueryValueExW(
                    hkey,
                    value_name.as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    std::ptr::null_mut(),
                    &mut cb_data,
                )
            };
            unsafe { RegCloseKey(hkey) };
            if val_res == ERROR_SUCCESS && cb_data > 0 {
                return true;
            }
        }
    }

    // Check HKEY_CURRENT_USER
    let cu_subkey = r"Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    let wide_subkey = wide(cu_subkey);
    let mut hkey = std::ptr::null_mut();
    let res = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, wide_subkey.as_ptr(), 0, KEY_READ, &mut hkey) };
    if res == ERROR_SUCCESS {
        let mut val_type = 0;
        let mut cb_data = 0;
        let val_res = unsafe {
            RegQueryValueExW(
                hkey,
                value_name.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type,
                std::ptr::null_mut(),
                &mut cb_data,
            )
        };
        unsafe { RegCloseKey(hkey) };
        if val_res == ERROR_SUCCESS && cb_data > 0 {
            return true;
        }
    }

    false
}
