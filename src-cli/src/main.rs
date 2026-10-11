// src-cli/src/main.rs
// Standalone pure CLI executable entry point. Zero GUI dependencies.

struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("[{}] {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: StderrLogger = StderrLogger;

#[cfg(target_os = "windows")]
fn init_windows_console() {
    unsafe {
        // Set console output code page to UTF-8 (65001)
        windows_sys::Win32::System::Console::SetConsoleOutputCP(65001);
        windows_sys::Win32::System::Console::SetConsoleCP(65001);

        // Enable Virtual Terminal Processing for ANSI escape codes
        let handle =
            windows_sys::Win32::System::Console::GetStdHandle(windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE);
        let mut mode: u32 = 0;
        if windows_sys::Win32::System::Console::GetConsoleMode(handle, &mut mode) != 0 {
            mode |= windows_sys::Win32::System::Console::ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            windows_sys::Win32::System::Console::SetConsoleMode(handle, mode);
        }
    }
}

fn main() {
    #[cfg(target_os = "windows")]
    init_windows_console();

    let args = wuwa_mod_cli::parse_args();
    let is_dev = cfg!(feature = "test-build") || cfg!(debug_assertions);

    let max_level = if is_dev {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    log::set_logger(&LOGGER).map(|()| log::set_max_level(max_level)).ok();

    wuwa_mod_cli::run(args, is_dev);
}
