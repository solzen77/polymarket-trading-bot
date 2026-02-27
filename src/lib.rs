pub mod api;
pub mod clob_sdk_ffi;
pub mod config;
pub mod detector;
pub mod merge;
pub mod models;
pub mod monitor;
pub mod simulation;
pub mod trader;
pub mod logger;

// Re-export commonly used types
pub use api::PolymarketApi;
pub use config::Config;
pub use models::TokenPrice;

// Global file writer for history.toml (initialized by main.rs)
use std::sync::{Mutex, OnceLock};
use std::fs::File;
use std::io::Write;
use chrono::Local;

static HISTORY_FILE: OnceLock<Mutex<File>> = OnceLock::new();

/// Initialize the global history file writer (called by main.rs)
pub fn init_history_file(file: File) {
    HISTORY_FILE.set(Mutex::new(file)).expect("History file already initialized");
}

// Logging functions - modules will use these
pub fn log_to_history(message: &str) {
    // Write to stderr
    eprint!("{}", message);
    use std::io::Write;
    let _ = std::io::stderr().flush();
    
    // Write to history file if initialized
    if let Some(file_mutex) = HISTORY_FILE.get() {
        if let Ok(mut file) = file_mutex.lock() {
            let _ = write!(file, "{}", message);
            let _ = file.flush();
        }
    }
}

/// Write a trading event to history with [HH:MM:SS] [EVENT] prefix (same style as logger).
pub fn log_trading_event(event: &str) {
    let ts = Local::now().format("%H:%M:%S");
    log_to_history(&format!("[{}] [EVENT]  {}\n", ts, event));
}

/// Legacy log line; uses same [TIME] [INFO] style as log_info!
#[macro_export]
macro_rules! log_println {
    ($($arg:tt)*) => {
        $crate::log_info!($($arg)*)
    };
}
