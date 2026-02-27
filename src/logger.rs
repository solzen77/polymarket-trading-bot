//! Consistent, user-friendly log style: [HH:MM:SS] LEVEL  message
//! All output goes to stderr and history file via crate::log_to_history.

use chrono::Local;

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub enum Level {
    Info,
    Ok,
    Warn,
    Error,
    Action,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Level::Info => "INFO ",
            Level::Ok => "OK   ",
            Level::Warn => "WARN ",
            Level::Error => "ERROR",
            Level::Action => "-->  ",
        }
    }
}

fn timestamp() -> String {
    Local::now().format("%H:%M:%S").to_string()
}

/// Emit one line: [HH:MM:SS] LEVEL  message. Writes to stderr + history file.
#[doc(hidden)]
pub fn emit(level: Level, message: &str) {
    let line = format!("[{}] [{}]  {}\n", timestamp(), level.tag(), message);
    crate::log_to_history(&line);
}

/// Log an informational message.
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { $crate::logger::emit($crate::logger::Level::Info, &format!($($arg)*)) };
}

/// Log a success / positive outcome.
#[macro_export]
macro_rules! log_ok {
    ($($arg:tt)*) => { $crate::logger::emit($crate::logger::Level::Ok, &format!($($arg)*)) };
}

/// Log a warning.
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { $crate::logger::emit($crate::logger::Level::Warn, &format!($($arg)*)) };
}

/// Log an error (non-fatal; for fatal use Result/panic).
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { $crate::logger::emit($crate::logger::Level::Error, &format!($($arg)*)) };
}

/// Log an action in progress (e.g. placing order, refreshing).
#[macro_export]
macro_rules! log_action {
    ($($arg:tt)*) => { $crate::logger::emit($crate::logger::Level::Action, &format!($($arg)*)) };
}
