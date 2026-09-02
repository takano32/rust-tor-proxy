//! Minimal leveled logging on top of `eprintln!`.
//!
//! Controlled by the `TOR_LOG` environment variable
//! (`error` | `warn` | `info` | `debug` | `trace`, default `info`).

use std::sync::atomic::{AtomicU8, Ordering};

pub const ERROR: u8 = 0;
pub const WARN: u8 = 1;
pub const INFO: u8 = 2;
pub const DEBUG: u8 = 3;
pub const TRACE: u8 = 4;

static LEVEL: AtomicU8 = AtomicU8::new(INFO);

pub fn init() {
    let level = match std::env::var("TOR_LOG")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "error" => ERROR,
        "warn" | "warning" => WARN,
        "" | "info" => INFO,
        "debug" => DEBUG,
        "trace" => TRACE,
        other => {
            eprintln!("[warn] unknown TOR_LOG value {other:?}, using \"info\"");
            INFO
        }
    };
    LEVEL.store(level, Ordering::Relaxed);
}

pub fn enabled(level: u8) -> bool {
    level <= LEVEL.load(Ordering::Relaxed)
}

#[macro_export]
macro_rules! log_at {
    ($level:expr, $tag:literal, $($arg:tt)*) => {
        if $crate::log::enabled($level) {
            eprintln!("[{}] {}", $tag, format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => { $crate::log_at!($crate::log::ERROR, "error", $($arg)*) };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => { $crate::log_at!($crate::log::WARN, "warn", $($arg)*) };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::log_at!($crate::log::INFO, "info", $($arg)*) };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => { $crate::log_at!($crate::log::DEBUG, "debug", $($arg)*) };
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => { $crate::log_at!($crate::log::TRACE, "trace", $($arg)*) };
}
