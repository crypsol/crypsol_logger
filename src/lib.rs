#[macro_use]
pub mod logs;
pub use log::Level;
/*
 * This file provides two macros for logging:
 * 1) `log!` for standard usage (maps to a log level and auto-selects a log stream).
 * 2) `log_custom!` for specifying a custom log stream name.
 *
 * Both macros support sending logs to CloudWatch asynchronously if the "LOG_TO_CLOUDWATCH"
 * environment variable is set to "true". Otherwise, they print logs to the console.
 */

/// A macro for logging a message with a given log::Level. If `LOG_TO_CLOUDWATCH` is "true",
/// it sends the log to CloudWatch asynchronously. Otherwise, it logs to the console.
///
/// # Usage
/// ```ignore
/// log!(Level::Info, "Hello from the log!");
/// ```
#[macro_export]
macro_rules! log {
    ($level:expr, $($arg:tt)+) => {{
        if $crate::logs::is_log_to_cloudwatch_enabled() {
            let message_str = format!($($arg)+);
            let log_stream = $crate::logs::LogStream::from_level(&$level);

            // Spawn the logging in an async task to avoid blocking
            tokio::spawn(async move {
                let _ = $crate::logs::custom_cloudwatch_log(
                    $level,
                    &message_str,
                    log_stream,
                    file!(),
                    line!()
                ).await;
            });
        } else {
            // Fallback to console logging if CloudWatch logging is disabled
            match $level {
                log::Level::Error => println!("ERROR: {}", format!($($arg)+)),
                log::Level::Warn  => println!("WARN: {}",  format!($($arg)+)),
                log::Level::Info  => println!("INFO: {}",  format!($($arg)+)),
                log::Level::Debug => println!("DEBUG: {}", format!($($arg)+)),
                log::Level::Trace => println!("TRACE: {}", format!($($arg)+)),
            }
        }
    }};
}

/// A macro for logging a message with a custom log stream name. If `LOG_TO_CLOUDWATCH` is "true",
/// it sends the log to CloudWatch asynchronously under the specified custom stream. Otherwise,
/// it prints logs to the console.
///
/// # Usage
/// ```ignore
/// log_custom!(Level::Info, "MyCustomStream", "Hello from a custom stream!");
/// ```
#[macro_export]
macro_rules! log_custom {
    ($level:expr, $log_stream:expr, $($arg:tt)+) => {{
        let log_to_cloudwatch = std::env::var("LOG_TO_CLOUDWATCH")
            .unwrap_or_else(|_| "true".to_string()) == "true";

        if log_to_cloudwatch {
            let message_str = format!($($arg)+);
            let stream = $crate::logs::LogStream::Custom($log_stream.to_string());
            tokio::spawn(async move {
                let _ = $crate::logs::custom_cloudwatch_log(
                    $level,
                    &message_str,
                    stream,
                    file!(),
                    line!()
                ).await;
            });
        } else {
            // Console fallback
            match $level {
                log::Level::Error => println!("{} ::ERROR: {}", $log_stream, format!($($arg)+)),
                log::Level::Warn  => println!("{} ::WARN: {}",  $log_stream, format!($($arg)+)),
                log::Level::Info  => println!("{} ::INFO: {}",  $log_stream, format!($($arg)+)),
                log::Level::Debug => println!("{} ::DEBUG: {}", $log_stream, format!($($arg)+)),
                log::Level::Trace => println!("{} ::TRACE: {}", $log_stream, format!($($arg)+)),
            }
        }
    }};
}
