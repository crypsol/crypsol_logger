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
                if let Err(e) = $crate::logs::custom_cloudwatch_log(
                    $level,
                    &message_str,
                    log_stream,
                    file!(),
                    line!()
                ).await {
                    let err_msg = format!("CloudWatch logging failed: {:?}", e);
                    if $crate::logs::is_log_to_file_enabled() {
                        let _ = $crate::logs::write_log_to_file(
                            $crate::Level::Error,
                            &err_msg,
                            $crate::logs::LogStream::ServerErrorResponses,
                            file!(),
                            line!()
                        ).await;
                    }
                    eprintln!("{err_msg}");
                }
            });
        } else if $crate::logs::is_log_to_file_enabled() {
            let message_str = format!($($arg)+);
            let log_stream = $crate::logs::LogStream::from_level(&$level);
            tokio::spawn(async move {
                let _ = $crate::logs::write_log_to_file(
                    $level,
                    &message_str,
                    log_stream,
                    file!(),
                    line!()
                ).await;
            });
        } else {
            // Fallback to console logging if other logging is disabled
            let ts = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f");
            let lvl_col = $crate::logs::colored_level($level);
            if $crate::logs::is_log_location_enabled() {
                println!(
                    "[{ts}] {lvl_col} - {} (File: {}, Line: {})",
                    format!($($arg)+),
                    file!(),
                    line!()
                );
            } else {
                println!(
                    "[{ts}] {lvl_col} - {}",
                    format!($($arg)+)
                );
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
        if $crate::logs::is_log_to_cloudwatch_enabled() {
            let message_str = format!($($arg)+);
            let stream = $crate::logs::LogStream::Custom($log_stream.to_string());
            tokio::spawn(async move {
                if let Err(e) = $crate::logs::custom_cloudwatch_log(
                    $level,
                    &message_str,
                    stream,
                    file!(),
                    line!()
                ).await {
                    let err_msg = format!("CloudWatch logging failed: {:?}", e);
                    if $crate::logs::is_log_to_file_enabled() {
                        let _ = $crate::logs::write_log_to_file(
                            $crate::Level::Error,
                            &err_msg,
                            $crate::logs::LogStream::ServerErrorResponses,
                            file!(),
                            line!()
                        ).await;
                    }
                    eprintln!("{err_msg}");
                }
            });
        } else if $crate::logs::is_log_to_file_enabled() {
            let message_str = format!($($arg)+);
            let stream = $crate::logs::LogStream::Custom($log_stream.to_string());
            tokio::spawn(async move {
                let _ = $crate::logs::write_log_to_file(
                    $level,
                    &message_str,
                    stream,
                    file!(),
                    line!()
                ).await;
            });
        } else {
            // Console fallback
            let ts = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f");
            let lvl_col = $crate::logs::colored_level($level);
            if $crate::logs::is_log_location_enabled() {
                println!(
                    "[{ts}] {lvl_col} - {} (File: {}, Line: {})",
                    format!($($arg)+),
                    file!(),
                    line!()
                );
            } else {
                println!(
                    "[{ts}] {lvl_col} - {}",
                    format!($($arg)+)
                );
            }
        }
    }};
}
