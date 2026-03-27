#[macro_use]
pub mod logs;
pub mod http_backend;
pub use log::Level;
#[doc(hidden)]
pub use serde_json;

/// Internal helper: inserts structured key-value pairs into a `serde_json::Map`,
/// supporting both `Display` (`=>`) and `Debug` (`=>?`) formatting.
#[macro_export]
#[doc(hidden)]
macro_rules! __crypsol_kv {
    // Debug field, more fields follow
    ($map:ident; $key:literal => ? $val:expr, $($rest:tt)+) => {
        $map.insert($key.to_string(), $crate::serde_json::Value::String(format!("{:?}", $val)));
        $crate::__crypsol_kv!($map; $($rest)+);
    };
    // Display field, more fields follow
    ($map:ident; $key:literal => $val:expr, $($rest:tt)+) => {
        $map.insert($key.to_string(), $crate::serde_json::Value::String(format!("{}", $val)));
        $crate::__crypsol_kv!($map; $($rest)+);
    };
    // Debug field, last (optional trailing comma)
    ($map:ident; $key:literal => ? $val:expr $(,)?) => {
        $map.insert($key.to_string(), $crate::serde_json::Value::String(format!("{:?}", $val)));
    };
    // Display field, last (optional trailing comma)
    ($map:ident; $key:literal => $val:expr $(,)?) => {
        $map.insert($key.to_string(), $crate::serde_json::Value::String(format!("{}", $val)));
    };
}

/*
 * This file provides two macros for logging:
 * 1) `log!` for standard usage (maps to a log level and auto-selects a log stream).
 * 2) `log_custom!` for specifying a custom log stream name.
 *
 * Backends (checked in order): CloudWatch, HTTP push, File, Console.
 */

/// A macro for logging a message with a given log::Level. If `LOG_TO_CLOUDWATCH` is "true",
/// it sends the log to CloudWatch asynchronously. Otherwise, it logs to the console.
///
/// # Usage
/// ```ignore
/// log!(Level::Info, "Hello from the log!");
/// log!(Level::Info, "User logged in"; "user_id" => user_id, "ip" => ip_addr);
/// log!(Level::Error, "Query failed"; "component" => "DB", "error" =>? e);
/// ```
#[macro_export]
macro_rules! log {

    ($level:expr, $fmt:literal $(, $fmtarg:expr)* ; $($fields:tt)+) => {{
        let message_str = format!($fmt $(, $fmtarg)*);
        let mut fields = $crate::serde_json::Map::new();
        $crate::__crypsol_kv!(fields; $($fields)+);
        let structured_msg = $crate::logs::build_structured_message(&message_str, fields);

        if $crate::logs::is_log_to_cloudwatch_enabled() {
            let log_stream = $crate::logs::LogStream::from_level(&$level);
            tokio::spawn(async move {
                if let Err(e) = $crate::logs::custom_cloudwatch_log(
                    $level,
                    &structured_msg,
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
        } else if $crate::logs::is_log_to_http_enabled() {
            let log_stream = $crate::logs::LogStream::from_level(&$level);
            tokio::spawn(async move {
                $crate::http_backend::queue_http_log(
                    $level,
                    &structured_msg,
                    log_stream,
                    file!(),
                    line!()
                ).await;
            });
        } else if $crate::logs::is_log_to_file_enabled() {
            let log_stream = $crate::logs::LogStream::from_level(&$level);
            tokio::spawn(async move {
                let _ = $crate::logs::write_log_to_file(
                    $level,
                    &structured_msg,
                    log_stream,
                    file!(),
                    line!()
                ).await;
            });
        } else {
            let ts = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f");
            let lvl_col = $crate::logs::colored_level($level);
            if $crate::logs::is_log_location_enabled() {
                println!(
                    "[{ts}] {lvl_col} - {} (File: {}, Line: {})",
                    structured_msg,
                    file!(),
                    line!()
                );
            } else {
                println!(
                    "[{ts}] {lvl_col} - {}",
                    structured_msg
                );
            }
        }
    }};


    ($level:expr, $($arg:tt)+) => {{
        if $crate::logs::is_log_to_cloudwatch_enabled() {
            let message_str = format!($($arg)+);
            let log_stream = $crate::logs::LogStream::from_level(&$level);

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
        } else if $crate::logs::is_log_to_http_enabled() {
            let message_str = format!($($arg)+);
            let log_stream = $crate::logs::LogStream::from_level(&$level);
            tokio::spawn(async move {
                $crate::http_backend::queue_http_log(
                    $level,
                    &message_str,
                    log_stream,
                    file!(),
                    line!()
                ).await;
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
/// log_custom!(Level::Info, "MyCustomStream", "order placed"; "order_id" => id, "total" => amount);
/// ```
#[macro_export]
macro_rules! log_custom {

    ($level:expr, $log_stream:expr, $fmt:literal $(, $fmtarg:expr)* ; $($fields:tt)+) => {{
        let message_str = format!($fmt $(, $fmtarg)*);
        let mut fields = $crate::serde_json::Map::new();
        $crate::__crypsol_kv!(fields; $($fields)+);
        let structured_msg = $crate::logs::build_structured_message(&message_str, fields);

        if $crate::logs::is_log_to_cloudwatch_enabled() {
            let stream = $crate::logs::LogStream::Custom($log_stream.to_string());
            tokio::spawn(async move {
                if let Err(e) = $crate::logs::custom_cloudwatch_log(
                    $level,
                    &structured_msg,
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
        } else if $crate::logs::is_log_to_http_enabled() {
            let stream = $crate::logs::LogStream::Custom($log_stream.to_string());
            tokio::spawn(async move {
                $crate::http_backend::queue_http_log(
                    $level,
                    &structured_msg,
                    stream,
                    file!(),
                    line!()
                ).await;
            });
        } else if $crate::logs::is_log_to_file_enabled() {
            let stream = $crate::logs::LogStream::Custom($log_stream.to_string());
            tokio::spawn(async move {
                let _ = $crate::logs::write_log_to_file(
                    $level,
                    &structured_msg,
                    stream,
                    file!(),
                    line!()
                ).await;
            });
        } else {
            let ts = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f");
            let lvl_col = $crate::logs::colored_level($level);
            if $crate::logs::is_log_location_enabled() {
                println!(
                    "[{ts}] {lvl_col} - {} (File: {}, Line: {})",
                    structured_msg,
                    file!(),
                    line!()
                );
            } else {
                println!(
                    "[{ts}] {lvl_col} - {}",
                    structured_msg
                );
            }
        }
    }};


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
        } else if $crate::logs::is_log_to_http_enabled() {
            let message_str = format!($($arg)+);
            let stream = $crate::logs::LogStream::Custom($log_stream.to_string());
            tokio::spawn(async move {
                $crate::http_backend::queue_http_log(
                    $level,
                    &message_str,
                    stream,
                    file!(),
                    line!()
                ).await;
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
