use crypsol_logger::{Level, logs};

#[test]
fn test_format_log_entry_with_location() {
    unsafe { std::env::set_var("LOG_SHOW_LOCATION", "true") };
    let entry = logs::format_log_entry(Level::Info, "hello", "file.rs", 10);
    assert!(entry.contains("File: file.rs"));
    assert!(entry.contains("Line: 10"));
}

#[test]
fn test_format_log_entry_without_location() {
    unsafe { std::env::remove_var("LOG_SHOW_LOCATION") };
    let entry = logs::format_log_entry(Level::Info, "hello", "file.rs", 10);
    assert!(!entry.contains("File:"));
}

#[test]
fn test_colored_level() {
    let s = logs::colored_level(Level::Error).to_string();
    assert!(s.contains("ERROR"));
}

#[test]
fn test_logstream_from_string_known() {
    use logs::LogStream;
    let s = LogStream::from_string("Server_Error_Responses".to_string());
    matches!(s, LogStream::ServerErrorResponses);
}

#[test]
fn test_logstream_from_string_custom() {
    use logs::LogStream;
    let name = "CustomStream".to_string();
    if let LogStream::Custom(n) = LogStream::from_string(name.clone()) {
        assert_eq!(n, name);
    } else {
        panic!("not custom");
    }
}

#[test]
fn test_logstream_from_level() {
    use logs::LogStream;
    assert!(matches!(
        LogStream::from_level(&Level::Warn),
        LogStream::ClientErrorResponses
    ));
}
