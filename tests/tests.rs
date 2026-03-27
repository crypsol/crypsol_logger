use crypsol_logger::{Level, log, log_custom, logs};

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

#[test]
fn test_build_structured_message_contains_all_fields() {
    let mut fields = serde_json::Map::new();
    fields.insert(
        "user_id".to_string(),
        serde_json::Value::String("42".to_string()),
    );
    fields.insert(
        "action".to_string(),
        serde_json::Value::String("login".to_string()),
    );

    let result = logs::build_structured_message("user authenticated", fields);
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(parsed["message"], "user authenticated");
    assert_eq!(parsed["user_id"], "42");
    assert_eq!(parsed["action"], "login");
}

#[test]
fn test_build_structured_message_single_field() {
    let mut fields = serde_json::Map::new();
    fields.insert(
        "count".to_string(),
        serde_json::Value::String("7".to_string()),
    );

    let result = logs::build_structured_message("items processed", fields);
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert_eq!(parsed["message"], "items processed");
    assert_eq!(parsed["count"], "7");
}

#[tokio::test]
async fn test_log_macro_structured_arm() {
    unsafe { std::env::remove_var("LOG_TO_CLOUDWATCH") };
    unsafe { std::env::remove_var("LOG_TO_FILE") };
    unsafe { std::env::remove_var("LOG_SHOW_LOCATION") };

    let uid = 99u64;
    let ip = "10.0.0.1";
    log!(Level::Info, "connection from {}", ip; "user_id" => uid, "ip" => ip);
}

#[tokio::test]
async fn test_log_custom_macro_structured_arm() {
    unsafe { std::env::remove_var("LOG_TO_CLOUDWATCH") };
    unsafe { std::env::remove_var("LOG_TO_FILE") };
    unsafe { std::env::remove_var("LOG_SHOW_LOCATION") };

    let order = "ORD-001";
    log_custom!(Level::Info, "Orders", "order placed"; "order_id" => order, "total" => 250);
}

#[test]
fn test_structured_fields_preserve_types() {
    let mut fields = serde_json::Map::new();
    fields.insert("count".into(), serde_json::Value::from(42_i64));
    fields.insert("active".into(), serde_json::Value::from(true));
    fields.insert("name".into(), serde_json::Value::from("alice"));

    let result = logs::build_structured_message("typed check", fields);
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

    assert!(parsed["count"].is_number(), "count should be a JSON number");
    assert!(parsed["active"].is_boolean(), "active should be a JSON bool");
    assert!(parsed["name"].is_string(), "name should be a JSON string");
    assert_eq!(parsed["count"], 42);
    assert_eq!(parsed["active"], true);
    assert_eq!(parsed["name"], "alice");
}
