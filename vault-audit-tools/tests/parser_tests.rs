use std::io::Write;
use tempfile::NamedTempFile;
use vault_audit_tools::audit::parser::AuditLogReader;

#[test]
fn test_parse_valid_audit_entry() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let log_line = r#"{"type":"response","time":"2025-10-07T10:30:00.123456Z","auth":{"entity_id":"test-entity-123","display_name":"test-user","policies":["default"]},"request":{"path":"kv/data/test","operation":"read"},"response":{}}"#;

    writeln!(temp_file, "{}", log_line).unwrap();
    temp_file.flush().unwrap();

    let mut reader = AuditLogReader::new(temp_file.path()).unwrap();
    let entry = reader.next_entry().unwrap().unwrap();

    assert_eq!(entry.entity_id(), Some("test-entity-123"));
    assert_eq!(entry.display_name(), Some("test-user"));
    assert_eq!(entry.path(), Some("kv/data/test"));
    assert_eq!(entry.operation(), Some("read"));
}

#[test]
fn test_parse_missing_entity() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let log_line = r#"{"type":"response","time":"2025-10-07T10:30:00Z","auth":{},"request":{"path":"auth/token/lookup-self","operation":"read"},"response":{}}"#;

    writeln!(temp_file, "{}", log_line).unwrap();
    temp_file.flush().unwrap();

    let mut reader = AuditLogReader::new(temp_file.path()).unwrap();
    let entry = reader.next_entry().unwrap().unwrap();

    assert_eq!(entry.entity_id(), None);
    assert_eq!(entry.path(), Some("auth/token/lookup-self"));
}

#[test]
fn test_skip_invalid_json() {
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "{{invalid json}}").unwrap();
    writeln!(temp_file, r#"{{"type":"response","time":"2025-10-07T10:30:00Z","auth":{{"entity_id":"test-123"}},"request":{{"path":"test","operation":"read"}},"response":{{}}}}"#).unwrap();
    temp_file.flush().unwrap();

    let mut reader = AuditLogReader::new(temp_file.path()).unwrap();
    let entry = reader.next_entry().unwrap().unwrap();

    assert_eq!(entry.entity_id(), Some("test-123"));
}

#[test]
fn test_empty_file() {
    let temp_file = NamedTempFile::new().unwrap();
    let mut reader = AuditLogReader::new(temp_file.path()).unwrap();
    let result = reader.next_entry().unwrap();
    assert!(result.is_none());
}

#[test]
fn test_multiple_entries() {
    let mut temp_file = NamedTempFile::new().unwrap();

    for i in 1..=5 {
        let log_line = format!(
            r#"{{"type":"response","time":"2025-10-07T10:30:00Z","auth":{{"entity_id":"entity-{}"}},"request":{{"path":"test","operation":"read"}},"response":{{}}}}"#,
            i
        );
        writeln!(temp_file, "{}", log_line).unwrap();
    }
    temp_file.flush().unwrap();

    let mut reader = AuditLogReader::new(temp_file.path()).unwrap();
    let mut count = 0;

    while let Some(_entry) = reader.next_entry().unwrap() {
        count += 1;
    }

    assert_eq!(count, 5);
}

#[test]
fn test_kv_v2_path_detection() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let log_line = r#"{"type":"response","time":"2025-10-07T10:30:00Z","auth":{"entity_id":"test"},"request":{"path":"kv/data/app1/secret","operation":"read","mount_type":"kv"},"response":{}}"#;

    writeln!(temp_file, "{}", log_line).unwrap();
    temp_file.flush().unwrap();

    let mut reader = AuditLogReader::new(temp_file.path()).unwrap();
    let entry = reader.next_entry().unwrap().unwrap();

    assert!(entry.path().unwrap().contains("/data/"));
    assert_eq!(entry.operation(), Some("read"));
}

#[test]
fn test_kubernetes_auth_path() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let log_line = r#"{"type":"response","time":"2025-10-07T10:30:00Z","auth":{"entity_id":"test"},"request":{"path":"auth/kubernetes/login","operation":"update"},"response":{}}"#;

    writeln!(temp_file, "{}", log_line).unwrap();
    temp_file.flush().unwrap();

    let mut reader = AuditLogReader::new(temp_file.path()).unwrap();
    let entry = reader.next_entry().unwrap().unwrap();

    assert!(entry.path().unwrap().contains("kubernetes"));
    assert!(entry.path().unwrap().ends_with("/login"));
}
