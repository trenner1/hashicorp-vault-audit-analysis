use vault_audit_tools::audit::types::*;

#[test]
fn test_parse_complete_audit_entry() {
    let json = r#"{
        "type": "request",
        "time": "2025-10-07T12:34:56.789Z",
        "auth": {
            "entity_id": "test-entity-123",
            "display_name": "test-user",
            "policies": ["default", "admin"],
            "token_type": "service"
        },
        "request": {
            "id": "req-123",
            "operation": "read",
            "path": "secret/data/myapp",
            "remote_address": "10.0.1.100"
        }
    }"#;

    let entry: AuditEntry = serde_json::from_str(json).expect("Failed to parse audit entry");

    assert_eq!(entry.entry_type, "request");
    assert_eq!(entry.time, "2025-10-07T12:34:56.789Z");
    assert!(entry.auth.is_some());
    assert!(entry.request.is_some());
    assert!(entry.response.is_none());

    let auth = entry.auth.unwrap();
    assert_eq!(auth.entity_id, Some("test-entity-123".to_string()));
    assert_eq!(auth.display_name, Some("test-user".to_string()));
    assert_eq!(auth.token_type, Some("service".to_string()));

    let request = entry.request.unwrap();
    assert_eq!(request.operation, Some("read".to_string()));
    assert_eq!(request.path, Some("secret/data/myapp".to_string()));
}

#[test]
fn test_parse_login_request() {
    let json = r#"{
        "type": "request",
        "time": "2025-10-07T12:34:56.789Z",
        "request": {
            "operation": "update",
            "path": "auth/kubernetes/login",
            "remote_address": "10.0.1.100"
        }
    }"#;

    let entry: AuditEntry = serde_json::from_str(json).expect("Failed to parse login request");

    assert_eq!(entry.entry_type, "request");
    assert!(entry.request.is_some());

    let request = entry.request.unwrap();
    assert_eq!(request.path, Some("auth/kubernetes/login".to_string()));
    assert!(request.path.unwrap().ends_with("/login"));
}

#[test]
fn test_parse_response_entry() {
    let json = r#"{
        "type": "response",
        "time": "2025-10-07T12:34:56.789Z",
        "auth": {
            "entity_id": "test-entity-456",
            "display_name": "service-account"
        },
        "request": {
            "path": "secret/data/myapp"
        },
        "response": {
            "mount_type": "kv"
        }
    }"#;

    let entry: AuditEntry = serde_json::from_str(json).expect("Failed to parse response entry");

    assert_eq!(entry.entry_type, "response");
    assert!(entry.response.is_some());

    let response = entry.response.unwrap();
    assert_eq!(response.mount_type, Some("kv".to_string()));
}

#[test]
fn test_parse_entry_with_error() {
    let json = r#"{
        "type": "response",
        "time": "2025-10-07T12:34:56.789Z",
        "error": "permission denied",
        "request": {
            "path": "secret/data/forbidden"
        }
    }"#;

    let entry: AuditEntry = serde_json::from_str(json).expect("Failed to parse error entry");

    assert!(entry.error.is_some());
    assert_eq!(entry.error.unwrap(), "permission denied");
}

#[test]
fn test_parse_entry_without_auth() {
    let json = r#"{
        "type": "request",
        "time": "2025-10-07T12:34:56.789Z",
        "request": {
            "path": "sys/health"
        }
    }"#;

    let entry: AuditEntry =
        serde_json::from_str(json).expect("Failed to parse unauthenticated request");

    assert!(entry.auth.is_none());
}

#[test]
fn test_parse_auth_with_metadata() {
    let json = r#"{
        "type": "request",
        "time": "2025-10-07T12:34:56.789Z",
        "auth": {
            "entity_id": "test-entity",
            "metadata": {
                "role": "developer",
                "team": "platform"
            }
        },
        "request": {
            "path": "secret/data/test"
        }
    }"#;

    let entry: AuditEntry = serde_json::from_str(json).expect("Failed to parse auth with metadata");

    let auth = entry.auth.unwrap();
    assert!(auth.metadata.is_some());

    let metadata = auth.metadata.unwrap();
    assert!(metadata.contains_key("role"));
    assert!(metadata.contains_key("team"));
}

#[test]
fn test_parse_kv_operation() {
    let json = r#"{
        "type": "request",
        "time": "2025-10-07T12:34:56.789Z",
        "auth": {
            "entity_id": "kv-user-123"
        },
        "request": {
            "operation": "read",
            "path": "kv/data/myapp/config",
            "mount_point": "kv/",
            "mount_type": "kv"
        },
        "response": {
            "mount_type": "kv"
        }
    }"#;

    let entry: AuditEntry = serde_json::from_str(json).expect("Failed to parse KV operation");

    let request = entry.request.unwrap();
    assert!(request.path.as_ref().unwrap().contains("/data/"));
    assert_eq!(request.mount_type, Some("kv".to_string()));
}

#[test]
fn test_parse_token_lookup() {
    let json = r#"{
        "type": "request",
        "time": "2025-10-07T12:34:56.789Z",
        "auth": {
            "entity_id": "lookup-entity"
        },
        "request": {
            "operation": "update",
            "path": "auth/token/lookup-self"
        }
    }"#;

    let entry: AuditEntry = serde_json::from_str(json).expect("Failed to parse token lookup");

    let request = entry.request.unwrap();
    assert!(request.path.as_ref().unwrap().contains("lookup"));
}

#[test]
fn test_parse_minimal_entry() {
    let json = r#"{
        "type": "request",
        "time": "2025-10-07T12:34:56.789Z"
    }"#;

    let entry: AuditEntry = serde_json::from_str(json).expect("Failed to parse minimal entry");

    assert_eq!(entry.entry_type, "request");
    assert!(entry.auth.is_none());
    assert!(entry.request.is_none());
    assert!(entry.response.is_none());
    assert!(entry.error.is_none());
}

#[test]
fn test_invalid_json_fails() {
    let json = r#"{"type": "invalid"#;

    let result: Result<AuditEntry, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn test_missing_required_type_field() {
    let json = r#"{
        "time": "2025-10-07T12:34:56.789Z"
    }"#;

    let result: Result<AuditEntry, _> = serde_json::from_str(json);
    assert!(result.is_err());
}
