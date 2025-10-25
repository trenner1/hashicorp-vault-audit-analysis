/// Integration tests for vault-audit commands
/// These tests verify end-to-end functionality with sample data
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tempfile::{NamedTempFile, TempDir};

/// Helper to create sample audit log file
fn create_sample_audit_log() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("test_audit.log");
    let mut file = fs::File::create(&file_path).unwrap();

    // Sample entries with various scenarios
    let entries = vec![
        // Token lookup operations
        r#"{"type":"response","time":"2025-10-07T10:00:00Z","auth":{"entity_id":"entity-1","display_name":"user1","accessor":"token-1","policies":["default"]},"request":{"path":"auth/token/lookup-self","operation":"read"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:00:01Z","auth":{"entity_id":"entity-1","display_name":"user1","accessor":"token-1","policies":["default"]},"request":{"path":"auth/token/lookup-self","operation":"read"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:00:02Z","auth":{"entity_id":"entity-1","display_name":"user1","accessor":"token-1","policies":["default"]},"request":{"path":"auth/token/lookup-self","operation":"read"},"response":{}}"#,
        // KV operations
        r#"{"type":"response","time":"2025-10-07T10:01:00Z","auth":{"entity_id":"entity-2","display_name":"user2","policies":["default"]},"request":{"path":"kv/data/app1/secret1","operation":"read","mount_type":"kv"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:01:01Z","auth":{"entity_id":"entity-2","display_name":"user2","policies":["default"]},"request":{"path":"kv/data/app1/secret2","operation":"read","mount_type":"kv"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:01:02Z","auth":{"entity_id":"entity-3","display_name":"user3","policies":["default"]},"request":{"path":"kv/data/app2/config","operation":"read","mount_type":"kv"},"response":{}}"#,
        // Kubernetes auth
        r#"{"type":"response","time":"2025-10-07T10:02:00Z","auth":{"entity_id":"entity-k8s-1","display_name":"k8s-sa","policies":["default"]},"request":{"path":"auth/kubernetes/login","operation":"update"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:02:01Z","auth":{"entity_id":"entity-k8s-2","display_name":"k8s-sa","policies":["default"]},"request":{"path":"auth/kubernetes/login","operation":"update"},"response":{}}"#,
        // No entity operations
        r#"{"type":"response","time":"2025-10-07T10:03:00Z","auth":{"display_name":"approle-app1","policies":["default"]},"request":{"path":"auth/approle/login","operation":"update"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:03:01Z","auth":{"display_name":"approle-app2","policies":["app-policy"]},"request":{"path":"auth/approle/login","operation":"update"},"response":{}}"#,
        // Token operations
        r#"{"type":"response","time":"2025-10-07T10:04:00Z","auth":{"entity_id":"entity-4","display_name":"admin","metadata":{"username":"admin1"},"policies":["admin"]},"request":{"path":"auth/token/renew-self","operation":"update"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:04:01Z","auth":{"entity_id":"entity-4","display_name":"admin","metadata":{"username":"admin1"},"policies":["admin"]},"request":{"path":"auth/token/lookup-self","operation":"read"},"response":{}}"#,
        // Various paths for hotspot analysis
        r#"{"type":"response","time":"2025-10-07T10:05:00Z","auth":{"entity_id":"entity-5","display_name":"service1","policies":["default"]},"request":{"path":"secret/data/db/password","operation":"read"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:05:01Z","auth":{"entity_id":"entity-5","display_name":"service1","policies":["default"]},"request":{"path":"secret/data/db/password","operation":"read"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:05:02Z","auth":{"entity_id":"entity-5","display_name":"service1","policies":["default"]},"request":{"path":"secret/data/db/password","operation":"read"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:05:03Z","auth":{"entity_id":"entity-6","display_name":"service2","policies":["default"]},"request":{"path":"secret/data/api/key","operation":"read"},"response":{}}"#,
    ];

    for entry in entries {
        writeln!(file, "{}", entry).unwrap();
    }
    file.flush().unwrap();

    (dir, file_path)
}

/// Helper to create sample KV CSV file
fn create_sample_kv_csv() -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        "kv_path,unique_clients,operations_count,entity_ids,alias_names,sample_paths_accessed"
    )
    .unwrap();
    writeln!(file, "kv/app1/,2,5,entity-1 entity-2,,kv/data/app1/secret1").unwrap();
    writeln!(file, "kv/app2/,1,3,entity-3,,kv/data/app2/config").unwrap();
    file.flush().unwrap();
    file
}

#[test]
fn test_system_overview_command() {
    let (_dir, log_path) = create_sample_audit_log();

    use vault_audit_tools::commands::system_overview;
    let log_files = vec![log_path.to_str().unwrap().to_string()];
    let result = system_overview::run(&log_files, 10, 1);

    assert!(result.is_ok());
}

#[test]
fn test_token_lookup_abuse_command() {
    let (_dir, log_path) = create_sample_audit_log();

    use vault_audit_tools::commands::token_lookup_abuse;
    let log_files = vec![log_path.to_str().unwrap().to_string()];
    let result = token_lookup_abuse::run(&log_files, 2);

    assert!(result.is_ok());
}

#[test]
fn test_kv_summary_command() {
    let csv_file = create_sample_kv_csv();

    use vault_audit_tools::commands::kv_summary;
    let result = kv_summary::run(csv_file.path().to_str().unwrap());

    assert!(result.is_ok());
}

#[test]
fn test_kv_compare_command() {
    let csv1 = create_sample_kv_csv();
    let csv2 = create_sample_kv_csv();

    use vault_audit_tools::commands::kv_compare;
    let result = kv_compare::run(csv1.path().to_str().unwrap(), csv2.path().to_str().unwrap());

    assert!(result.is_ok());
}

#[test]
fn test_token_operations_command() {
    let (_dir, log_path) = create_sample_audit_log();

    use vault_audit_tools::commands::token_operations;
    let log_files = vec![log_path.to_str().unwrap().to_string()];
    let result = token_operations::run(&log_files, None);

    assert!(result.is_ok());
}

#[test]
fn test_path_hotspots_command() {
    let (_dir, log_path) = create_sample_audit_log();

    use vault_audit_tools::commands::path_hotspots;
    let log_files = vec![log_path.to_str().unwrap().to_string()];
    let result = path_hotspots::run(&log_files, 10);

    assert!(result.is_ok());
}

#[test]
fn test_entity_gaps_command() {
    let (_dir, log_path) = create_sample_audit_log();

    use vault_audit_tools::commands::entity_gaps;
    let log_files = vec![log_path.to_str().unwrap().to_string()];
    let result = entity_gaps::run(&log_files, 300);

    assert!(result.is_ok());
}

#[test]
fn test_entity_timeline_command() {
    let (_dir, log_path) = create_sample_audit_log();

    use vault_audit_tools::commands::entity_timeline;
    let log_files = vec![log_path.to_str().unwrap().to_string()];
    let result = entity_timeline::run(&log_files, "entity-1", None);

    assert!(result.is_ok());
}

#[test]
fn test_k8s_auth_command() {
    let (_dir, log_path) = create_sample_audit_log();

    use vault_audit_tools::commands::k8s_auth;
    let log_files = vec![log_path.to_str().unwrap().to_string()];
    let result = k8s_auth::run(&log_files, None);

    assert!(result.is_ok());
}

#[test]
fn test_kv_analyzer_command() {
    let (_dir, log_path) = create_sample_audit_log();
    let output = TempDir::new().unwrap();
    let output_path = output.path().join("kv_output.csv");

    use vault_audit_tools::commands::kv_analyzer;
    let log_files = vec![log_path.to_str().unwrap().to_string()];
    let result = kv_analyzer::run(&log_files, "kv/", Some(output_path.to_str().unwrap()), None);

    assert!(result.is_ok());
    assert!(output_path.exists());
}

#[test]
fn test_token_export_command() {
    let (_dir, log_path) = create_sample_audit_log();
    let output = TempDir::new().unwrap();
    let output_path = output.path().join("token_export.csv");

    use vault_audit_tools::commands::token_export;
    let log_files = vec![log_path.to_str().unwrap().to_string()];
    let result = token_export::run(&log_files, output_path.to_str().unwrap(), 1);

    assert!(result.is_ok());
    assert!(output_path.exists());
}
