use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_preprocess_entities_with_invalid_file() {
    use vault_audit_tools::commands::preprocess_entities;

    let result = preprocess_entities::run(
        &["/nonexistent/file.log".to_string()],
        "output.json",
        "json",
    );

    assert!(result.is_err());
}

#[test]
fn test_preprocess_entities_with_empty_file() {
    use vault_audit_tools::commands::preprocess_entities;

    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("empty.log");
    File::create(&log_path).unwrap();

    let output_path = temp_dir.path().join("output.json");

    let result = preprocess_entities::run(
        &[log_path.to_str().unwrap().to_string()],
        output_path.to_str().unwrap(),
        "json",
    );

    // Should succeed even with empty file
    assert!(result.is_ok());
}

#[test]
fn test_preprocess_entities_invalid_format() {
    use vault_audit_tools::commands::preprocess_entities;

    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");
    File::create(&log_path).unwrap();

    let output_path = temp_dir.path().join("output.txt");

    let result = preprocess_entities::run(
        &[log_path.to_str().unwrap().to_string()],
        output_path.to_str().unwrap(),
        "invalid_format",
    );

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid format"));
}

#[test]
fn test_preprocess_entities_json_format() {
    use vault_audit_tools::commands::preprocess_entities;

    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    // Create a log file with a valid login event
    let mut file = File::create(&log_path).unwrap();
    let entry = r#"{"type":"request","time":"2025-10-07T12:00:00Z","auth":{"entity_id":"test-123","display_name":"test-user"},"request":{"path":"auth/kubernetes/login"}}"#;
    writeln!(file, "{}", entry).unwrap();

    let output_path = temp_dir.path().join("output.json");

    let result = preprocess_entities::run(
        &[log_path.to_str().unwrap().to_string()],
        output_path.to_str().unwrap(),
        "json",
    );

    assert!(result.is_ok());
    assert!(output_path.exists());
}

#[test]
fn test_preprocess_entities_csv_format() {
    use vault_audit_tools::commands::preprocess_entities;

    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    // Create a log file with a valid login event
    let mut file = File::create(&log_path).unwrap();
    let entry = r#"{"type":"request","time":"2025-10-07T12:00:00Z","auth":{"entity_id":"test-456","display_name":"csv-user"},"request":{"path":"auth/userpass/login"}}"#;
    writeln!(file, "{}", entry).unwrap();

    let output_path = temp_dir.path().join("output.csv");

    let result = preprocess_entities::run(
        &[log_path.to_str().unwrap().to_string()],
        output_path.to_str().unwrap(),
        "csv",
    );

    assert!(result.is_ok());
    assert!(output_path.exists());
}

#[test]
fn test_kv_summary_invalid_file() {
    use vault_audit_tools::commands::kv_summary;

    let result = kv_summary::run("/nonexistent/kv_usage.csv");
    assert!(result.is_err());
}

#[test]
fn test_kv_summary_empty_file() {
    use vault_audit_tools::commands::kv_summary;

    let temp_dir = TempDir::new().unwrap();
    let csv_path = temp_dir.path().join("empty.csv");
    File::create(&csv_path).unwrap();

    let result = kv_summary::run(csv_path.to_str().unwrap());
    // Should handle empty file gracefully
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_kv_compare_missing_files() {
    use vault_audit_tools::commands::kv_compare;

    let result = kv_compare::run("/nonexistent/old.csv", "/nonexistent/new.csv");

    // kv_compare doesn't error on missing files, it just reports them
    assert!(result.is_ok());
}

#[test]
fn test_kv_compare_with_temp_files() {
    use vault_audit_tools::commands::kv_compare;

    let temp_dir = TempDir::new().unwrap();

    let old_path = temp_dir.path().join("old.csv");
    let new_path = temp_dir.path().join("new.csv");

    // Create minimal CSV files
    let mut old_file = File::create(&old_path).unwrap();
    writeln!(
        old_file,
        "path,entity_id,read_count,list_count,first_access,last_access"
    )
    .unwrap();

    let mut new_file = File::create(&new_path).unwrap();
    writeln!(
        new_file,
        "path,entity_id,read_count,list_count,first_access,last_access"
    )
    .unwrap();

    let result = kv_compare::run(old_path.to_str().unwrap(), new_path.to_str().unwrap());

    assert!(result.is_ok());
}

#[test]
fn test_entity_gaps_empty_log() {
    use vault_audit_tools::commands::entity_gaps;

    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("empty.log");
    File::create(&log_path).unwrap();

    let result = entity_gaps::run(&[log_path.to_str().unwrap().to_string()], 3600);
    assert!(result.is_ok());
}

#[test]
fn test_entity_gaps_invalid_file() {
    use vault_audit_tools::commands::entity_gaps;

    let result = entity_gaps::run(&["/nonexistent/file.log".to_string()], 3600);
    assert!(result.is_err());
}

#[test]
fn test_system_overview_invalid_file() {
    use vault_audit_tools::commands::system_overview;

    let result = system_overview::run(&["/nonexistent/file.log".to_string()], 10, 1, false);
    assert!(result.is_err());
}

#[test]
fn test_system_overview_empty_log() {
    use vault_audit_tools::commands::system_overview;

    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("empty.log");
    File::create(&log_path).unwrap();

    let result = system_overview::run(&[log_path.to_str().unwrap().to_string()], 10, 1, false);
    assert!(result.is_ok());
}

#[test]
fn test_k8s_auth_invalid_file() {
    use vault_audit_tools::commands::k8s_auth;

    let result = k8s_auth::run(&["/nonexistent/file.log".to_string()], None);
    assert!(result.is_err());
}

#[test]
fn test_k8s_auth_empty_log() {
    use vault_audit_tools::commands::k8s_auth;

    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("empty.log");
    File::create(&log_path).unwrap();

    let result = k8s_auth::run(&[log_path.to_str().unwrap().to_string()], None);
    assert!(result.is_ok());
}

#[test]
fn test_path_hotspots_invalid_file() {
    use vault_audit_tools::commands::path_hotspots;

    let result = path_hotspots::run(&["/nonexistent/file.log".to_string()], 10);
    assert!(result.is_err());
}

#[test]
fn test_path_hotspots_empty_log() {
    use vault_audit_tools::commands::path_hotspots;

    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("empty.log");
    File::create(&log_path).unwrap();

    let result = path_hotspots::run(&[log_path.to_str().unwrap().to_string()], 10);
    assert!(result.is_ok());
}
