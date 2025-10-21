/// Integration tests for entity analysis commands
/// Tests entity-creation, entity-churn, and baseline entity functionality
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tempfile::{NamedTempFile, TempDir};
use vault_audit_tools::commands::{entity_churn, entity_creation};

/// Helper to create sample audit log with entity creation events
fn create_entity_creation_log() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("test_audit.log");
    let mut file = fs::File::create(&file_path).unwrap();

    // Sample entries showing entity creation on different auth paths
    let entries = vec![
        // GitHub auth creates entities
        r#"{"type":"response","time":"2025-10-07T10:00:00Z","auth":{"entity_id":"entity-github-1","display_name":"org/repo","policies":["default"]},"request":{"path":"auth/github/login","operation":"update","mount_path":"auth/github/","mount_type":"github"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:00:01Z","auth":{"entity_id":"entity-github-2","display_name":"org/repo2","policies":["default"]},"request":{"path":"auth/github/login","operation":"update","mount_path":"auth/github/","mount_type":"github"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:00:02Z","auth":{"entity_id":"entity-github-1","display_name":"org/repo","policies":["default"]},"request":{"path":"kv/data/secret","operation":"read","mount_path":"kv/"},"response":{}}"#,
        // Kubernetes auth creates entities
        r#"{"type":"response","time":"2025-10-07T10:01:00Z","auth":{"entity_id":"entity-k8s-1","display_name":"system:serviceaccount:default:app","policies":["default"]},"request":{"path":"auth/kubernetes/login","operation":"update","mount_path":"auth/kubernetes/","mount_type":"kubernetes"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:01:01Z","auth":{"entity_id":"entity-k8s-2","display_name":"system:serviceaccount:default:app2","policies":["default"]},"request":{"path":"auth/kubernetes/login","operation":"update","mount_path":"auth/kubernetes/","mount_type":"kubernetes"},"response":{}}"#,
        // AppRole creates entities
        r#"{"type":"response","time":"2025-10-07T10:02:00Z","auth":{"entity_id":"entity-approle-1","display_name":"approle-app1","policies":["app"]},"request":{"path":"auth/approle/login","operation":"update","mount_path":"auth/approle/","mount_type":"approle"},"response":{}}"#,
    ];

    for entry in entries {
        writeln!(file, "{}", entry).unwrap();
    }
    file.flush().unwrap();

    (dir, file_path)
}

/// Helper to create multiple day logs for churn analysis
fn create_multi_day_logs() -> (TempDir, Vec<PathBuf>) {
    let dir = TempDir::new().unwrap();

    // Day 1 log
    let day1_path = dir.path().join("day1.log");
    let mut day1 = fs::File::create(&day1_path).unwrap();
    let day1_entries = vec![
        r#"{"type":"response","time":"2025-10-07T10:00:00Z","auth":{"entity_id":"entity-persistent","display_name":"persistent-user","policies":["default"]},"request":{"path":"auth/kubernetes/login","operation":"update","mount_point":"auth/kubernetes/","mount_type":"kubernetes"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:00:01Z","auth":{"entity_id":"entity-ephemeral-1","display_name":"ephemeral-1","policies":["default"]},"request":{"path":"auth/github/login","operation":"update","mount_point":"auth/github/","mount_type":"github"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-07T10:00:02Z","auth":{"entity_id":"entity-day1-only","display_name":"day1-only","policies":["default"]},"request":{"path":"auth/approle/login","operation":"update","mount_point":"auth/approle/","mount_type":"approle"},"response":{}}"#,
    ];
    for entry in day1_entries {
        writeln!(day1, "{}", entry).unwrap();
    }
    day1.flush().unwrap();

    // Day 2 log
    let day2_path = dir.path().join("day2.log");
    let mut day2 = fs::File::create(&day2_path).unwrap();
    let day2_entries = vec![
        r#"{"type":"response","time":"2025-10-08T10:00:00Z","auth":{"entity_id":"entity-persistent","display_name":"persistent-user","policies":["default"]},"request":{"path":"auth/kubernetes/login","operation":"update","mount_point":"auth/kubernetes/","mount_type":"kubernetes"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-08T10:00:01Z","auth":{"entity_id":"entity-new-day2","display_name":"new-day2","policies":["default"]},"request":{"path":"auth/github/login","operation":"update","mount_point":"auth/github/","mount_type":"github"},"response":{}}"#,
    ];
    for entry in day2_entries {
        writeln!(day2, "{}", entry).unwrap();
    }
    day2.flush().unwrap();

    // Day 3 log
    let day3_path = dir.path().join("day3.log");
    let mut day3 = fs::File::create(&day3_path).unwrap();
    let day3_entries = vec![
        r#"{"type":"response","time":"2025-10-09T10:00:00Z","auth":{"entity_id":"entity-persistent","display_name":"persistent-user","policies":["default"]},"request":{"path":"auth/kubernetes/login","operation":"update","mount_point":"auth/kubernetes/","mount_type":"kubernetes"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-09T10:00:01Z","auth":{"entity_id":"entity-new-day2","display_name":"new-day2","policies":["default"]},"request":{"path":"auth/github/login","operation":"update","mount_point":"auth/github/","mount_type":"github"},"response":{}}"#,
        r#"{"type":"response","time":"2025-10-09T10:00:02Z","auth":{"entity_id":"entity-new-day3","display_name":"new-day3","policies":["default"]},"request":{"path":"auth/approle/login","operation":"update","mount_point":"auth/approle/","mount_type":"approle"},"response":{}}"#,
    ];
    for entry in day3_entries {
        writeln!(day3, "{}", entry).unwrap();
    }
    day3.flush().unwrap();

    (dir, vec![day1_path, day2_path, day3_path])
}

/// Helper to create baseline entities CSV
fn create_baseline_csv() -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "entity_id,name,auth_mount_path").unwrap();
    writeln!(file, "entity-baseline-1,baseline-user-1,auth/github/").unwrap();
    writeln!(file, "entity-baseline-2,baseline-user-2,auth/kubernetes/").unwrap();
    file.flush().unwrap();
    file
}

#[test]
fn test_entity_creation_basic() {
    let (_dir, log_path) = create_entity_creation_log();

    // Run entity-creation command
    let log_files = vec![log_path.to_str().unwrap().to_string()];
    let result = entity_creation::run(&log_files, None, None);

    assert!(result.is_ok(), "entity-creation should succeed");
}

#[test]
fn test_entity_creation_with_output() {
    let (_dir, log_path) = create_entity_creation_log();
    let output_file = NamedTempFile::new().unwrap();

    // Run entity-creation with JSON output
    let log_files = vec![log_path.to_str().unwrap().to_string()];
    let result = entity_creation::run(&log_files, None, Some(output_file.path().to_str().unwrap()));

    assert!(result.is_ok(), "entity-creation with output should succeed");

    // Verify output file was created and contains JSON
    let contents = fs::read_to_string(output_file.path()).unwrap();
    assert!(
        contents.contains("entity_id"),
        "Output should contain entity data"
    );
    assert!(
        contents.contains("mount_path"),
        "Output should contain mount_path data"
    );
}

#[test]
fn test_entity_churn_multi_day() {
    let (_dir, log_paths) = create_multi_day_logs();
    let log_files: Vec<String> = log_paths
        .iter()
        .map(|p| p.to_str().unwrap().to_string())
        .collect();

    // Run entity-churn command
    let result = entity_churn::run(&log_files, None, None, None);

    assert!(
        result.is_ok(),
        "entity-churn should succeed with multiple files"
    );
}

#[test]
fn test_entity_churn_with_baseline() {
    let (_dir, log_paths) = create_multi_day_logs();
    let baseline_csv = create_baseline_csv();
    let log_files: Vec<String> = log_paths
        .iter()
        .map(|p| p.to_str().unwrap().to_string())
        .collect();

    // Run entity-churn with baseline
    let result = entity_churn::run(
        &log_files,
        None,
        Some(baseline_csv.path().to_str().unwrap()),
        None,
    );

    assert!(result.is_ok(), "entity-churn with baseline should succeed");
}

#[test]
fn test_entity_churn_with_json_output() {
    let (_dir, log_paths) = create_multi_day_logs();
    let output_file = NamedTempFile::new().unwrap();
    let log_files: Vec<String> = log_paths
        .iter()
        .map(|p| p.to_str().unwrap().to_string())
        .collect();

    // Run entity-churn with JSON output
    let result = entity_churn::run(
        &log_files,
        None,
        None,
        Some(output_file.path().to_str().unwrap()),
    );

    assert!(result.is_ok(), "entity-churn with output should succeed");

    // Verify output file contains expected data
    let contents = fs::read_to_string(output_file.path()).unwrap();
    assert!(
        contents.contains("entity_id"),
        "Output should contain entity_id"
    );
    assert!(
        contents.contains("lifecycle"),
        "Output should contain lifecycle classification"
    );
}

#[test]
fn test_entity_churn_minimum_files() {
    let (_dir, log_paths) = create_multi_day_logs();

    // Test with only 2 files (minimum required)
    let log_files: Vec<String> = log_paths
        .iter()
        .take(2)
        .map(|p| p.to_str().unwrap().to_string())
        .collect();

    let result = entity_churn::run(&log_files, None, None, None);

    assert!(result.is_ok(), "entity-churn should work with 2 files");
}

#[test]
fn test_entity_churn_single_file() {
    let (_dir, log_paths) = create_multi_day_logs();

    // Test with only 1 file (should work for single-day analysis)
    let log_files: Vec<String> = log_paths
        .iter()
        .take(1)
        .map(|p| p.to_str().unwrap().to_string())
        .collect();

    let result = entity_churn::run(&log_files, None, None, None);

    // Single file is allowed (useful for baseline analysis)
    assert!(
        result.is_ok(),
        "entity-churn should work with 1 file for baseline analysis"
    );
}
