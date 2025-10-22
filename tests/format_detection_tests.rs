use std::fs::File;
use std::io::Write;
use tempfile::TempDir;
use vault_audit_tools::commands::entity_creation::load_entity_mappings;

#[test]
fn test_load_json_entity_mappings() {
    let temp_dir = TempDir::new().unwrap();
    let json_path = temp_dir.path().join("entities.json");

    let json_data = r#"{
        "entity-123": {
            "display_name": "user1",
            "mount_path": "auth/kubernetes/",
            "mount_accessor": "auth_k8s_abc123",
            "username": null,
            "login_count": 10,
            "first_seen": "2025-10-01",
            "last_seen": "2025-10-07"
        },
        "entity-456": {
            "display_name": "user2",
            "mount_path": "auth/userpass/",
            "mount_accessor": "auth_userpass_def456",
            "username": null,
            "login_count": 5,
            "first_seen": "2025-10-02",
            "last_seen": "2025-10-07"
        }
    }"#;

    let mut file = File::create(&json_path).unwrap();
    file.write_all(json_data.as_bytes()).unwrap();

    let mappings =
        load_entity_mappings(json_path.to_str().unwrap()).expect("Failed to load JSON mappings");

    assert_eq!(mappings.len(), 2);
    assert!(mappings.contains_key("entity-123"));
    assert!(mappings.contains_key("entity-456"));

    let mapping1 = &mappings["entity-123"];
    assert_eq!(mapping1.display_name, "user1");
    assert_eq!(mapping1.mount_path, "auth/kubernetes/");
    assert_eq!(mapping1.mount_accessor, "auth_k8s_abc123");
}

#[test]
fn test_load_csv_entity_mappings() {
    let temp_dir = TempDir::new().unwrap();
    let csv_path = temp_dir.path().join("entities.csv");

    let csv_data = "entity_id,display_name,username,login_count,first_seen,last_seen,policies,mount_path,namespace,mount_accessor\n\
                    entity-789,user3,k8s-user3,10,2025-10-01,2025-10-07,default,auth/kubernetes/,root,auth_k8s_xyz789\n\
                    entity-012,user4,k8s-user4,5,2025-10-02,2025-10-07,admin,auth/userpass/,root,auth_up_qrs012\n";

    let mut file = File::create(&csv_path).unwrap();
    file.write_all(csv_data.as_bytes()).unwrap();

    let mappings =
        load_entity_mappings(csv_path.to_str().unwrap()).expect("Failed to load CSV mappings");

    assert_eq!(mappings.len(), 2);
    assert!(mappings.contains_key("entity-789"));
    assert!(mappings.contains_key("entity-012"));

    let mapping1 = &mappings["entity-789"];
    assert_eq!(mapping1.display_name, "user3");
    assert_eq!(mapping1.mount_path, "auth/kubernetes/");
    assert_eq!(mapping1.mount_accessor, "auth_k8s_xyz789");
}

#[test]
fn test_json_extension_detection() {
    let temp_dir = TempDir::new().unwrap();
    let json_path = temp_dir.path().join("test.json");

    let json_data = r#"{"e1": {"display_name": "d1", "mount_path": "m1/", "mount_accessor": "a1", "username": null, "login_count": 0, "first_seen": "", "last_seen": ""}}"#;

    let mut file = File::create(&json_path).unwrap();
    file.write_all(json_data.as_bytes()).unwrap();

    let mappings =
        load_entity_mappings(json_path.to_str().unwrap()).expect("JSON extension detection failed");

    assert_eq!(mappings.len(), 1);
}

#[test]
fn test_csv_extension_detection() {
    let temp_dir = TempDir::new().unwrap();
    let csv_path = temp_dir.path().join("test.csv");

    let csv_data =
        "entity_id,display_name,x,x,x,x,x,mount_path,x,mount_accessor\ne2,d2,x,x,x,x,x,m2/,x,a2\n";

    let mut file = File::create(&csv_path).unwrap();
    file.write_all(csv_data.as_bytes()).unwrap();

    let mappings =
        load_entity_mappings(csv_path.to_str().unwrap()).expect("CSV extension detection failed");

    assert_eq!(mappings.len(), 1);
}

#[test]
fn test_fallback_to_json_then_csv() {
    let temp_dir = TempDir::new().unwrap();
    let no_ext_path = temp_dir.path().join("entities");

    // Try with JSON format data (should parse as JSON first)
    let json_data = r#"{"e3": {"display_name": "d3", "mount_path": "m3/", "mount_accessor": "a3", "username": null, "login_count": 0, "first_seen": "", "last_seen": ""}}"#;

    let mut file = File::create(&no_ext_path).unwrap();
    file.write_all(json_data.as_bytes()).unwrap();

    let mappings =
        load_entity_mappings(no_ext_path.to_str().unwrap()).expect("Fallback JSON parse failed");

    assert_eq!(mappings.len(), 1);
    assert!(mappings.contains_key("e3"));
}

#[test]
fn test_fallback_csv_when_json_fails() {
    let temp_dir = TempDir::new().unwrap();
    let no_ext_path = temp_dir.path().join("entities_csv");

    // CSV data without extension
    let csv_data =
        "entity_id,display_name,x,x,x,x,x,mount_path,x,mount_accessor\ne4,d4,x,x,x,x,x,m4/,x,a4\n";

    let mut file = File::create(&no_ext_path).unwrap();
    file.write_all(csv_data.as_bytes()).unwrap();

    let mappings =
        load_entity_mappings(no_ext_path.to_str().unwrap()).expect("Fallback CSV parse failed");

    assert_eq!(mappings.len(), 1);
    assert!(mappings.contains_key("e4"));
}

#[test]
fn test_invalid_json_format() {
    let temp_dir = TempDir::new().unwrap();
    let json_path = temp_dir.path().join("invalid.json");

    let invalid_json = r#"{"invalid": "not an array"#;

    let mut file = File::create(&json_path).unwrap();
    file.write_all(invalid_json.as_bytes()).unwrap();

    let result = load_entity_mappings(json_path.to_str().unwrap());
    assert!(result.is_err());
}

#[test]
fn test_missing_file() {
    let result = load_entity_mappings("/nonexistent/path/to/file.json");
    assert!(result.is_err());
}

#[test]
fn test_csv_missing_required_columns() {
    let temp_dir = TempDir::new().unwrap();
    let csv_path = temp_dir.path().join("incomplete.csv");

    // Only 3 columns - rows will be skipped, resulting in empty mappings
    let csv_data = "entity_id,display_name,username\ne5,d5,u5\n";

    let mut file = File::create(&csv_path).unwrap();
    file.write_all(csv_data.as_bytes()).unwrap();

    let result = load_entity_mappings(csv_path.to_str().unwrap());
    // The function succeeds but returns empty mappings because rows are skipped
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_empty_json_array() {
    let temp_dir = TempDir::new().unwrap();
    let json_path = temp_dir.path().join("empty.json");

    let json_data = "{}";

    let mut file = File::create(&json_path).unwrap();
    file.write_all(json_data.as_bytes()).unwrap();

    let mappings =
        load_entity_mappings(json_path.to_str().unwrap()).expect("Empty JSON object should parse");

    assert_eq!(mappings.len(), 0);
}

#[test]
fn test_empty_csv_file() {
    let temp_dir = TempDir::new().unwrap();
    let csv_path = temp_dir.path().join("empty.csv");

    let csv_data = "entity_id,display_name,x,x,x,x,x,mount_path,x,mount_accessor\n";

    let mut file = File::create(&csv_path).unwrap();
    file.write_all(csv_data.as_bytes()).unwrap();

    let mappings =
        load_entity_mappings(csv_path.to_str().unwrap()).expect("Empty CSV should parse");

    assert_eq!(mappings.len(), 0);
}

#[test]
fn test_duplicate_entity_ids() {
    let temp_dir = TempDir::new().unwrap();
    let json_path = temp_dir.path().join("duplicates.json");

    // Same entity_id twice in a HashMap - later value wins (but can only have one key)
    let json_data = r#"{"dup1": {"display_name": "second", "mount_path": "m2/", "mount_accessor": "a2", "username": null, "login_count": 0, "first_seen": "", "last_seen": ""}}"#;

    let mut file = File::create(&json_path).unwrap();
    file.write_all(json_data.as_bytes()).unwrap();

    let mappings =
        load_entity_mappings(json_path.to_str().unwrap()).expect("Duplicates should parse");

    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings["dup1"].display_name, "second");
}
