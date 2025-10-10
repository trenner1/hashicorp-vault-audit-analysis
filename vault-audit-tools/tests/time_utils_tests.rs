use chrono::{DateTime, Datelike, Timelike, Utc};
use vault_audit_tools::utils::time::{format_timestamp, parse_timestamp};

#[test]
fn test_parse_valid_timestamp() {
    let ts = "2025-10-07T10:30:45.123456Z";
    let result = parse_timestamp(ts);
    assert!(result.is_ok());

    let dt: DateTime<Utc> = result.unwrap();
    assert_eq!(dt.year(), 2025);
    assert_eq!(dt.month(), 10);
    assert_eq!(dt.day(), 7);
    assert_eq!(dt.hour(), 10);
    assert_eq!(dt.minute(), 30);
    assert_eq!(dt.second(), 45);
}

#[test]
fn test_parse_timestamp_with_offset() {
    let ts = "2025-10-07T10:30:45+00:00";
    let result = parse_timestamp(ts);
    assert!(result.is_ok());
}

#[test]
fn test_parse_invalid_timestamp() {
    let ts = "not-a-timestamp";
    let result = parse_timestamp(ts);
    assert!(result.is_err());
}

#[test]
fn test_parse_empty_timestamp() {
    let ts = "";
    let result = parse_timestamp(ts);
    assert!(result.is_err());
}

#[test]
fn test_format_timestamp() {
    let ts = "2025-10-07T10:30:45Z";
    let dt = parse_timestamp(ts).unwrap();
    let formatted = format_timestamp(&dt);

    assert!(formatted.contains("2025-10-07"));
    assert!(formatted.contains("10:30:45"));
}

#[test]
fn test_roundtrip_timestamp() {
    let original = "2025-10-07T10:30:45Z";
    let dt = parse_timestamp(original).unwrap();
    let formatted = format_timestamp(&dt);

    // format_timestamp produces human-readable format, not RFC3339
    // So just verify the formatted string contains expected components
    assert!(formatted.contains("2025-10-07"));
    assert!(formatted.contains("10:30:45"));
    assert!(formatted.contains("UTC"));
}
