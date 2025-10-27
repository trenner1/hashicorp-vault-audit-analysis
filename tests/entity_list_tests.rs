use vault_audit_tools::utils::format::format_number;

#[test]
fn test_format_number_zero() {
    assert_eq!(format_number(0), "0");
}

#[test]
fn test_format_number_small() {
    assert_eq!(format_number(123), "123");
    assert_eq!(format_number(999), "999");
}

#[test]
fn test_format_number_thousands() {
    assert_eq!(format_number(1_000), "1,000");
    assert_eq!(format_number(1_234), "1,234");
    assert_eq!(format_number(9_999), "9,999");
}

#[test]
fn test_format_number_millions() {
    assert_eq!(format_number(1_000_000), "1,000,000");
    assert_eq!(format_number(1_234_567), "1,234,567");
}

#[test]
fn test_format_number_large() {
    assert_eq!(format_number(1_234_567_890), "1,234,567,890");
}

#[test]
fn test_format_number_edge_cases() {
    assert_eq!(format_number(1), "1");
    assert_eq!(format_number(10), "10");
    assert_eq!(format_number(100), "100");
    assert_eq!(format_number(10_000), "10,000");
    assert_eq!(format_number(100_000), "100,000");
}
