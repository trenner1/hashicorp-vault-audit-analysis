use vault_audit_tools::commands::entity_list::format_number;

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
    assert_eq!(format_number(1000), "1,000");
    assert_eq!(format_number(1234), "1,234");
    assert_eq!(format_number(9999), "9,999");
}

#[test]
fn test_format_number_millions() {
    assert_eq!(format_number(1000000), "1,000,000");
    assert_eq!(format_number(1234567), "1,234,567");
}

#[test]
fn test_format_number_large() {
    assert_eq!(format_number(1234567890), "1,234,567,890");
}

#[test]
fn test_format_number_edge_cases() {
    assert_eq!(format_number(1), "1");
    assert_eq!(format_number(10), "10");
    assert_eq!(format_number(100), "100");
    assert_eq!(format_number(10000), "10,000");
    assert_eq!(format_number(100000), "100,000");
}
