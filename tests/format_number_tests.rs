// Test format_number function from utils module
// This function formats numbers with thousand separators (e.g., 1234567 -> "1,234,567")

use vault_audit_tools::utils::format::format_number;

#[test]
fn test_format_number_zero() {
    assert_eq!(format_number(0), "0");
}

#[test]
fn test_format_number_small() {
    assert_eq!(format_number(42), "42");
    assert_eq!(format_number(999), "999");
}

#[test]
fn test_format_number_thousands() {
    assert_eq!(format_number(1_000), "1,000");
    assert_eq!(format_number(1_234), "1,234");
    assert_eq!(format_number(9_999), "9,999");
}

#[test]
fn test_format_number_ten_thousands() {
    assert_eq!(format_number(10_000), "10,000");
    assert_eq!(format_number(12_345), "12,345");
    assert_eq!(format_number(99_999), "99,999");
}

#[test]
fn test_format_number_hundreds_of_thousands() {
    assert_eq!(format_number(100_000), "100,000");
    assert_eq!(format_number(123_456), "123,456");
    assert_eq!(format_number(999_999), "999,999");
}

#[test]
fn test_format_number_millions() {
    assert_eq!(format_number(1_000_000), "1,000,000");
    assert_eq!(format_number(1_234_567), "1,234,567");
    assert_eq!(format_number(9_999_999), "9,999,999");
}

#[test]
fn test_format_number_ten_millions() {
    assert_eq!(format_number(10_000_000), "10,000,000");
    assert_eq!(format_number(12_345_678), "12,345,678");
    assert_eq!(format_number(99_999_999), "99,999,999");
}

#[test]
fn test_format_number_hundreds_of_millions() {
    assert_eq!(format_number(100_000_000), "100,000,000");
    assert_eq!(format_number(123_456_789), "123,456,789");
    assert_eq!(format_number(999_999_999), "999,999,999");
}

#[test]
fn test_format_number_billions() {
    assert_eq!(format_number(1_000_000_000), "1,000,000,000");
    assert_eq!(format_number(1_234_567_890), "1,234,567,890");
}

#[test]
fn test_format_number_large() {
    // Test with usize::MAX to ensure no panic
    let formatted = format_number(usize::MAX);
    assert!(!formatted.is_empty());
    assert!(formatted.contains(','));

    // Verify the format is correct for a large known value
    let large_num = 18_446_744_073_709_551_615_usize; // usize::MAX on 64-bit
    if usize::BITS == 64 {
        assert_eq!(format_number(large_num), "18,446,744,073,709,551,615");
    }
}
