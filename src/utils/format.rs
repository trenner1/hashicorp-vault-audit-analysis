//! Number and text formatting utilities.
//!
//! This module provides common formatting functions used across commands
//! for consistent output presentation.

/// Formats a number with comma separators for thousands.
///
/// # Examples
///
/// ```
/// use vault_audit_tools::utils::format::format_number;
///
/// assert_eq!(format_number(1234), "1,234");
/// assert_eq!(format_number(1234567), "1,234,567");
/// assert_eq!(format_number(42), "42");
/// ```
pub fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(1), "1");
        assert_eq!(format_number(12), "12");
        assert_eq!(format_number(123), "123");
        assert_eq!(format_number(1234), "1,234");
        assert_eq!(format_number(12345), "12,345");
        assert_eq!(format_number(123_456), "123,456");
        assert_eq!(format_number(1_234_567), "1,234,567");
        assert_eq!(format_number(12_345_678), "12,345,678");
        assert_eq!(format_number(123_456_789), "123,456,789");
        assert_eq!(format_number(1_000_000_000), "1,000,000,000");
    }

    #[test]
    fn test_format_number_large() {
        assert_eq!(
            format_number(usize::MAX),
            format!("{:}", usize::MAX)
                .chars()
                .rev()
                .enumerate()
                .fold(String::new(), |mut acc, (i, c)| {
                    if i > 0 && i % 3 == 0 {
                        acc.push(',');
                    }
                    acc.push(c);
                    acc
                })
                .chars()
                .rev()
                .collect::<String>()
        );
    }
}
