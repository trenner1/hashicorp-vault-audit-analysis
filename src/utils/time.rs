use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

/// Parse a timestamp string from Vault audit logs
#[allow(dead_code)]
pub fn parse_timestamp(ts: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts)
        .context("Failed to parse timestamp")
        .map(|dt| dt.with_timezone(&Utc))
}

/// Format a timestamp for display
#[allow(dead_code)]
pub fn format_timestamp(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Calculate duration between two timestamps in human-readable format
#[allow(dead_code)]
pub fn duration_human(start: &DateTime<Utc>, end: &DateTime<Utc>) -> String {
    let duration = end.signed_duration_since(*start);
    let seconds = duration.num_seconds();

    if seconds < 60 {
        format!("{} seconds", seconds)
    } else if seconds < 3600 {
        format!("{} minutes", seconds / 60)
    } else if seconds < 86400 {
        format!("{:.1} hours", seconds as f64 / 3600.0)
    } else {
        format!("{:.1} days", seconds as f64 / 86400.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn test_parse_timestamp() {
        let ts = "2025-10-06T07:26:03.801191678Z";
        let dt = parse_timestamp(ts).unwrap();
        assert_eq!(dt.year(), 2025);
        assert_eq!(dt.month(), 10);
        assert_eq!(dt.day(), 6);
    }

    #[test]
    fn test_duration_human() {
        let start = parse_timestamp("2025-10-06T07:26:03Z").unwrap();
        let end = parse_timestamp("2025-10-06T08:26:03Z").unwrap();
        let duration = duration_human(&start, &end);
        assert!(duration.contains("1.0 hours"));
    }
}
