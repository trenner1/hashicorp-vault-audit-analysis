//! Entity timeline visualization command.
//!
//! ⚠️ **DEPRECATED**: Use `entity-analysis timeline` instead.
//!
//! ```bash
//! # Old (deprecated):
//! vault-audit entity-timeline logs/*.log --entity-id abc-123-def
//!
//! # New (recommended):
//! vault-audit entity-analysis timeline --entity-id abc-123-def logs/*.log
//! ```
//!
//! See [`entity_analysis`](crate::commands::entity_analysis) for the unified command.
//!
//! ---
//!
//! Generates a detailed timeline of all operations performed by a specific entity,
//! useful for understanding entity behavior and troubleshooting issues.
//! Supports multi-file analysis to track entities across multiple days.
//!
//! # Usage
//!
//! ```bash
//! # Single file
//! vault-audit entity-timeline audit.log --entity-id abc-123-def
//!
//! # Multi-day timeline
//! vault-audit entity-timeline day1.log day2.log day3.log --entity-id abc-123-def
//! ```
//!
//! # Output
//!
//! Displays a chronological view of the entity's activity:
//! - Timestamp
//! - Operation type (read, write, list, etc.)
//! - Path accessed
//! - Response status
//!
//! Also provides:
//! - Activity summary (operations by type)
//! - Time-based patterns (hourly distribution)
//! - Mount point usage
//! - First and last seen timestamps

use crate::audit::types::AuditEntry;
use crate::utils::format::format_number;
use crate::utils::progress::ProgressBar;
use crate::utils::reader::open_file;
use anyhow::Result;
use chrono::{DateTime, Timelike, Utc};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};

#[derive(Clone)]
#[allow(dead_code)]
struct Operation {
    timestamp: DateTime<Utc>,
    path: String,
    op: String,
}

pub fn run(log_files: &[String], entity_id: &str, display_name: Option<&String>) -> Result<()> {
    println!("Analyzing timeline for entity: {}", entity_id);
    if let Some(name) = display_name {
        println!("Display name: {}", name);
    }
    println!();

    let mut operations_by_hour: HashMap<String, HashMap<String, usize>> = HashMap::new();
    let mut operations_by_type: HashMap<String, usize> = HashMap::new();
    let mut paths_accessed: HashMap<String, usize> = HashMap::new();
    let mut operations_timeline: Vec<Operation> = Vec::new();
    let mut total_lines = 0;
    let mut entity_operations = 0;

    // Process each log file sequentially
    for (file_idx, log_file) in log_files.iter().enumerate() {
        eprintln!(
            "[{}/{}] Processing: {}",
            file_idx + 1,
            log_files.len(),
            log_file
        );

        // Count lines in file first for accurate progress tracking
        eprintln!("Scanning file to determine total lines...");
        let total_file_lines = crate::utils::parallel::count_file_lines(log_file)?;

        let progress = ProgressBar::new(total_file_lines, "Processing");

        let file = open_file(log_file)?;
        let reader = BufReader::new(file);

        let mut file_lines = 0;

        for line in reader.lines() {
            file_lines += 1;
            total_lines += 1;
            let line = line?;

            if file_lines % 10_000 == 0 {
                progress.update(file_lines);
            }

            let entry: AuditEntry = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Check if this is our entity
            let entry_entity_id = match &entry.auth {
                Some(auth) => match &auth.entity_id {
                    Some(id) => id.as_str(),
                    None => continue,
                },
                None => continue,
            };

            if entry_entity_id != entity_id {
                continue;
            }

            entity_operations += 1;

            let path = entry
                .request
                .as_ref()
                .and_then(|r| r.path.as_deref())
                .unwrap_or("")
                .to_string();
            let operation = entry
                .request
                .as_ref()
                .and_then(|r| r.operation.as_deref())
                .unwrap_or("")
                .to_string();

            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&entry.time) {
                let ts_utc = ts.with_timezone(&Utc);

                // Track by hour
                let hour_key = ts_utc.format("%Y-%m-%d %H:00").to_string();
                let hour_ops = operations_by_hour.entry(hour_key).or_default();
                *hour_ops.entry("total".to_string()).or_insert(0) += 1;
                *hour_ops.entry(operation.clone()).or_insert(0) += 1;

                // Store operation for timeline
                operations_timeline.push(Operation {
                    timestamp: ts_utc,
                    path: path.clone(),
                    op: operation.clone(),
                });
            }

            // Track operation types
            *operations_by_type.entry(operation).or_insert(0) += 1;

            // Track paths
            *paths_accessed.entry(path).or_insert(0) += 1;
        }

        // Ensure 100% progress for this file
        progress.update(total_file_lines);

        progress.finish_with_message(&format!(
            "Processed {} lines from this file",
            format_number(file_lines)
        ));
    }

    eprintln!(
        "\nTotal: Processed {} lines, found {} operations for entity: {}",
        format_number(total_lines),
        format_number(entity_operations),
        entity_id
    );

    if entity_operations == 0 {
        println!("\nNo operations found for this entity!");
        return Ok(());
    }

    // Sort timeline
    operations_timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Calculate time span
    let (first_op, last_op, time_span_hours) = if operations_timeline.is_empty() {
        return Ok(());
    } else {
        let first = operations_timeline.first().unwrap().timestamp;
        let last = operations_timeline.last().unwrap().timestamp;
        let span = (last - first).num_seconds() as f64 / 3600.0;
        (first, last, span)
    };

    // Analysis and reporting
    println!("\n{}", "=".repeat(100));
    println!("TIMELINE ANALYSIS FOR: {}", entity_id);
    println!("{}", "=".repeat(100));

    // 1. Summary statistics
    println!("\n1. SUMMARY STATISTICS");
    println!("{}", "-".repeat(100));
    println!("Total operations: {}", format_number(entity_operations));
    println!(
        "Time span: {:.2} hours ({:.2} days)",
        time_span_hours,
        time_span_hours / 24.0
    );
    println!(
        "Average rate: {:.1} operations/hour ({:.2}/minute)",
        entity_operations as f64 / time_span_hours,
        entity_operations as f64 / time_span_hours / 60.0
    );
    println!("First operation: {}", first_op.format("%Y-%m-%d %H:%M:%S"));
    println!("Last operation: {}", last_op.format("%Y-%m-%d %H:%M:%S"));

    // 2. Operation type distribution
    println!("\n2. OPERATION TYPE DISTRIBUTION");
    println!("{}", "-".repeat(100));
    println!("{:<30} {:<15} {:<15}", "Operation", "Count", "Percentage");
    println!("{}", "-".repeat(100));

    let mut sorted_ops: Vec<_> = operations_by_type.iter().collect();
    sorted_ops.sort_by(|a, b| b.1.cmp(a.1));

    for (op, count) in sorted_ops {
        let percentage = (*count as f64 / entity_operations as f64) * 100.0;
        println!(
            "{:<30} {:<15} {:<15.2}%",
            op,
            format_number(*count),
            percentage
        );
    }

    // 3. Top paths accessed
    println!("\n3. TOP 30 PATHS ACCESSED");
    println!("{}", "-".repeat(100));
    println!("{:<70} {:<15} {:<15}", "Path", "Count", "Percentage");
    println!("{}", "-".repeat(100));

    let mut sorted_paths: Vec<_> = paths_accessed.iter().collect();
    sorted_paths.sort_by(|a, b| b.1.cmp(a.1));

    for (path, count) in sorted_paths.iter().take(30) {
        let percentage = (**count as f64 / entity_operations as f64) * 100.0;
        let display_path = if path.len() > 68 {
            format!("{}...", &path[..65])
        } else {
            (*path).clone()
        };
        println!(
            "{:<70} {:<15} {:<15.2}%",
            display_path,
            format_number(**count),
            percentage
        );
    }

    // 4. Hourly activity pattern
    println!("\n4. HOURLY ACTIVITY PATTERN (Top 30 Hours)");
    println!("{}", "-".repeat(100));
    println!(
        "{:<20} {:<12} {:<10} {:<10} {:<10} {:<10}",
        "Hour", "Total Ops", "read", "update", "list", "Other"
    );
    println!("{}", "-".repeat(100));

    let mut sorted_hours: Vec<_> = operations_by_hour.iter().collect();
    sorted_hours.sort_by(|a, b| {
        let a_total = a.1.get("total").unwrap_or(&0);
        let b_total = b.1.get("total").unwrap_or(&0);
        b_total.cmp(a_total)
    });

    for (hour, ops) in sorted_hours.iter().take(30) {
        let total = *ops.get("total").unwrap_or(&0);
        let read = *ops.get("read").unwrap_or(&0);
        let update = *ops.get("update").unwrap_or(&0);
        let list_operations = *ops.get("list").unwrap_or(&0);
        let other = total - read - update - list_operations;

        println!(
            "{:<20} {:<12} {:<10} {:<10} {:<10} {:<10}",
            hour,
            format_number(total),
            format_number(read),
            format_number(update),
            format_number(list_operations),
            format_number(other)
        );
    }

    // 5. Activity distribution by hour of day
    println!("\n5. ACTIVITY DISTRIBUTION BY HOUR OF DAY");
    println!("{}", "-".repeat(100));

    let mut hour_of_day_stats: HashMap<u32, usize> = HashMap::new();
    for op in &operations_timeline {
        let hour = op.timestamp.hour();
        *hour_of_day_stats.entry(hour).or_insert(0) += 1;
    }

    println!("{:<10} {:<15} {:<50}", "Hour", "Operations", "Bar Chart");
    println!("{}", "-".repeat(100));

    let max_ops_in_hour = hour_of_day_stats.values().max().copied().unwrap_or(1);

    for hour in 0..24 {
        let ops = *hour_of_day_stats.get(&hour).unwrap_or(&0);
        let bar_length = if max_ops_in_hour > 0 {
            (ops * 50) / max_ops_in_hour
        } else {
            0
        };
        let bar = "█".repeat(bar_length);
        println!("{:02}:00     {:<15} {}", hour, format_number(ops), bar);
    }

    // 6. Peak activity analysis
    println!("\n6. PEAK ACTIVITY WINDOWS");
    println!("{}", "-".repeat(100));

    let mut window_counts: HashMap<DateTime<Utc>, usize> = HashMap::new();

    for op in &operations_timeline {
        // Round to 5-minute window
        let minute = (op.timestamp.minute() / 5) * 5;
        let window_start = op
            .timestamp
            .with_minute(minute)
            .unwrap()
            .with_second(0)
            .unwrap()
            .with_nanosecond(0)
            .unwrap();
        *window_counts.entry(window_start).or_insert(0) += 1;
    }

    let mut sorted_windows: Vec<_> = window_counts.iter().collect();
    sorted_windows.sort_by(|a, b| b.1.cmp(a.1));

    println!(
        "{:<25} {:<15} {:<20}",
        "5-Minute Window", "Operations", "Rate (ops/sec)"
    );
    println!("{}", "-".repeat(100));

    for (window, count) in sorted_windows.iter().take(20) {
        let rate = **count as f64 / 300.0;
        println!(
            "{:<25} {:<15} {:<20.3}",
            window.format("%Y-%m-%d %H:%M"),
            format_number(**count),
            rate
        );
    }

    // 7. Behavioral patterns
    println!("\n7. BEHAVIORAL PATTERNS");
    println!("{}", "-".repeat(100));

    if time_span_hours > 1.0 {
        let ops_per_hour = entity_operations as f64 / time_span_hours;
        if ops_per_hour > 100.0 {
            println!(
                "⚠️  HIGH FREQUENCY: {:.0} operations/hour suggests automated polling",
                ops_per_hour
            );
            println!("   Recommended action: Implement caching or increase polling interval");
        }

        // Check for token lookup abuse
        let token_lookup_paths: Vec<_> = paths_accessed
            .keys()
            .filter(|p| p.contains("token/lookup"))
            .collect();
        let total_token_lookups: usize = token_lookup_paths
            .iter()
            .map(|p| paths_accessed.get(*p).unwrap_or(&0))
            .sum();

        if total_token_lookups > 1000 {
            println!(
                "⚠️  TOKEN LOOKUP ABUSE: {} token lookups detected",
                format_number(total_token_lookups)
            );
            println!(
                "   Rate: {:.1} lookups/hour = {:.2} lookups/second",
                total_token_lookups as f64 / time_span_hours,
                total_token_lookups as f64 / time_span_hours / 3600.0
            );
            println!("   Recommended action: Implement client-side token TTL tracking");
        }

        // Check for path concentration
        if let Some((top_path, top_count)) = sorted_paths.first() {
            let top_path_pct = (**top_count as f64 / entity_operations as f64) * 100.0;
            if top_path_pct > 30.0 {
                println!(
                    "⚠️  PATH CONCENTRATION: {:.1}% of operations on single path",
                    top_path_pct
                );
                println!("   Path: {}", top_path);
                println!(
                    "   Recommended action: Review why this path is accessed {} times",
                    format_number(**top_count)
                );
            }
        }

        // Check for 24/7 activity
        let hours_with_activity = (0..24)
            .filter(|h| hour_of_day_stats.contains_key(h))
            .count();
        if hours_with_activity >= 20 {
            println!(
                "⚠️  24/7 ACTIVITY: Active in {}/24 hours",
                hours_with_activity
            );
            println!("   Suggests automated system or background process");
        }
    }

    println!("\n{}", "=".repeat(100));

    Ok(())
}
