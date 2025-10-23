//! Token lookup abuse detection.
//!
//! Identifies entities performing excessive token lookup operations,
//! which can indicate misconfigured applications or potential security issues.
//! Supports multi-file analysis for pattern detection over time.
//!
//! # Usage
//!
//! ```bash
//! # Single file with default threshold (100 lookups per entity)
//! vault-audit token-lookup-abuse audit.log
//!
//! # Multi-day analysis with custom threshold
//! vault-audit token-lookup-abuse logs/*.log --threshold 500
//! ```
//!
//! # Output
//!
//! Displays entities exceeding the lookup threshold with:
//! - Entity ID and display name
//! - Total lookup operations
//! - Time range (first seen to last seen)
//! - Rate (lookups per hour)
//!
//! Helps identify:
//! - Applications polling tokens too frequently
//! - Misconfigured token renewal logic
//! - Potential reconnaissance activity

use crate::audit::types::AuditEntry;
use crate::utils::progress::ProgressBar;
use crate::utils::reader::open_file;
use crate::utils::time::parse_timestamp;
use anyhow::Result;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};

/// Tracks token lookup statistics for an entity
#[derive(Debug)]
struct TokenData {
    lookups: usize,
    first_seen: String,
    last_seen: String,
}

impl TokenData {
    fn new(timestamp: String) -> Self {
        Self {
            lookups: 1,
            first_seen: timestamp.clone(),
            last_seen: timestamp,
        }
    }
}

fn calculate_time_span_hours(first_seen: &str, last_seen: &str) -> f64 {
    match (parse_timestamp(first_seen), parse_timestamp(last_seen)) {
        (Ok(first), Ok(last)) => {
            let duration = last.signed_duration_since(first);
            duration.num_seconds() as f64 / 3600.0
        }
        _ => 0.0,
    }
}

fn format_number(n: usize) -> String {
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

pub fn run(log_files: &[String], threshold: usize) -> Result<()> {
    // entity_id -> accessor -> TokenData
    let mut patterns: HashMap<String, HashMap<String, TokenData>> = HashMap::new();
    let mut total_lines = 0;
    let mut lookup_lines = 0;

    // Process each log file sequentially
    for (file_idx, log_file) in log_files.iter().enumerate() {
        eprintln!(
            "[{}/{}] Processing: {}",
            file_idx + 1,
            log_files.len(),
            log_file
        );

        // Get file size for progress tracking
        let file_size = std::fs::metadata(log_file).ok().map(|m| m.len() as usize);
        let mut progress = if let Some(size) = file_size {
            ProgressBar::new(size, "Processing")
        } else {
            ProgressBar::new_spinner("Processing")
        };

        let file = open_file(log_file)?;
        let reader = BufReader::new(file);

        let mut file_lines = 0;
        let mut bytes_read = 0;

        for line in reader.lines() {
            file_lines += 1;
            total_lines += 1;
            let line = line?;
            bytes_read += line.len() + 1; // +1 for newline

            // Update progress every 10k lines for smooth animation
            if file_lines % 10_000 == 0 {
                if let Some(size) = file_size {
                    progress.update(bytes_read.min(size)); // Cap at file size
                } else {
                    progress.update(file_lines);
                }
            }

            let entry: AuditEntry = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Filter for token lookup-self operations
            let request = match &entry.request {
                Some(r) => r,
                None => continue,
            };

            let path = match &request.path {
                Some(p) => p.as_str(),
                None => continue,
            };

            if path != "auth/token/lookup-self" {
                continue;
            }

            let auth = match &entry.auth {
                Some(a) => a,
                None => continue,
            };

            let entity_id = match &auth.entity_id {
                Some(id) => id.as_str(),
                None => continue,
            };

            let accessor = match &auth.accessor {
                Some(a) => a.clone(),
                None => continue,
            };

            lookup_lines += 1;

            let entity_map = patterns.entry(entity_id.to_string()).or_default();

            entity_map
                .entry(accessor)
                .and_modify(|data| {
                    data.lookups += 1;
                    data.last_seen = entry.time.clone();
                })
                .or_insert_with(|| TokenData::new(entry.time.clone()));
        }

        // Ensure 100% progress for this file
        if let Some(size) = file_size {
            progress.update(size);
        }

        progress.finish_with_message(&format!(
            "Processed {} lines from this file",
            format_number(file_lines)
        ));
    }

    eprintln!(
        "\nTotal: Processed {} lines, found {} lookup-self operations",
        format_number(total_lines),
        format_number(lookup_lines)
    );

    // Find entities with excessive lookups
    let mut excessive_patterns = Vec::new();

    for (entity_id, tokens) in &patterns {
        for (accessor, data) in tokens {
            if data.lookups >= threshold {
                let time_span = calculate_time_span_hours(&data.first_seen, &data.last_seen);
                let lookups_per_hour = if time_span > 0.0 {
                    data.lookups as f64 / time_span
                } else {
                    0.0
                };

                // Truncate accessor for display
                let accessor_display = if accessor.len() > 23 {
                    format!("{}...", &accessor[..20])
                } else {
                    accessor.clone()
                };

                excessive_patterns.push((
                    entity_id.clone(),
                    accessor_display,
                    data.lookups,
                    time_span,
                    lookups_per_hour,
                    data.first_seen.clone(),
                    data.last_seen.clone(),
                ));
            }
        }
    }

    // Sort by number of lookups (descending)
    excessive_patterns.sort_by(|a, b| b.2.cmp(&a.2));

    // Print summary
    println!("\n{}", "=".repeat(120));
    println!("Token Lookup Pattern Analysis");
    println!("{}", "=".repeat(120));
    println!("\nTotal Entities: {}", format_number(patterns.len()));
    println!(
        "Entities with ≥{} lookups on same token: {}",
        threshold,
        format_number(excessive_patterns.len())
    );

    if !excessive_patterns.is_empty() {
        let top = 20;
        println!("\nTop {} Entities with Excessive Token Lookups:", top);
        println!("{}", "-".repeat(120));
        println!(
            "{:<40} {:<25} {:>10} {:>12} {:>15}",
            "Entity ID", "Token Accessor", "Lookups", "Time Span", "Rate"
        );
        println!(
            "{:<40} {:<25} {:>10} {:>12} {:>15}",
            "", "", "", "(hours)", "(lookups/hr)"
        );
        println!("{}", "-".repeat(120));

        for (entity_id, accessor, lookups, time_span, rate, _first, _last) in
            excessive_patterns.iter().take(top)
        {
            println!(
                "{:<40} {:<25} {:>10} {:>12.1} {:>15.1}",
                entity_id,
                accessor,
                format_number(*lookups),
                time_span,
                rate
            );
        }

        // Statistics
        let total_excessive_lookups: usize = excessive_patterns.iter().map(|p| p.2).sum();
        let avg_lookups = total_excessive_lookups as f64 / excessive_patterns.len() as f64;
        let max_lookups = excessive_patterns[0].2;

        println!("\n{}", "-".repeat(120));
        println!(
            "Total Excessive Lookups: {}",
            format_number(total_excessive_lookups)
        );
        println!("Average Lookups per Entity: {:.1}", avg_lookups);
        println!(
            "Maximum Lookups (single token): {}",
            format_number(max_lookups)
        );

        // Find highest rate
        let mut by_rate = excessive_patterns.clone();
        by_rate.sort_by(|a, b| b.4.partial_cmp(&a.4).unwrap_or(std::cmp::Ordering::Equal));

        if by_rate[0].4 > 0.0 {
            println!("\nHighest Rate: {:.1} lookups/hour", by_rate[0].4);
            println!("  Entity: {}", by_rate[0].0);
            println!("  Lookups: {}", format_number(by_rate[0].2));
        }
    }

    println!("{}", "=".repeat(120));

    Ok(())
}
