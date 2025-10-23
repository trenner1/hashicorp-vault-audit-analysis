//! KV usage comparison across time periods.
//!
//! ⚠️ **DEPRECATED**: Use `kv-analysis compare` instead.
//!
//! ```bash
//! # Old (deprecated):
//! vault-audit kv-compare old_usage.csv new_usage.csv
//!
//! # New (recommended):
//! vault-audit kv-analysis compare old_usage.csv new_usage.csv
//! ```
//!
//! See [`kv_analysis`](crate::commands::kv_analysis) for the unified command.
//!
//! ---
//!
//! Compares KV secrets engine usage between two CSV exports to identify
//! changes in access patterns over time.
//!
//! # Usage
//!
//! ```bash
//! # Generate two CSV files from different time periods
//! vault-audit kv-analyzer old-audit.log --output old-usage.csv
//! vault-audit kv-analyzer new-audit.log --output new-usage.csv
//!
//! # Compare them
//! vault-audit kv-compare old-usage.csv new-usage.csv
//! ```
//!
//! # Output
//!
//! Displays comparison metrics by mount point:
//! - Change in total operations
//! - Change in unique secrets accessed
//! - Change in entity count
//! - Percentage changes
//!
//! Helps identify:
//! - Growing or shrinking KV usage
//! - New secrets being accessed
//! - Secrets no longer used
//! - Changes in access patterns

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs::File;

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

/// Mount point usage statistics
struct MountData {
    operations: usize,
    paths: usize,
    entities: HashSet<String>,
}

fn analyze_mount(csvfile: &str) -> Result<Option<MountData>> {
    let file = match File::open(csvfile) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };

    let mut reader = csv::Reader::from_reader(file);
    let mut operations = 0;
    let mut paths = 0;
    let mut entities: HashSet<String> = HashSet::new();

    for result in reader.records() {
        let record = result?;

        // Get operations_count (column 2)
        if let Some(ops_str) = record.get(2) {
            if let Ok(ops) = ops_str.parse::<usize>() {
                operations += ops;
            }
        }

        paths += 1;

        // Get entity_ids (column 3)
        if let Some(entity_ids_str) = record.get(3) {
            for eid in entity_ids_str.split(',') {
                let trimmed = eid.trim();
                if !trimmed.is_empty() {
                    entities.insert(trimmed.to_string());
                }
            }
        }
    }

    if paths == 0 {
        return Ok(None);
    }

    Ok(Some(MountData {
        operations,
        paths,
        entities,
    }))
}

pub fn run(csv1: &str, csv2: &str) -> Result<()> {
    let csv_files = vec![csv1.to_string(), csv2.to_string()];

    println!("{}", "=".repeat(95));
    println!(
        "{:<20} {:<18} {:<18} {:<20}",
        "KV Mount", "Operations", "Unique Paths", "Unique Entities"
    );
    println!("{}", "=".repeat(95));

    let mut results = Vec::new();
    let mut total_ops = 0;
    let mut total_paths = 0;
    let mut all_entities: HashSet<String> = HashSet::new();

    for csv_file in &csv_files {
        // Extract mount name from filename
        let mount_name = std::path::Path::new(csv_file)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(csv_file);

        match analyze_mount(csv_file).context(format!("Failed to analyze {}", csv_file))? {
            Some(data) => {
                println!(
                    "{:<20} {:<18} {:<18} {:<20}",
                    mount_name,
                    format_number(data.operations),
                    format_number(data.paths),
                    format_number(data.entities.len())
                );

                total_ops += data.operations;
                total_paths += data.paths;
                all_entities.extend(data.entities.iter().cloned());

                results.push((mount_name.to_string(), data));
            }
            None => {
                println!("{:<20} {:<18}", mount_name, "(file not found)");
            }
        }
    }

    println!("{}", "=".repeat(95));
    println!(
        "{:<20} {:<18} {:<18} {:<20}",
        "TOTAL",
        format_number(total_ops),
        format_number(total_paths),
        format_number(all_entities.len())
    );
    println!("{}", "=".repeat(95));

    // Show percentage breakdown
    if !results.is_empty() {
        println!("\nPercentage Breakdown by Operations:");
        println!("{}", "-".repeat(50));

        // Sort by operations descending
        results.sort_by(|a, b| b.1.operations.cmp(&a.1.operations));

        for (mount, data) in results {
            let pct = if total_ops > 0 {
                (data.operations as f64 / total_ops as f64) * 100.0
            } else {
                0.0
            };
            println!("{:<20} {:>6.2}%", mount, pct);
        }
    }

    Ok(())
}
