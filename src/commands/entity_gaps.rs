//! Entity gaps analysis command.
//!
//! ⚠️ **DEPRECATED**: Use `entity-analysis gaps` instead.
//!
//! ```bash
//! # Old (deprecated):
//! vault-audit entity-gaps logs/*.log
//!
//! # New (recommended):
//! vault-audit entity-analysis gaps logs/*.log
//! ```
//!
//! See [`entity_analysis`](crate::commands::entity_analysis) for the unified command.
//!
//! ---
//!
//! Identifies operations that occur without an associated entity ID,
//! which can indicate unauthenticated requests or system operations.
//! Supports multi-file analysis for comprehensive coverage.
//!
//! # Usage
//!
//! ```bash
//! # Single file
//! vault-audit entity-gaps audit.log
//!
//! # Multi-day analysis
//! vault-audit entity-gaps logs/vault_audit.*.log
//! ```
//!
//! # Output
//!
//! Displays operations grouped by path that have no entity ID:
//! - Request path
//! - Total operations count
//! - Common operations (read, write, list, etc.)
//!
//! Helps identify:
//! - Public endpoints (health checks, metrics)
//! - System operations
//! - Potential authentication issues
//! - Unauthenticated access patterns

use crate::audit::types::AuditEntry;
use crate::utils::progress::ProgressBar;
use crate::utils::reader::open_file;
use anyhow::Result;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};

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

pub fn run(log_files: &[String], _window_seconds: u64) -> Result<()> {
    let mut operations_by_type: HashMap<String, usize> = HashMap::new();
    let mut paths_accessed: HashMap<String, usize> = HashMap::new();
    let mut total_lines = 0;
    let mut no_entity_operations = 0;

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
                    progress.update(bytes_read.min(size));
                } else {
                    progress.update(file_lines);
                }
            }

            let entry: AuditEntry = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Check for no entity
            if entry.entity_id().is_some() {
                continue;
            }

            no_entity_operations += 1;

            // Track data
            if let Some(op) = entry.operation() {
                *operations_by_type.entry(op.to_string()).or_insert(0) += 1;
            }

            if let Some(path) = entry.path() {
                *paths_accessed.entry(path.to_string()).or_insert(0) += 1;
            }
        }

        progress.finish_with_message(&format!(
            "Processed {} lines from this file",
            format_number(file_lines)
        ));
    }

    eprintln!("\nTotal: Processed {} lines", format_number(total_lines));
    eprintln!(
        "Found {} operations with no entity ID",
        format_number(no_entity_operations)
    );

    if no_entity_operations == 0 {
        println!("\nNo operations without entity ID found!");
        return Ok(());
    }

    println!("\n{}", "=".repeat(100));
    println!("NO-ENTITY OPERATIONS ANALYSIS");
    println!("{}", "=".repeat(100));

    println!("\n1. SUMMARY");
    println!("{}", "-".repeat(100));
    println!(
        "Total no-entity operations: {}",
        format_number(no_entity_operations)
    );
    println!(
        "Percentage of all operations: {:.2}%",
        (no_entity_operations as f64 / total_lines as f64) * 100.0
    );

    println!("\n2. OPERATION TYPE DISTRIBUTION");
    println!("{}", "-".repeat(100));
    println!("{:<30} {:<15} {:<15}", "Operation", "Count", "Percentage");
    println!("{}", "-".repeat(100));

    let mut sorted_ops: Vec<_> = operations_by_type.iter().collect();
    sorted_ops.sort_by(|a, b| b.1.cmp(a.1));

    for (op, count) in sorted_ops.iter().take(20) {
        let percentage = (**count as f64 / no_entity_operations as f64) * 100.0;
        println!(
            "{:<30} {:<15} {:<15.2}%",
            op,
            format_number(**count),
            percentage
        );
    }

    println!("\n3. TOP 30 PATHS ACCESSED");
    println!("{}", "-".repeat(100));
    println!("{:<70} {:<15} {:<15}", "Path", "Count", "% of No-Entity");
    println!("{}", "-".repeat(100));

    let mut sorted_paths: Vec<_> = paths_accessed.iter().collect();
    sorted_paths.sort_by(|a, b| b.1.cmp(a.1));

    for (path, count) in sorted_paths.iter().take(30) {
        let percentage = (**count as f64 / no_entity_operations as f64) * 100.0;
        let display_path = if path.len() > 68 {
            format!("{}...", &path[..65])
        } else {
            path.to_string()
        };
        println!(
            "{:<70} {:<15} {:<15.2}%",
            display_path,
            format_number(**count),
            percentage
        );
    }

    println!("\n{}", "=".repeat(100));

    Ok(())
}
