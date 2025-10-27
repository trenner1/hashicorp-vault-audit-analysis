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
use crate::utils::format::format_number;
use crate::utils::processor::{ProcessingMode, ProcessorBuilder};
use anyhow::Result;
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct GapsState {
    operations_by_type: HashMap<String, usize>,
    paths_accessed: HashMap<String, usize>,
    no_entity_operations: usize,
}

impl GapsState {
    fn new() -> Self {
        Self {
            operations_by_type: HashMap::new(),
            paths_accessed: HashMap::new(),
            no_entity_operations: 0,
        }
    }

    fn merge(mut self, other: Self) -> Self {
        // Merge operations_by_type
        for (op, count) in other.operations_by_type {
            *self.operations_by_type.entry(op).or_insert(0) += count;
        }

        // Merge paths_accessed
        for (path, count) in other.paths_accessed {
            *self.paths_accessed.entry(path).or_insert(0) += count;
        }

        // Merge counters
        self.no_entity_operations += other.no_entity_operations;

        self
    }
}

pub fn run(log_files: &[String], _window_seconds: u64) -> Result<()> {
    let processor = ProcessorBuilder::new()
        .mode(ProcessingMode::Auto)
        .progress_label("Processing".to_string())
        .build();

    let (result, stats) = processor.process_files_streaming(
        log_files,
        |entry: &AuditEntry, state: &mut GapsState| {
            // Check for no entity
            if entry.entity_id().is_some() {
                return;
            }

            state.no_entity_operations += 1;

            // Track data
            if let Some(op) = entry.operation() {
                *state.operations_by_type.entry(op.to_string()).or_insert(0) += 1;
            }

            if let Some(path) = entry.path() {
                *state.paths_accessed.entry(path.to_string()).or_insert(0) += 1;
            }
        },
        GapsState::merge,
        GapsState::new(),
    )?;

    let total_lines = stats.total_lines;
    let no_entity_operations = result.no_entity_operations;
    let operations_by_type = result.operations_by_type;
    let paths_accessed = result.paths_accessed;

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
    println!("{:<70} {:>15} {:>15}", "Path", "Count", "% of No-Entity");
    println!("{}", "-".repeat(100));

    let mut sorted_paths: Vec<_> = paths_accessed.iter().collect();
    sorted_paths.sort_by(|a, b| b.1.cmp(a.1));

    for (path, count) in sorted_paths.iter().take(30) {
        let percentage = (**count as f64 / no_entity_operations as f64) * 100.0;
        let display_path = if path.len() > 68 {
            format!("{}...", &path[..65])
        } else {
            (*path).to_string()
        };
        println!(
            "{:<70} {:>15} {:>14.2}%",
            display_path,
            format_number(**count),
            percentage
        );
    }

    println!("\n{}", "=".repeat(100));

    Ok(())
}
