//! Unified token analysis command.
//!
//! Consolidates token operations tracking, abuse detection, and data export
//! into a single powerful command. Supports multi-file analysis (compressed
//! or uncompressed) for comprehensive token usage analysis.
//!
//! # Usage
//!
//! ```bash
//! # Overview of all token operations by entity
//! vault-audit token-analysis logs/*.log
//! vault-audit token-analysis logs/*.log.gz
//!
//! # Detect token lookup abuse (default threshold: 1000)
//! vault-audit token-analysis logs/*.log --abuse-threshold 1000
//!
//! # Filter specific operation types
//! vault-audit token-analysis logs/*.log --filter lookup
//! vault-audit token-analysis logs/*.log --filter create,renew
//!
//! # Export to CSV for further analysis
//! vault-audit token-analysis logs/*.log --export token_data.csv
//!
//! # Export only high-volume token accessors (individual tokens)
//! vault-audit token-analysis logs/*.log --min-operations 1000 --export high_volume_tokens.csv
//!
//! # Combine abuse detection with export
//! vault-audit token-analysis logs/*.log --abuse-threshold 500 --export abuse_patterns.csv
//! ```
//!
//! **Compressed File Support**: Automatically handles `.gz` and `.zst` files.
//!
//! # Understanding Entities vs Accessors
//!
//! - **Entity**: A user or service identity (e.g., "fg-PIOP0SRVDEVOPS")
//!   - One entity can have multiple tokens over time
//!   - Summary view shows per-entity totals
//!
//! - **Accessor**: A unique token identifier (individual token)
//!   - Each accessor belongs to one entity
//!   - CSV export shows per-accessor detail with timestamps
//!   - Example: An entity with 100k operations might have 3 accessors with 50k, 30k, 20k operations each
//!
//! # Output Modes
//!
//! ## Default: Operations Summary (Per-Entity)
//! Displays aggregated breakdown of all token operations by entity:
//! - lookup-self, renew-self, revoke-self, create, login, other
//! - Shows top 50 entities sorted by total operations
//! - One row per entity (combines all tokens for that entity)
//!
//! ## Abuse Detection Mode (--abuse-threshold)
//! Identifies entities exceeding lookup threshold:
//! - Entity details and lookup count
//! - Time range and rate (lookups/hour)
//! - Helps find misconfigured apps or compromised credentials
//!
//! ## Export Mode (--export) - Per-Accessor Detail
//! Generates CSV with per-token accessor granularity:
//! - entity_id, display_name, accessor (token identifier)
//! - operations, first_seen, last_seen, duration_hours
//! - Shows individual token lifecycle and usage patterns
//! - Use --min-operations to filter low-activity tokens
//! - First/last seen timestamps
//! - Duration

use crate::audit::types::AuditEntry;
use crate::utils::progress::ProgressBar;
use crate::utils::reader::open_file;
use crate::utils::time::parse_timestamp;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

/// Type alias for the complex return type from process_logs
type ProcessLogsResult = (
    HashMap<String, TokenOps>,
    HashMap<String, EntityAccessors>,
    usize,
);

/// Token operation statistics for a single entity
#[derive(Debug, Default)]
struct TokenOps {
    lookup_self: usize,
    renew_self: usize,
    revoke_self: usize,
    create: usize,
    login: usize,
    other: usize,
    display_name: Option<String>,
    username: Option<String>,
    first_seen: Option<String>,
    last_seen: Option<String>,
}

impl TokenOps {
    fn total(&self) -> usize {
        self.lookup_self
            + self.renew_self
            + self.revoke_self
            + self.create
            + self.login
            + self.other
    }

    fn update_timestamps(&mut self, timestamp: &str) {
        if self.first_seen.is_none() {
            self.first_seen = Some(timestamp.to_string());
        }
        self.last_seen = Some(timestamp.to_string());
    }
}

/// Token accessor-specific data for detailed analysis
#[derive(Debug, Default)]
struct AccessorData {
    operations: usize,
    first_seen: String,
    last_seen: String,
}

/// Tracks per-accessor token activity for an entity
#[derive(Debug, Default)]
struct EntityAccessors {
    accessors: HashMap<String, AccessorData>,
    display_name: Option<String>,
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

fn calculate_time_span_hours(first_seen: &str, last_seen: &str) -> f64 {
    match (parse_timestamp(first_seen), parse_timestamp(last_seen)) {
        (Ok(first), Ok(last)) => {
            let duration = last.signed_duration_since(first);
            duration.num_seconds() as f64 / 3600.0
        }
        _ => 0.0,
    }
}

/// Process audit logs and collect token operation data
fn process_logs(
    log_files: &[String],
    operation_filter: Option<&Vec<String>>,
) -> Result<ProcessLogsResult> {
    let mut token_ops: HashMap<String, TokenOps> = HashMap::new();
    let mut accessor_data: HashMap<String, EntityAccessors> = HashMap::new();
    let mut total_lines = 0;

    for (file_idx, log_file) in log_files.iter().enumerate() {
        eprintln!(
            "[{}/{}] Processing: {}",
            file_idx + 1,
            log_files.len(),
            log_file
        );

        let file_size = std::fs::metadata(log_file).ok().map(|m| m.len() as usize);
        let mut progress = if let Some(size) = file_size {
            ProgressBar::new(size, "Processing")
        } else {
            ProgressBar::new_spinner("Processing")
        };

        let mut file_lines = 0;
        let mut bytes_read = 0;

        let file = open_file(log_file)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            file_lines += 1;
            total_lines += 1;
            let line = line?;
            bytes_read += line.len() + 1;

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

            // Skip if no request or auth info
            let request = match entry.request {
                Some(r) => r,
                None => continue,
            };

            let auth = match entry.auth {
                Some(a) => a,
                None => continue,
            };

            let entity_id = match auth.entity_id {
                Some(ref id) if !id.is_empty() => id.clone(),
                _ => continue,
            };

            // Determine operation type
            let path = request.path.as_deref().unwrap_or("");
            let operation = request.operation.as_deref().unwrap_or("");

            let op_type = if path == "auth/token/lookup-self" {
                "lookup"
            } else if path == "auth/token/renew-self" {
                "renew"
            } else if path == "auth/token/revoke-self" {
                "revoke"
            } else if path == "auth/token/create" {
                "create"
            } else if path.starts_with("auth/") && operation == "update" {
                "login"
            } else if path.starts_with("auth/token/") {
                "other"
            } else {
                continue; // Not a token operation
            };

            // Apply operation filter if specified
            if let Some(filters) = operation_filter {
                if !filters.iter().any(|f| op_type.contains(f.as_str())) {
                    continue;
                }
            }

            // Update token operations summary
            let ops = token_ops.entry(entity_id.clone()).or_default();
            match op_type {
                "lookup" => ops.lookup_self += 1,
                "renew" => ops.renew_self += 1,
                "revoke" => ops.revoke_self += 1,
                "create" => ops.create += 1,
                "login" => ops.login += 1,
                _ => ops.other += 1,
            }

            if ops.display_name.is_none() {
                ops.display_name = auth.display_name.clone();
            }
            if ops.username.is_none() {
                ops.username = auth.metadata.as_ref().and_then(|m| {
                    m.get("username")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                });
            }
            ops.update_timestamps(&entry.time);

            // Track accessor-level data for detailed analysis
            if let Some(accessor) = auth.accessor {
                let entity_acc = accessor_data.entry(entity_id.clone()).or_default();
                if entity_acc.display_name.is_none() {
                    entity_acc.display_name = auth.display_name.clone();
                }

                let acc_data =
                    entity_acc
                        .accessors
                        .entry(accessor)
                        .or_insert_with(|| AccessorData {
                            operations: 0,
                            first_seen: entry.time.clone(),
                            last_seen: entry.time.clone(),
                        });
                acc_data.operations += 1;
                acc_data.last_seen = entry.time;
            }
        }

        progress.finish();
        eprintln!("  Processed {} lines", format_number(file_lines));
    }

    Ok((token_ops, accessor_data, total_lines))
}

/// Display operations summary
fn display_summary(token_ops: &HashMap<String, TokenOps>, total_lines: usize) {
    let mut ops_vec: Vec<_> = token_ops.iter().collect();
    ops_vec.sort_by(|a, b| b.1.total().cmp(&a.1.total()));

    // Calculate totals
    let total_ops: usize = ops_vec.iter().map(|(_, ops)| ops.total()).sum();
    let total_lookup: usize = ops_vec.iter().map(|(_, ops)| ops.lookup_self).sum();
    let total_renew: usize = ops_vec.iter().map(|(_, ops)| ops.renew_self).sum();
    let total_revoke: usize = ops_vec.iter().map(|(_, ops)| ops.revoke_self).sum();
    let total_create: usize = ops_vec.iter().map(|(_, ops)| ops.create).sum();
    let total_login: usize = ops_vec.iter().map(|(_, ops)| ops.login).sum();
    let total_other: usize = ops_vec.iter().map(|(_, ops)| ops.other).sum();

    println!("Total: Processed {} lines\n", format_number(total_lines));
    println!("{}", "=".repeat(150));
    println!(
        "{:<30} {:<25} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "Display Name",
        "Username",
        "Total",
        "Lookup",
        "Renew",
        "Revoke",
        "Create",
        "Login",
        "Other"
    );
    println!("{}", "=".repeat(150));

    // Show top 50
    for (_, ops) in ops_vec.iter().take(50) {
        let display = ops.display_name.as_deref().unwrap_or("");
        let username = ops.username.as_deref().unwrap_or("");

        println!(
            "{:<30} {:<25} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
            if display.len() > 30 {
                &display[..30]
            } else {
                display
            },
            if username.len() > 25 {
                &username[..25]
            } else {
                username
            },
            format_number(ops.total()),
            format_number(ops.lookup_self),
            format_number(ops.renew_self),
            format_number(ops.revoke_self),
            format_number(ops.create),
            format_number(ops.login),
            format_number(ops.other)
        );
    }

    println!("{}", "=".repeat(150));
    println!(
        "TOTAL (top 50)                                                       {:>10}",
        format_number(total_ops)
    );
    println!(
        "TOTAL ENTITIES                                                       {:>10}",
        format_number(token_ops.len())
    );
    println!("{}", "=".repeat(150));
    println!();
    println!("Operation Type Breakdown:");
    println!("{}", "-".repeat(60));
    println!(
        "Lookup (lookup-self):   {:>12}  ({:>5.1}%)",
        format_number(total_lookup),
        (total_lookup as f64 / total_ops as f64) * 100.0
    );
    println!(
        "Renew (renew-self):     {:>12}  ({:>5.1}%)",
        format_number(total_renew),
        (total_renew as f64 / total_ops as f64) * 100.0
    );
    println!(
        "Revoke (revoke-self):   {:>12}  ({:>5.1}%)",
        format_number(total_revoke),
        (total_revoke as f64 / total_ops as f64) * 100.0
    );
    println!(
        "Create (child token):   {:>12}  ({:>5.1}%)",
        format_number(total_create),
        (total_create as f64 / total_ops as f64) * 100.0
    );
    println!(
        "Login (auth token):     {:>12}  ({:>5.1}%)",
        format_number(total_login),
        (total_login as f64 / total_ops as f64) * 100.0
    );
    println!(
        "Other:                  {:>12}  ({:>5.1}%)",
        format_number(total_other),
        (total_other as f64 / total_ops as f64) * 100.0
    );
    println!("{}", "-".repeat(60));
    println!("TOTAL:              {:>16}", format_number(total_ops));
}

/// Display abuse detection results
fn display_abuse(token_ops: &HashMap<String, TokenOps>, threshold: usize) {
    let mut abusers: Vec<_> = token_ops
        .iter()
        .filter(|(_, ops)| ops.lookup_self >= threshold)
        .collect();

    abusers.sort_by(|a, b| b.1.lookup_self.cmp(&a.1.lookup_self));

    if abusers.is_empty() {
        println!(
            "\n No entities found exceeding threshold of {} lookup operations",
            format_number(threshold)
        );
        return;
    }

    println!(
        "\n Found {} entities exceeding {} lookup operations:\n",
        abusers.len(),
        format_number(threshold)
    );

    println!(
        "{:<50} {:>12} {:>20} {:>12}",
        "Entity", "Lookups", "Time Span", "Rate/Hour"
    );
    println!("{}", "=".repeat(106));

    for (entity_id, ops) in abusers {
        let display = ops
            .display_name
            .as_deref()
            .or(ops.username.as_deref())
            .unwrap_or(entity_id);

        let time_span = if let (Some(first), Some(last)) = (&ops.first_seen, &ops.last_seen) {
            calculate_time_span_hours(first, last)
        } else {
            0.0
        };

        let rate = if time_span > 0.0 {
            ops.lookup_self as f64 / time_span
        } else {
            0.0
        };

        println!(
            "{:<50} {:>12} {:>17.1}h {:>12.1}",
            if display.len() > 50 {
                format!("{}...", &display[..47])
            } else {
                display.to_string()
            },
            format_number(ops.lookup_self),
            time_span,
            rate
        );
    }
}

/// Export data to CSV
fn export_csv(
    accessor_data: &HashMap<String, EntityAccessors>,
    output: &str,
    min_operations: usize,
) -> Result<()> {
    let mut file = File::create(output)
        .with_context(|| format!("Failed to create output file: {}", output))?;

    writeln!(
        file,
        "entity_id,display_name,accessor,operations,first_seen,last_seen,duration_hours"
    )?;

    let mut rows: Vec<_> = accessor_data
        .iter()
        .flat_map(|(entity_id, entity_data)| {
            entity_data
                .accessors
                .iter()
                .map(move |(accessor, data)| (entity_id, &entity_data.display_name, accessor, data))
        })
        .filter(|(_, _, _, data)| data.operations >= min_operations)
        .collect();

    rows.sort_by(|a, b| b.3.operations.cmp(&a.3.operations));

    for (entity_id, display_name, accessor, data) in rows {
        let duration = calculate_time_span_hours(&data.first_seen, &data.last_seen);
        let display = display_name.as_deref().unwrap_or(entity_id);

        writeln!(
            file,
            "{},{},{},{},{},{},{:.2}",
            entity_id,
            display,
            accessor,
            data.operations,
            data.first_seen,
            data.last_seen,
            duration
        )?;
    }

    Ok(())
}

/// Main entry point for token analysis command
pub fn run(
    log_files: &[String],
    abuse_threshold: Option<usize>,
    operation_filter: Option<Vec<String>>,
    export_path: Option<&str>,
    min_operations: usize,
) -> Result<()> {
    eprintln!("Token Analysis");
    eprintln!("   Files: {}", log_files.len());
    if let Some(ref filters) = operation_filter {
        eprintln!("   Filter: {}", filters.join(", "));
    }
    if let Some(threshold) = abuse_threshold {
        eprintln!("   Abuse threshold: {}", format_number(threshold));
    }
    if let Some(output) = export_path {
        eprintln!("   Export: {}", output);
    }
    eprintln!();

    let (token_ops, accessor_data, total_lines) =
        process_logs(log_files, operation_filter.as_ref())?;

    eprintln!("\n Processed {} total lines", format_number(total_lines));
    eprintln!(
        "  {} unique entities with token operations",
        format_number(token_ops.len())
    );

    // Display based on mode
    if let Some(threshold) = abuse_threshold {
        display_abuse(&token_ops, threshold);
    } else {
        display_summary(&token_ops, total_lines);
    }

    // Export if requested
    if let Some(output) = export_path {
        export_csv(&accessor_data, output, min_operations)?;
        eprintln!("\n Exported data to: {}", output);
    }

    Ok(())
}
