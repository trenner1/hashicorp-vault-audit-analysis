//! Token lifecycle operations analysis.
//!
//! Tracks token-related operations to understand token usage patterns
//! and identify entities performing high volumes of token operations.
//! Supports multi-file analysis for long-term trending.
//!
//! # Usage
//!
//! ```bash
//! # Single file analysis
//! vault-audit token-operations vault_audit.log
//!
//! # Week-long analysis
//! vault-audit token-operations logs/vault_audit.2025-10-*.log
//! ```
//!
//! # Output
//!
//! Displays a summary table showing per-entity token operations:
//! - **lookup-self**: Token self-inspection operations
//! - **renew-self**: Token renewal operations
//! - **revoke-self**: Token revocation operations
//! - **create**: New token creation
//! - **login**: Authentication operations that create tokens
//! - **other**: Other token-related operations
//!
//! Results are sorted by total operations (descending) to identify
//! the most active entities.

use crate::audit::types::AuditEntry;
use crate::utils::progress::ProgressBar;
use anyhow::Result;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

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

pub fn run(log_files: &[String], output: Option<&str>) -> Result<()> {
    let mut token_ops: HashMap<String, TokenOps> = HashMap::new();
    let mut total_lines = 0;

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

        let mut file_lines = 0;
        let mut bytes_read = 0;

        let file = File::open(log_file)?;
        let reader = BufReader::new(file);

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

            // Get entity_id first
            let entity_id = match &entry.auth {
                Some(auth) => match &auth.entity_id {
                    Some(id) => id.as_str(),
                    None => continue,
                },
                None => continue,
            };

            // Filter for token operations OR login operations
            let path = match &entry.request {
                Some(r) => match &r.path {
                    Some(p) => p.as_str(),
                    None => continue,
                },
                None => continue,
            };

            let is_token_op = path.starts_with("auth/token/");
            let is_login = path.starts_with("auth/") && path.contains("/login");

            if !is_token_op && !is_login {
                continue;
            }

            let operation = entry
                .request
                .as_ref()
                .and_then(|r| r.operation.as_deref())
                .unwrap_or("");

            let ops = token_ops.entry(entity_id.to_string()).or_default();

            // Categorize operation
            if is_login {
                ops.login += 1;
            } else if path.contains("lookup-self") {
                ops.lookup_self += 1;
            } else if path.contains("renew-self") {
                ops.renew_self += 1;
            } else if path.contains("revoke-self") {
                ops.revoke_self += 1;
            } else if path.contains("create") || operation == "create" {
                ops.create += 1;
            } else {
                ops.other += 1;
            }

            // Capture display name and metadata (first occurrence)
            if ops.display_name.is_none() {
                ops.display_name = entry
                    .auth
                    .as_ref()
                    .and_then(|a| a.display_name.as_deref())
                    .map(|s| s.to_string());
                if let Some(auth) = &entry.auth {
                    if let Some(metadata) = &auth.metadata {
                        if let Some(username) = metadata.get("username") {
                            ops.username = username.as_str().map(|s| s.to_string());
                        }
                    }
                }
            }
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

    eprintln!("\nTotal: Processed {} lines", format_number(total_lines));

    // Calculate totals per entity
    let mut entity_totals: Vec<_> = token_ops
        .iter()
        .map(|(entity_id, ops)| {
            let total = ops.lookup_self
                + ops.renew_self
                + ops.revoke_self
                + ops.create
                + ops.login
                + ops.other;
            (
                entity_id.clone(),
                total,
                ops.display_name
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                ops.lookup_self,
                ops.renew_self,
                ops.revoke_self,
                ops.create,
                ops.login,
                ops.other,
                ops.username.clone().unwrap_or_default(),
            )
        })
        .filter(|x| x.1 > 0)
        .collect();

    // Sort by total operations
    entity_totals.sort_by(|a, b| b.1.cmp(&a.1));

    // Display results
    let top = 50;
    println!("\n{}", "=".repeat(150));
    println!(
        "{:<30} {:<25} {:<10} {:<10} {:<10} {:<10} {:<10} {:<10} {:<10}",
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

    let mut grand_total = 0;
    for (_, total, display_name, lookup, renew, revoke, create, login, other, username) in
        entity_totals.iter().take(top)
    {
        let display_name_trunc = if display_name.len() > 29 {
            &display_name[..29]
        } else {
            display_name
        };
        let username_trunc = if username.len() > 24 {
            &username[..24]
        } else {
            username
        };

        println!(
            "{:<30} {:<25} {:<10} {:<10} {:<10} {:<10} {:<10} {:<10} {:<10}",
            display_name_trunc,
            username_trunc,
            format_number(*total),
            format_number(*lookup),
            format_number(*renew),
            format_number(*revoke),
            format_number(*create),
            format_number(*login),
            format_number(*other)
        );
        grand_total += total;
    }

    println!("{}", "=".repeat(150));
    println!(
        "{:<55} {:<10}",
        format!("TOTAL (top {})", entity_totals.len().min(top)),
        format_number(grand_total)
    );
    println!(
        "{:<55} {:<10}",
        "TOTAL ENTITIES",
        format_number(entity_totals.len())
    );
    println!("{}", "=".repeat(150));

    // Summary by operation type
    let total_lookup: usize = entity_totals.iter().map(|x| x.3).sum();
    let total_renew: usize = entity_totals.iter().map(|x| x.4).sum();
    let total_revoke: usize = entity_totals.iter().map(|x| x.5).sum();
    let total_create: usize = entity_totals.iter().map(|x| x.6).sum();
    let total_login: usize = entity_totals.iter().map(|x| x.7).sum();
    let total_other: usize = entity_totals.iter().map(|x| x.8).sum();
    let overall_total =
        total_lookup + total_renew + total_revoke + total_create + total_login + total_other;

    println!("\nOperation Type Breakdown:");
    println!("{}", "-".repeat(60));
    println!(
        "Lookup (lookup-self):  {:>12}  ({:>5.1}%)",
        format_number(total_lookup),
        (total_lookup as f64 / overall_total as f64) * 100.0
    );
    println!(
        "Renew (renew-self):    {:>12}  ({:>5.1}%)",
        format_number(total_renew),
        (total_renew as f64 / overall_total as f64) * 100.0
    );
    println!(
        "Revoke (revoke-self):  {:>12}  ({:>5.1}%)",
        format_number(total_revoke),
        (total_revoke as f64 / overall_total as f64) * 100.0
    );
    println!(
        "Create (child token):  {:>12}  ({:>5.1}%)",
        format_number(total_create),
        (total_create as f64 / overall_total as f64) * 100.0
    );
    println!(
        "Login (auth token):    {:>12}  ({:>5.1}%)",
        format_number(total_login),
        (total_login as f64 / overall_total as f64) * 100.0
    );
    println!(
        "Other:                 {:>12}  ({:>5.1}%)",
        format_number(total_other),
        (total_other as f64 / overall_total as f64) * 100.0
    );
    println!("{}", "-".repeat(60));
    println!(
        "TOTAL:                 {:>12}",
        format_number(overall_total)
    );

    // TODO: CSV output if specified
    if let Some(_output_path) = output {
        eprintln!("Note: CSV output not yet implemented");
    }

    Ok(())
}
