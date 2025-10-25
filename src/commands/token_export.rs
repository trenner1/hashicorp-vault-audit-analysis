//! Token lookup pattern exporter.
//!
//! **⚠️ DEPRECATED**: Use `token-analysis --export` instead.
//!
//! This command has been consolidated into the unified `token-analysis` command.
//! Use the `--export` flag for CSV export with per-accessor detail.
//!
//! ```bash
//! # Old command (deprecated)
//! vault-audit token-export audit.log --output lookups.csv --min-lookups 100
//!
//! # New command (recommended)
//! vault-audit token-analysis audit.log --export lookups.csv --min-operations 100
//! ```
//!
//! See [`token_analysis`](crate::commands::token_analysis) module for full documentation.
//!
//! ---
//!
//! Exports token lookup patterns to CSV for further analysis.
//! Identifies entities with high token lookup volumes and their patterns.
//! Supports multi-file analysis for historical trending.
//!
//! # Usage
//!
//! ```bash
//! # Single file export
//! vault-audit token-export audit.log --output lookups.csv
//!
//! # Multi-day export with filtering
//! vault-audit token-export *.log --output lookups.csv --min-lookups 100
//! ```
//!
//! # Output
//!
//! Generates a CSV file with columns:
//! - Entity ID
//! - Display name
//! - Token accessor
//! - Lookup count
//! - First seen timestamp
//! - Last seen timestamp
//! - Duration (time between first and last seen)
//!
//! Useful for:
//! - Token usage trending
//! - Token lifetime analysis
//! - Identifying long-lived vs short-lived tokens

use crate::audit::types::AuditEntry;
use crate::utils::format::format_number;
use crate::utils::progress::ProgressBar;
use crate::utils::reader::open_file;
use crate::utils::time::parse_timestamp;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Token activity statistics
#[derive(Debug, Default)]
struct TokenData {
    lookups: usize,
    first_seen: String,
    last_seen: String,
}

/// Entity with associated token data
#[derive(Debug)]
struct EntityData {
    display_name: String,
    tokens: HashMap<String, TokenData>,
}

fn calculate_time_span_hours(first: &str, last: &str) -> Result<f64> {
    let first_dt = parse_timestamp(first)
        .with_context(|| format!("Failed to parse first timestamp: {}", first))?;
    let last_dt = parse_timestamp(last)
        .with_context(|| format!("Failed to parse last timestamp: {}", last))?;

    let duration = last_dt.signed_duration_since(first_dt);
    Ok(duration.num_seconds() as f64 / 3600.0)
}

pub fn run(log_files: &[String], output: &str, min_lookups: usize) -> Result<()> {
    let mut entities: HashMap<String, EntityData> = HashMap::new();
    let mut total_lines = 0;
    let mut lookup_count = 0;

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

            // Filter for token lookup operations
            let Some(request) = &entry.request else {
                continue;
            };

            let path = match &request.path {
                Some(p) => p.as_str(),
                None => continue,
            };

            if !path.starts_with("auth/token/lookup") {
                continue;
            }

            let Some(entity_id) = entry.auth.as_ref().and_then(|a| a.entity_id.as_deref()) else {
                continue;
            };

            lookup_count += 1;

            let display_name = entry
                .auth
                .as_ref()
                .and_then(|a| a.display_name.as_deref())
                .unwrap_or("N/A");

            let entity_data = entities
                .entry(entity_id.to_string())
                .or_insert_with(|| EntityData {
                    display_name: display_name.to_string(),
                    tokens: HashMap::new(),
                });

            let accessor = entry
                .auth
                .as_ref()
                .and_then(|a| a.accessor.as_deref())
                .unwrap_or("unknown")
                .to_string();

            let timestamp = entry.time.clone();

            let token_data = entity_data.tokens.entry(accessor).or_default();
            token_data.lookups += 1;

            if token_data.first_seen.is_empty() {
                token_data.first_seen.clone_from(&timestamp);
            }
            token_data.last_seen = timestamp;
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
        "\nTotal: Processed {} lines, found {} token lookups from {} entities",
        format_number(total_lines),
        format_number(lookup_count),
        format_number(entities.len())
    );

    // Prepare CSV rows
    let mut rows: Vec<_> = entities
        .iter()
        .flat_map(|(entity_id, entity_data)| {
            entity_data
                .tokens
                .iter()
                .map(move |(accessor, token_data)| {
                    let time_span =
                        calculate_time_span_hours(&token_data.first_seen, &token_data.last_seen)
                            .unwrap_or_else(|err| {
                                eprintln!(
                                    "Warning: Failed to calculate time span for accessor {}: {}",
                                    accessor, err
                                );
                                0.0
                            });
                    let lookups_per_hour = if time_span > 0.0 {
                        token_data.lookups as f64 / time_span
                    } else {
                        0.0
                    };

                    (
                        entity_id.clone(),
                        entity_data.display_name.clone(),
                        accessor.clone(),
                        token_data.lookups,
                        time_span,
                        lookups_per_hour,
                        token_data.first_seen.clone(),
                        token_data.last_seen.clone(),
                    )
                })
        })
        .collect();

    // Sort by total lookups descending
    rows.sort_by(|a, b| b.3.cmp(&a.3));

    // Filter by minimum lookups
    rows.retain(|row| row.3 >= min_lookups);

    // Create output directory if needed
    if let Some(parent) = std::path::Path::new(output).parent() {
        std::fs::create_dir_all(parent).context("Failed to create output directory")?;
    }

    // Write CSV
    let file = File::create(output).context("Failed to create output file")?;
    let mut writer = csv::Writer::from_writer(file);

    writer.write_record([
        "entity_id",
        "display_name",
        "token_accessor",
        "total_lookups",
        "time_span_hours",
        "lookups_per_hour",
        "first_seen",
        "last_seen",
    ])?;

    for (entity_id, display_name, accessor, lookups, time_span, rate, first, last) in &rows {
        writer.write_record([
            entity_id,
            display_name,
            accessor,
            &lookups.to_string(),
            &format!("{:.2}", time_span),
            &format!("{:.2}", rate),
            first,
            last,
        ])?;
    }

    writer.flush()?;

    eprintln!(
        "\n[SUCCESS] Exported {} token lookup records to: {}",
        format_number(rows.len()),
        output
    );

    // Print summary
    let total_lookups: usize = rows.iter().map(|r| r.3).sum();
    let unique_entities = entities.len();
    let unique_tokens = rows.len();

    eprintln!("\n{}", "=".repeat(80));
    eprintln!("Summary Statistics:");
    eprintln!("{}", "-".repeat(80));
    eprintln!(
        "Total Token Lookup Operations: {}",
        format_number(total_lookups)
    );
    eprintln!("Unique Entities: {}", format_number(unique_entities));
    eprintln!("Unique Token Accessors: {}", format_number(unique_tokens));
    eprintln!(
        "Average Lookups per Token: {:.1}",
        total_lookups as f64 / unique_tokens as f64
    );

    // Top 5 entities by lookup count
    let mut entity_totals: HashMap<String, usize> = HashMap::new();
    let mut entity_names: HashMap<String, String> = HashMap::new();
    for (entity_id, display_name, _, lookups, _, _, _, _) in &rows {
        *entity_totals.entry(entity_id.clone()).or_insert(0) += lookups;
        entity_names.insert(entity_id.clone(), display_name.clone());
    }

    let mut top_entities: Vec<_> = entity_totals.into_iter().collect();
    top_entities.sort_by(|a, b| b.1.cmp(&a.1));

    eprintln!("\nTop 5 Entities by Lookup Count:");
    eprintln!("{}", "-".repeat(80));
    for (i, (entity_id, count)) in top_entities.iter().take(5).enumerate() {
        let name = entity_names.get(entity_id).unwrap();
        eprintln!(
            "{}. {} ({}): {} lookups",
            i + 1,
            name,
            entity_id,
            format_number(*count)
        );
    }

    eprintln!("{}", "=".repeat(80));
    eprintln!("\n✓ Token lookup data exported to: {}", output);

    Ok(())
}
