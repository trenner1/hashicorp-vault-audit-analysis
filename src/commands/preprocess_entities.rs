//! Entity mapping preprocessor.
//!
//! ⚠️ **DEPRECATED**: Use `entity-analysis preprocess` instead.
//!
//! ```bash
//! # Old (deprecated):
//! vault-audit preprocess-entities logs/*.log --output mappings.json
//!
//! # New (recommended):
//! vault-audit entity-analysis preprocess logs/*.log --output mappings.json
//! ```
//!
//! **Note**: Most commands now auto-preprocess entity mappings, so this is rarely needed!
//!
//! See [`entity_analysis`](crate::commands::entity_analysis) for the unified command.
//!
//! ---
//!
//! Extracts entity-to-alias mappings from audit logs and exports to JSON or CSV,
//! creating a baseline for subsequent entity analysis.
//! Supports multi-file processing for comprehensive entity mapping.
//!
//! # Usage
//!
//! ```bash
//! # Single file preprocessing (JSON default)
//! vault-audit preprocess-entities audit.log --output entity-mappings.json
//!
//! # Multi-day comprehensive mapping (CSV)
//! vault-audit preprocess-entities logs/*.log --output entity-mappings.csv --format csv
//!
//! # JSON format for entity-creation command
//! vault-audit preprocess-entities logs/*.log --output entity-mappings.json --format json
//! ```
//!
//! # Output
//!
//! Generates JSON or CSV containing:
//! - Entity ID
//! - Display name
//! - Mount path and accessor
//! - Username (if available)
//! - Login count
//! - First and last seen timestamps
//!
//! This output can be used as a baseline for:
//! - `entity-creation` command (accepts both CSV and JSON)
//! - `client-activity` command (JSON format)
//! - External analysis tools
//! - Historical trending

use crate::audit::types::AuditEntry;
use crate::utils::progress::ProgressBar;
use crate::utils::reader::open_file;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

/// Entity mapping with login statistics
#[derive(Debug, Serialize, Deserialize)]
struct EntityMapping {
    display_name: String,
    mount_path: String,
    mount_accessor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    login_count: usize,
    first_seen: String,
    last_seen: String,
}

pub fn run(log_files: &[String], output: &str, format: &str) -> Result<()> {
    eprintln!("Preprocessing audit logs...");
    eprintln!("Extracting entity → display_name mappings from login events...\n");

    let mut entity_map: HashMap<String, EntityMapping> = HashMap::new();
    let mut login_events = 0;
    let mut lines_processed = 0;

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

        let file = open_file(log_file)
            .with_context(|| format!("Failed to open audit log file: {}", log_file))?;
        let reader = BufReader::new(file);

        let mut progress = if let Some(size) = file_size {
            ProgressBar::new(size, "Processing")
        } else {
            ProgressBar::new_spinner("Processing")
        };
        let mut bytes_read = 0;
        let mut file_lines = 0;

        for line in reader.lines() {
            file_lines += 1;
            lines_processed += 1;
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

            // Look for login events in auth paths
            let request = match &entry.request {
                Some(r) => r,
                None => continue,
            };

            let path = match &request.path {
                Some(p) => p,
                None => continue,
            };

            if !path.starts_with("auth/") {
                continue;
            }

            if !path.contains("/login") {
                continue;
            }

            // Skip if no auth info
            let auth = match &entry.auth {
                Some(a) => a,
                None => continue,
            };

            // Skip if no entity_id or display_name
            let entity_id = match &auth.entity_id {
                Some(id) if !id.is_empty() => id.clone(),
                _ => continue,
            };

            let display_name = match &auth.display_name {
                Some(name) if !name.is_empty() => name.clone(),
                _ => continue,
            };

            login_events += 1;

            // Extract mount path from the auth path (e.g., "auth/github/login" -> "auth/github")
            let mount_path = path
                .trim_end_matches("/login")
                .trim_end_matches(&format!("/{}", display_name))
                .to_string();

            let mount_accessor = auth.accessor.clone().unwrap_or_default();
            let username = auth
                .metadata
                .as_ref()
                .and_then(|m| m.get("username"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // Update or insert entity mapping
            entity_map
                .entry(entity_id)
                .and_modify(|mapping| {
                    mapping.login_count += 1;
                    mapping.last_seen = entry.time.clone();
                    // Update display_name if it's newer (handle case variations)
                    if entry.time > mapping.last_seen {
                        mapping.display_name = display_name.clone();
                    }
                })
                .or_insert_with(|| EntityMapping {
                    display_name,
                    mount_path,
                    mount_accessor,
                    username,
                    login_count: 1,
                    first_seen: entry.time.clone(),
                    last_seen: entry.time.clone(),
                });
        }

        // Ensure we show 100% complete for this file
        if let Some(size) = file_size {
            progress.update(size);
        } else {
            progress.update(file_lines);
        }

        progress.finish_with_message(&format!("Processed {} lines from this file", file_lines));
    }

    eprintln!(
        "\nTotal: Processed {} lines, found {} login events, tracked {} entities",
        lines_processed,
        login_events,
        entity_map.len()
    );

    // Write output based on format
    eprintln!("\nWriting entity mappings to: {}", output);

    match format.to_lowercase().as_str() {
        "json" => {
            let output_file = File::create(output)
                .with_context(|| format!("Failed to create output file: {}", output))?;
            let mut writer = std::io::BufWriter::new(output_file);

            // Write as pretty JSON for readability
            let json = serde_json::to_string_pretty(&entity_map)
                .context("Failed to serialize entity mappings")?;
            writer.write_all(json.as_bytes())?;
            writer.flush()?;

            eprintln!("✓ JSON entity mapping file created successfully!\n");
        }
        "csv" => {
            let output_file = File::create(output)
                .with_context(|| format!("Failed to create output file: {}", output))?;
            let mut csv_writer = csv::Writer::from_writer(output_file);

            // Write CSV header
            csv_writer.write_record([
                "entity_id",
                "display_name",
                "mount_path",
                "mount_accessor",
                "username",
                "login_count",
                "first_seen",
                "last_seen",
            ])?;

            // Write entity data
            for (entity_id, mapping) in &entity_map {
                csv_writer.write_record([
                    entity_id,
                    &mapping.display_name,
                    &mapping.mount_path,
                    &mapping.mount_accessor,
                    mapping.username.as_deref().unwrap_or(""),
                    &mapping.login_count.to_string(),
                    &mapping.first_seen,
                    &mapping.last_seen,
                ])?;
            }

            csv_writer.flush()?;
            eprintln!("✓ CSV entity mapping file created successfully!\n");
        }
        _ => {
            anyhow::bail!("Invalid format '{}'. Use 'csv' or 'json'", format);
        }
    }

    eprintln!("Usage with client-activity command:");
    eprintln!(
        "  vault-audit client-activity --start <START> --end <END> --entity-map {}",
        output
    );

    Ok(())
}
