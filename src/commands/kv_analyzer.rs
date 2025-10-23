//! KV secrets engine usage analyzer.
//!
//! Analyzes KV mount access patterns from audit logs and generates
//! detailed usage statistics per path and entity. Supports multi-file
//! analysis for long-term trend tracking.
//!
//! # Usage
//!
//! ```bash
//! # Single file analysis
//! vault-audit kv-analyzer audit.log --output kv_usage.csv
//!
//! # Multi-day analysis
//! vault-audit kv-analyzer day1.log day2.log day3.log --output kv_usage.csv
//!
//! # Filter specific KV mount
//! vault-audit kv-analyzer *.log --kv-prefix "appcodes/" --output appcodes.csv
//! ```
//!
//! # Output
//!
//! Generates a CSV report with:
//! - Mount point
//! - Normalized secret path (without /data/ or /metadata/)
//! - Number of unique entities accessing the secret
//! - Total operations count
//! - List of unique paths accessed
//!
//! # KV v2 Path Normalization
//!
//! Automatically normalizes KV v2 paths:
//! - `secret/data/myapp/config` → `secret/myapp/config`
//! - `secret/metadata/myapp/config` → `secret/myapp/config`

use crate::audit::types::AuditEntry;
use crate::utils::progress::ProgressBar;
use crate::utils::reader::open_file;
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs::File;
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

/// Tracks KV usage statistics for a specific path
struct KvUsageData {
    entity_ids: HashSet<String>,
    operations_count: usize,
    paths_accessed: HashSet<String>,
}

/// Normalizes KV paths by removing KV v2 /data/ and /metadata/ components
fn normalize_kv_path(path: &str) -> String {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();

    // Handle KV v2 paths (kv/data/... or kv/metadata/...)
    if parts.len() >= 3 && (parts[1] == "data" || parts[1] == "metadata") {
        let mount = parts[0];
        let remaining: Vec<&str> = std::iter::once(parts[2])
            .chain(parts.iter().skip(3).copied())
            .collect();

        return if remaining.len() >= 3 {
            format!(
                "{}/{}/{}/{}/",
                mount, remaining[0], remaining[1], remaining[2]
            )
        } else if remaining.len() == 2 {
            format!("{}/{}/{}/", mount, remaining[0], remaining[1])
        } else if remaining.len() == 1 {
            format!("{}/{}/", mount, remaining[0])
        } else {
            format!("{}/", mount)
        };
    }

    // Handle KV v1 or simple paths
    if parts.len() >= 4 {
        format!("{}/{}/{}/{}/", parts[0], parts[1], parts[2], parts[3])
    } else if parts.len() == 3 {
        format!("{}/{}/{}/", parts[0], parts[1], parts[2])
    } else if parts.len() == 2 {
        format!("{}/{}/", parts[0], parts[1])
    } else if parts.len() == 1 {
        format!("{}/", parts[0])
    } else {
        String::new()
    }
}

fn load_entity_alias_mapping(alias_export_csv: &str) -> Result<HashMap<String, Vec<String>>> {
    let mut entity_aliases: HashMap<String, Vec<String>> = HashMap::new();

    let file = match File::open(alias_export_csv) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("[WARN] Entity alias export not found: {}", alias_export_csv);
            return Ok(entity_aliases);
        }
    };

    let mut reader = csv::Reader::from_reader(file);

    for result in reader.records() {
        let record = result?;
        if let (Some(entity_id), Some(alias_name)) = (record.get(0), record.get(1)) {
            entity_aliases
                .entry(entity_id.to_string())
                .or_default()
                .push(alias_name.to_string());
        }
    }

    Ok(entity_aliases)
}

pub fn run(
    log_files: &[String],
    kv_prefix: &str,
    output: Option<&str>,
    entity_csv: Option<&str>,
) -> Result<()> {
    let output_file = output.unwrap_or("kv_usage_by_client.csv");

    let mut kv_usage: HashMap<String, KvUsageData> = HashMap::new();
    let mut total_lines = 0;
    let mut parsed_lines = 0;

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

        let file = open_file(log_file)
            .with_context(|| format!("Failed to open audit log file: {}", log_file))?;
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

            // Filter for KV operations
            let request = match &entry.request {
                Some(r) => r,
                None => continue,
            };

            let path = match &request.path {
                Some(p) => p.as_str(),
                None => continue,
            };

            // Check prefix
            if !kv_prefix.is_empty() && !path.starts_with(kv_prefix) {
                continue;
            }
            if kv_prefix.is_empty() && !path.contains("/data/") && !path.contains("/metadata/") {
                continue;
            }

            // Filter for read/list operations
            let operation = request.operation.as_deref().unwrap_or("");
            if operation != "read" && operation != "list" {
                continue;
            }

            let entity_id = match entry.auth.as_ref().and_then(|a| a.entity_id.as_deref()) {
                Some(id) => id,
                None => continue,
            };

            parsed_lines += 1;

            // Normalize path
            let app_path = normalize_kv_path(path);

            let usage = kv_usage.entry(app_path).or_insert_with(|| KvUsageData {
                entity_ids: HashSet::new(),
                operations_count: 0,
                paths_accessed: HashSet::new(),
            });

            usage.entity_ids.insert(entity_id.to_string());
            usage.operations_count += 1;
            usage.paths_accessed.insert(path.to_string());
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
        "\nTotal: Processed {} lines, parsed {} KV operations",
        format_number(total_lines),
        format_number(parsed_lines)
    );

    if kv_usage.is_empty() {
        eprintln!("[ERROR] No KV operations found in audit logs.");
        std::process::exit(1);
    }

    // Load entity/alias mapping
    let entity_aliases = if let Some(alias_file) = entity_csv {
        load_entity_alias_mapping(alias_file)?
    } else {
        HashMap::new()
    };

    // Ensure output directory exists
    if let Some(parent) = std::path::Path::new(output_file).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write CSV
    let file = File::create(output_file).context("Failed to create output file")?;
    let mut writer = csv::Writer::from_writer(file);

    writer.write_record([
        "kv_path",
        "unique_clients",
        "operations_count",
        "entity_ids",
        "alias_names",
        "sample_paths_accessed",
    ])?;

    let mut paths: Vec<_> = kv_usage.keys().collect();
    paths.sort();

    for kv_path in paths {
        let data = &kv_usage[kv_path];

        let mut entity_ids: Vec<_> = data.entity_ids.iter().cloned().collect();
        entity_ids.sort();

        let unique_clients = entity_ids.len();
        let operations = data.operations_count;

        // Collect alias names
        let mut alias_names = Vec::new();
        for eid in &entity_ids {
            if let Some(aliases) = entity_aliases.get(eid) {
                alias_names.extend(aliases.iter().cloned());
            }
        }

        // Sample paths (limit to 5)
        let mut sample_paths: Vec<_> = data.paths_accessed.iter().cloned().collect();
        sample_paths.sort();
        sample_paths.truncate(5);

        writer.write_record([
            kv_path,
            &unique_clients.to_string(),
            &operations.to_string(),
            &entity_ids.join(", "),
            &alias_names.join(", "),
            &sample_paths.join(", "),
        ])?;
    }

    writer.flush()?;

    println!("Done. Output written to: {}", output_file);
    println!("Summary: {} KV paths analyzed", kv_usage.len());

    Ok(())
}
