//! KV secrets engine usage analyzer.
//!
//! ⚠️ **DEPRECATED**: Use `kv-analysis analyze` instead.
//!
//! ```bash
//! # Old (deprecated):
//! vault-audit kv-analyzer logs/*.log --output kv_usage.csv
//!
//! # New (recommended):
//! vault-audit kv-analysis analyze logs/*.log --output kv_usage.csv
//! ```
//!
//! See [`kv_analysis`](crate::commands::kv_analysis) for the unified command.
//!
//! ---
//!
//! Analyzes KV mount access patterns from audit logs and generates
//! detailed usage statistics per path and entity. Supports multi-file
//! analysis (compressed or uncompressed) for long-term trend tracking.
//!
//! # Usage
//!
//! ```bash
//! # Single file analysis (plain or compressed)
//! vault-audit kv-analyzer audit.log --output kv_usage.csv
//! vault-audit kv-analyzer audit.log.gz --output kv_usage.csv
//!
//! # Multi-day analysis with compressed files
//! vault-audit kv-analyzer day1.log.gz day2.log.gz day3.log.gz --output kv_usage.csv
//!
//! # Filter specific KV mount
//! vault-audit kv-analyzer *.log --kv-prefix "appcodes/" --output appcodes.csv
//! ```
//!
//! **Compressed File Support**: Processes `.gz` and `.zst` files with no manual decompression.
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
use crate::utils::format::format_number;
use crate::utils::processor::{ProcessingMode, ProcessorBuilder};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs::File;

/// Tracks KV usage statistics for a specific path
#[derive(Debug, Clone)]
struct KvUsageData {
    entity_ids: HashSet<String>,
    operations_count: usize,
    paths_accessed: HashSet<String>,
}

impl KvUsageData {
    fn new() -> Self {
        Self {
            entity_ids: HashSet::new(),
            operations_count: 0,
            paths_accessed: HashSet::new(),
        }
    }

    fn merge(&mut self, other: Self) {
        self.entity_ids.extend(other.entity_ids);
        self.operations_count += other.operations_count;
        self.paths_accessed.extend(other.paths_accessed);
    }
}

#[derive(Debug, Clone)]
struct KvAnalyzerState {
    kv_usage: HashMap<String, KvUsageData>,
    kv_prefix: String,
    parsed_lines: usize,
}

impl KvAnalyzerState {
    fn new(kv_prefix: String) -> Self {
        Self {
            kv_usage: HashMap::with_capacity(10000),
            kv_prefix,
            parsed_lines: 0,
        }
    }

    fn merge(mut self, other: Self) -> Self {
        self.parsed_lines += other.parsed_lines;
        for (path, other_data) in other.kv_usage {
            self.kv_usage
                .entry(path)
                .and_modify(|data| data.merge(other_data.clone()))
                .or_insert(other_data);
        }
        self
    }
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
    let mut entity_aliases: HashMap<String, Vec<String>> = HashMap::with_capacity(2000); // Pre-allocate for entities

    let Ok(file) = File::open(alias_export_csv) else {
        eprintln!("[WARN] Entity alias export not found: {}", alias_export_csv);
        return Ok(entity_aliases);
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
    let kv_prefix_owned = kv_prefix.to_string();

    let processor = ProcessorBuilder::new()
        .mode(ProcessingMode::Auto)
        .progress_label("Processing".to_string())
        .build();

    let (result, stats) = processor.process_files_streaming(
        log_files,
        |entry: &AuditEntry, state: &mut KvAnalyzerState| {
            // Filter for KV operations
            let Some(request) = &entry.request else {
                return;
            };

            let path = match &request.path {
                Some(p) => p.as_str(),
                None => return,
            };

            // Check prefix
            if !state.kv_prefix.is_empty() && !path.starts_with(&state.kv_prefix) {
                return;
            }
            if state.kv_prefix.is_empty()
                && !path.contains("/data/")
                && !path.contains("/metadata/")
            {
                return;
            }

            // Filter for read/list operations
            let operation = request.operation.as_deref().unwrap_or("");
            if operation != "read" && operation != "list" {
                return;
            }

            let Some(entity_id) = entry.auth.as_ref().and_then(|a| a.entity_id.as_deref()) else {
                return;
            };

            state.parsed_lines += 1;

            // Normalize path
            let app_path = normalize_kv_path(path);

            let usage = state
                .kv_usage
                .entry(app_path)
                .or_insert_with(KvUsageData::new);

            usage.entity_ids.insert(entity_id.to_string());
            usage.operations_count += 1;
            usage.paths_accessed.insert(path.to_string());
        },
        KvAnalyzerState::merge,
        KvAnalyzerState::new(kv_prefix_owned),
    )?;

    let total_lines = stats.total_lines;
    let parsed_lines = result.parsed_lines;
    let kv_usage = result.kv_usage;

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
        HashMap::with_capacity(0) // Empty aliases when file doesn't exist
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
