//! System-wide audit log overview.
//!
//! Provides high-level statistics and insights about Vault usage
//! across the entire audit log. Supports analyzing multiple log files
//! (compressed or uncompressed) for long-term trend analysis.
//!
//! # Usage
//!
//! ```bash
//! # Single file (plain or compressed)
//! vault-audit system-overview audit.log
//! vault-audit system-overview audit.log.gz
//!
//! # Multiple files for week-long analysis
//! vault-audit system-overview day1.log day2.log day3.log
//!
//! # Using shell globbing with compressed files
//! vault-audit system-overview logs/vault_audit.2025-10-*.log.gz
//! ```
//!
//! **Compressed File Support**: Automatically detects and decompresses `.gz` (gzip)
//! and `.zst` (zstandard) files with streaming processing - no temp files needed.
//!
//! # Output
//!
//! Displays comprehensive statistics:
//! - Total entries processed
//! - Unique entities
//! - Unique paths accessed
//! - Operation breakdown (read, write, list, delete)
//! - Top paths by access count
//! - Mount point usage
//! - Authentication method breakdown
//! - Time range covered
//! - Error rate
//!
//! Useful for:
//! - Understanding overall Vault usage
//! - Capacity planning
//! - Identifying hotspots
//! - Security audits

use crate::audit::types::AuditEntry;
use crate::utils::format::format_number;
use crate::utils::parallel::process_files_parallel;
use crate::utils::progress::ProgressBar;
use crate::utils::reader::open_file;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};

/// Path access statistics
#[derive(Debug)]
struct PathData {
    count: usize,
    operations: HashMap<String, usize>,
    entities: HashSet<String>,
}

impl PathData {
    fn new() -> Self {
        Self {
            count: 0,
            operations: HashMap::with_capacity(10), // Typical: few operation types per path
            entities: HashSet::with_capacity(50),   // Typical: dozens of entities per popular path
        }
    }
}

/// Results from processing a single file
#[derive(Debug)]
struct FileAnalysisResult {
    path_operations: HashMap<String, PathData>,
    operation_types: HashMap<String, usize>,
    path_prefixes: HashMap<String, usize>,
    entity_paths: HashMap<String, HashMap<String, usize>>,
    entity_names: HashMap<String, String>,
}

/// Process entries from a single file using streaming to reduce memory usage
fn process_file_entries_streaming(file_path: &str) -> Result<FileAnalysisResult> {
    use crate::utils::reader::open_file;
    use std::io::{BufRead, BufReader};

    let mut path_operations: HashMap<String, PathData> = HashMap::with_capacity(5000);
    let mut operation_types: HashMap<String, usize> = HashMap::with_capacity(20);
    let mut path_prefixes: HashMap<String, usize> = HashMap::with_capacity(100);
    let mut entity_paths: HashMap<String, HashMap<String, usize>> = HashMap::with_capacity(2000);
    let mut entity_names: HashMap<String, String> = HashMap::with_capacity(2000);

    let file = open_file(file_path)?;
    let reader = BufReader::new(file);

    for line_result in reader.lines() {
        let line = line_result?;

        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }

        // Parse JSON entry
        let entry: AuditEntry = match serde_json::from_str(&line) {
            Ok(entry) => entry,
            Err(_) => continue, // Skip invalid JSON lines
        };

        let Some(request) = &entry.request else {
            continue;
        };

        let path = match &request.path {
            Some(p) => p.as_str(),
            None => continue,
        };

        let operation = match &request.operation {
            Some(o) => o.as_str(),
            None => continue,
        };

        let entity_id = entry
            .auth
            .as_ref()
            .and_then(|a| a.entity_id.as_deref())
            .unwrap_or("no-entity");

        let display_name = entry
            .auth
            .as_ref()
            .and_then(|a| a.display_name.as_deref())
            .unwrap_or("N/A");

        if path.is_empty() || operation.is_empty() {
            continue;
        }

        // Track by full path
        let path_data = path_operations
            .entry(path.to_string())
            .or_insert_with(PathData::new);
        path_data.count += 1;
        *path_data
            .operations
            .entry(operation.to_string())
            .or_insert(0) += 1;
        path_data.entities.insert(entity_id.to_string());

        // Track by operation type
        *operation_types.entry(operation.to_string()).or_insert(0) += 1;

        // Track by path prefix
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let prefix = if parts.len() >= 2 {
            format!("{}/{}", parts[0], parts[1])
        } else if !parts.is_empty() {
            parts[0].to_string()
        } else {
            "root".to_string()
        };
        *path_prefixes.entry(prefix).or_insert(0) += 1;

        // Track entity usage
        let entity_map = entity_paths.entry(entity_id.to_string()).or_default();
        *entity_map.entry(path.to_string()).or_insert(0) += 1;
        entity_names
            .entry(entity_id.to_string())
            .or_insert_with(|| display_name.to_string());
    }

    Ok(FileAnalysisResult {
        path_operations,
        operation_types,
        path_prefixes,
        entity_paths,
        entity_names,
    })
}

/// Process entries from a single file (original non-streaming version)
fn process_file_entries(_file_path: &str, entries: Vec<AuditEntry>) -> FileAnalysisResult {
    let mut path_operations: HashMap<String, PathData> = HashMap::with_capacity(5000);
    let mut operation_types: HashMap<String, usize> = HashMap::with_capacity(20);
    let mut path_prefixes: HashMap<String, usize> = HashMap::with_capacity(100);
    let mut entity_paths: HashMap<String, HashMap<String, usize>> = HashMap::with_capacity(2000);
    let mut entity_names: HashMap<String, String> = HashMap::with_capacity(2000);

    for entry in entries {
        let Some(request) = &entry.request else {
            continue;
        };

        let path = match &request.path {
            Some(p) => p.as_str(),
            None => continue,
        };

        let operation = match &request.operation {
            Some(o) => o.as_str(),
            None => continue,
        };

        let entity_id = entry
            .auth
            .as_ref()
            .and_then(|a| a.entity_id.as_deref())
            .unwrap_or("no-entity");

        let display_name = entry
            .auth
            .as_ref()
            .and_then(|a| a.display_name.as_deref())
            .unwrap_or("N/A");

        if path.is_empty() || operation.is_empty() {
            continue;
        }

        // Track by full path
        let path_data = path_operations
            .entry(path.to_string())
            .or_insert_with(PathData::new);
        path_data.count += 1;
        *path_data
            .operations
            .entry(operation.to_string())
            .or_insert(0) += 1;
        path_data.entities.insert(entity_id.to_string());

        // Track by operation type
        *operation_types.entry(operation.to_string()).or_insert(0) += 1;

        // Track by path prefix
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let prefix = if parts.len() >= 2 {
            format!("{}/{}", parts[0], parts[1])
        } else if !parts.is_empty() {
            parts[0].to_string()
        } else {
            "root".to_string()
        };
        *path_prefixes.entry(prefix).or_insert(0) += 1;

        // Track entity usage
        let entity_map = entity_paths.entry(entity_id.to_string()).or_default();
        *entity_map.entry(path.to_string()).or_insert(0) += 1;
        entity_names
            .entry(entity_id.to_string())
            .or_insert_with(|| display_name.to_string());
    }

    FileAnalysisResult {
        path_operations,
        operation_types,
        path_prefixes,
        entity_paths,
        entity_names,
    }
}

/// Combine results from multiple files
fn combine_results(
    results: Vec<crate::utils::parallel::FileProcessResult<FileAnalysisResult>>,
) -> FileAnalysisResult {
    let mut combined = FileAnalysisResult {
        path_operations: HashMap::with_capacity(5000),
        operation_types: HashMap::with_capacity(20),
        path_prefixes: HashMap::with_capacity(100),
        entity_paths: HashMap::with_capacity(2000),
        entity_names: HashMap::with_capacity(2000),
    };

    for file_result in results {
        let result = file_result.data;

        // Merge path operations
        for (path, path_data) in result.path_operations {
            if let Some(existing) = combined.path_operations.get_mut(&path) {
                existing.count += path_data.count;
                for (op, count) in path_data.operations {
                    *existing.operations.entry(op).or_insert(0) += count;
                }
                existing.entities.extend(path_data.entities);
            } else {
                combined.path_operations.insert(path, path_data);
            }
        }

        // Merge operation types
        for (op, count) in result.operation_types {
            *combined.operation_types.entry(op).or_insert(0) += count;
        }

        // Merge path prefixes
        for (prefix, count) in result.path_prefixes {
            *combined.path_prefixes.entry(prefix).or_insert(0) += count;
        }

        // Merge entity paths
        for (entity_id, paths) in result.entity_paths {
            let entity_map = combined.entity_paths.entry(entity_id).or_default();
            for (path, count) in paths {
                *entity_map.entry(path).or_insert(0) += count;
            }
        }

        // Merge entity names (first occurrence wins)
        for (entity_id, name) in result.entity_names {
            combined.entity_names.entry(entity_id).or_insert(name);
        }
    }

    combined
}

/// Sequential processing fallback for compatibility and single files
fn run_sequential(log_files: &[String]) -> Result<(FileAnalysisResult, usize)> {
    let mut combined_result = FileAnalysisResult {
        path_operations: HashMap::with_capacity(5000),
        operation_types: HashMap::with_capacity(20),
        path_prefixes: HashMap::with_capacity(100),
        entity_paths: HashMap::with_capacity(2000),
        entity_names: HashMap::with_capacity(2000),
    };
    let mut total_lines = 0;

    // Process each file sequentially
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

        let file = open_file(log_file)?;
        let reader = BufReader::new(file);

        let mut file_lines = 0;
        let mut bytes_read = 0;
        let mut entries = Vec::new();

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

            if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                entries.push(entry);
            }
        }

        if let Some(size) = file_size {
            progress.update(size);
        }

        progress.finish_with_message(&format!(
            "Processed {} lines from this file",
            format_number(file_lines)
        ));

        // Process the entries from this file and merge directly
        let file_result = process_file_entries(log_file, entries);

        // Merge path operations
        for (path, path_data) in file_result.path_operations {
            if let Some(existing) = combined_result.path_operations.get_mut(&path) {
                existing.count += path_data.count;
                for (op, count) in path_data.operations {
                    *existing.operations.entry(op).or_insert(0) += count;
                }
                existing.entities.extend(path_data.entities);
            } else {
                combined_result.path_operations.insert(path, path_data);
            }
        }

        // Merge operation types
        for (op, count) in file_result.operation_types {
            *combined_result.operation_types.entry(op).or_insert(0) += count;
        }

        // Merge path prefixes
        for (prefix, count) in file_result.path_prefixes {
            *combined_result.path_prefixes.entry(prefix).or_insert(0) += count;
        }

        // Merge entity paths
        for (entity_id, paths) in file_result.entity_paths {
            let entity_map = combined_result.entity_paths.entry(entity_id).or_default();
            for (path, count) in paths {
                *entity_map.entry(path).or_insert(0) += count;
            }
        }

        // Merge entity names
        for (entity_id, name) in file_result.entity_names {
            combined_result
                .entity_names
                .entry(entity_id)
                .or_insert(name);
        }
    }

    Ok((combined_result, total_lines))
}

pub fn run(
    log_files: &[String],
    top: usize,
    min_operations: usize,
    sequential: bool,
) -> Result<()> {
    let (combined_result, total_lines) = if sequential || log_files.len() == 1 {
        // Use sequential processing for single files or when explicitly requested
        eprintln!("Processing {} files sequentially...", log_files.len());
        run_sequential(log_files)?
    } else {
        // Use parallel processing for multiple files with streaming
        process_files_parallel(log_files, process_file_entries_streaming, combine_results)?
    };

    eprintln!("\nTotal: Processed {} lines", format_number(total_lines));

    let path_operations = combined_result.path_operations;
    let operation_types = combined_result.operation_types;
    let path_prefixes = combined_result.path_prefixes;
    let entity_paths = combined_result.entity_paths;
    let entity_names = combined_result.entity_names;

    let total_operations: usize = operation_types.values().sum();

    // Print results
    println!("\n{}", "=".repeat(100));
    println!("High-Volume Vault Operations Analysis");
    println!("{}", "=".repeat(100));

    // 1. Operation Types Summary
    println!("\n1. Operation Types (Overall)");
    println!("{}", "-".repeat(100));
    println!("{:<20} {:>15} {:>12}", "Operation", "Count", "Percentage");
    println!("{}", "-".repeat(100));

    let mut sorted_ops: Vec<_> = operation_types.iter().collect();
    sorted_ops.sort_by(|a, b| b.1.cmp(a.1));

    for (op, count) in sorted_ops {
        let pct = if total_operations > 0 {
            (*count as f64 / total_operations as f64) * 100.0
        } else {
            0.0
        };
        println!("{:<20} {:>15} {:>11.2}%", op, format_number(*count), pct);
    }

    println!("{}", "-".repeat(100));
    println!(
        "{:<20} {:>15} {:>11.2}%",
        "TOTAL",
        format_number(total_operations),
        100.0
    );

    // 2. Top Path Prefixes
    println!("\n2. Top Path Prefixes (First 2 components)");
    println!("{}", "-".repeat(100));
    println!(
        "{:<40} {:>15} {:>12}",
        "Path Prefix", "Operations", "Percentage"
    );
    println!("{}", "-".repeat(100));

    let mut sorted_prefixes: Vec<_> = path_prefixes.iter().collect();
    sorted_prefixes.sort_by(|a, b| b.1.cmp(a.1));

    for (prefix, count) in sorted_prefixes.iter().take(top) {
        let pct = if total_operations > 0 {
            (**count as f64 / total_operations as f64) * 100.0
        } else {
            0.0
        };
        println!(
            "{:<40} {:>15} {:>11.2}%",
            prefix,
            format_number(**count),
            pct
        );
    }

    // 3. Top Individual Paths
    println!("\n3. Top {} Individual Paths (Highest Volume)", top);
    println!("{}", "-".repeat(100));
    println!(
        "{:<60} {:>10} {:>10} {:>15}",
        "Path", "Ops", "Entities", "Top Op"
    );
    println!("{}", "-".repeat(100));

    let mut sorted_paths: Vec<_> = path_operations.iter().collect();
    sorted_paths.sort_by(|a, b| b.1.count.cmp(&a.1.count));

    for (path, data) in sorted_paths.iter().take(top) {
        if data.count < min_operations {
            break;
        }
        let top_op = data
            .operations
            .iter()
            .max_by_key(|x| x.1)
            .map_or("N/A", |x| x.0.as_str());
        let path_display = if path.len() > 60 {
            format!("{}...", &path[..58])
        } else {
            (*path).to_string()
        };
        println!(
            "{:<60} {:>10} {:>10} {:>15}",
            path_display,
            format_number(data.count),
            format_number(data.entities.len()),
            top_op
        );
    }

    // 4. Top Entities by Total Operations
    println!("\n4. Top {} Entities by Total Operations", top);
    println!("{}", "-".repeat(100));
    println!(
        "{:<50} {:<38} {:>10}",
        "Display Name", "Entity ID", "Total Ops"
    );
    println!("{}", "-".repeat(100));

    let mut entity_totals: HashMap<String, usize> = HashMap::with_capacity(entity_paths.len());
    for (entity_id, paths) in &entity_paths {
        let total: usize = paths.values().sum();
        entity_totals.insert(entity_id.clone(), total);
    }

    let mut sorted_entities: Vec<_> = entity_totals.iter().collect();
    sorted_entities.sort_by(|a, b| b.1.cmp(a.1));

    for (entity_id, total) in sorted_entities.iter().take(top) {
        let name = entity_names
            .get(*entity_id)
            .map_or("N/A", std::string::String::as_str);
        let name_display = if name.len() > 48 { &name[..48] } else { name };
        let entity_short = if entity_id.len() > 36 {
            &entity_id[..36]
        } else {
            entity_id
        };
        println!(
            "{:<50} {:<38} {:>10}",
            name_display,
            entity_short,
            format_number(**total)
        );
    }

    // 5. Potential Stress Points
    println!("\n5. Potential System Stress Points");
    println!("{}", "-".repeat(100));

    #[derive(Debug)]
    struct StressPoint {
        path: String,
        entity_name: String,
        operations: usize,
    }

    let mut stress_points = Vec::new();

    for (path, data) in &path_operations {
        if data.count >= min_operations {
            for entity_id in &data.entities {
                if let Some(entity_ops_map) = entity_paths.get(entity_id) {
                    if let Some(&entity_ops) = entity_ops_map.get(path) {
                        if entity_ops >= min_operations {
                            stress_points.push(StressPoint {
                                path: path.clone(),
                                entity_name: entity_names
                                    .get(entity_id)
                                    .cloned()
                                    .unwrap_or_else(|| "N/A".to_string()),
                                operations: entity_ops,
                            });
                        }
                    }
                }
            }
        }
    }

    stress_points.sort_by(|a, b| b.operations.cmp(&a.operations));

    println!("{:<40} {:<40} {:>10}", "Entity", "Path", "Ops");
    println!("{}", "-".repeat(100));

    for sp in stress_points.iter().take(top) {
        let entity_display = if sp.entity_name.len() > 38 {
            &sp.entity_name[..38]
        } else {
            &sp.entity_name
        };
        let path_display = if sp.path.len() > 38 {
            &sp.path[..38]
        } else {
            &sp.path
        };
        println!(
            "{:<40} {:<40} {:>10}",
            entity_display,
            path_display,
            format_number(sp.operations)
        );
    }

    println!("{}", "=".repeat(100));
    println!("\nTotal Lines Processed: {}", format_number(total_lines));
    println!("Total Operations: {}", format_number(total_operations));
    println!("{}", "=".repeat(100));

    Ok(())
}
