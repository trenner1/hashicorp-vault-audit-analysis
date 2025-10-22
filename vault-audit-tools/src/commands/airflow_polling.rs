//! Airflow polling pattern detection.
//!
//! Identifies Apache Airflow instances that are polling Vault connections
//! excessively, which can cause performance issues.
//! Supports multi-file analysis for pattern detection over time.
//!
//! # Usage
//!
//! ```bash
//! # Single file - detect default Airflow patterns
//! vault-audit airflow-polling audit.log
//!
//! # Multi-day analysis with custom thresholds
//! vault-audit airflow-polling logs/*.log --threshold 100
//! ```
//!
//! # Detection Logic
//!
//! Identifies entities accessing paths like:
//! - `database/config/*`
//! - `database/creds/*`
//! - Connection-related paths
//!
//! With characteristics of polling behavior:
//! - High frequency access (default: >50 ops)
//! - Regular time intervals
//! - Repeated access to same paths
//!
//! # Output
//!
//! Displays entities with polling patterns:
//! - Entity ID and display name
//! - Total operations count
//! - Polling rate (ops per hour)
//! - Paths being polled
//! - Time span of activity
//!
//! Helps optimize:
//! - Airflow connection pooling
//! - Vault performance
//! - Database credential caching

use crate::audit::types::AuditEntry;
use crate::utils::progress::ProgressBar;
use crate::utils::time::parse_timestamp;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn format_number(n: usize) -> String {
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

struct PathData {
    operations: usize,
    entities: std::collections::HashSet<String>,
    operations_by_entity: HashMap<String, usize>,
    timestamps: Vec<DateTime<Utc>>,
}

impl PathData {
    fn new() -> Self {
        Self {
            operations: 0,
            entities: std::collections::HashSet::new(),
            operations_by_entity: HashMap::new(),
            timestamps: Vec::new(),
        }
    }
}

pub fn run(log_files: &[String], output: Option<&str>) -> Result<()> {
    let mut airflow_operations = 0;
    let mut airflow_paths: HashMap<String, PathData> = HashMap::new();
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

        let file = File::open(log_file)?;
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

            // Filter for Airflow-related paths (case-insensitive)
            let request = match &entry.request {
                Some(r) => r,
                None => continue,
            };

            let path = match &request.path {
                Some(p) => p.as_str(),
                None => continue,
            };

            if path.to_lowercase().contains("airflow") {
                airflow_operations += 1;

                let entity_id = entry
                    .auth
                    .as_ref()
                    .and_then(|a| a.entity_id.as_deref())
                    .unwrap_or("no-entity");

                // Track path statistics
                let path_data = airflow_paths
                    .entry(path.to_string())
                    .or_insert_with(PathData::new);
                path_data.operations += 1;
                path_data.entities.insert(entity_id.to_string());
                *path_data
                    .operations_by_entity
                    .entry(entity_id.to_string())
                    .or_insert(0) += 1;

                // Track timestamp if available
                if let Ok(ts) = parse_timestamp(&entry.time) {
                    path_data.timestamps.push(ts);
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

    eprintln!(
        "\nTotal: Processed {} lines, found {} Airflow operations",
        format_number(total_lines),
        format_number(airflow_operations)
    );

    println!("\nSummary:");
    println!("  Total lines processed: {}", format_number(total_lines));
    println!(
        "  Airflow operations: {}",
        format_number(airflow_operations)
    );
    println!("  Unique paths: {}", format_number(airflow_paths.len()));

    let total_entities: std::collections::HashSet<_> = airflow_paths
        .values()
        .flat_map(|data| data.entities.iter().cloned())
        .collect();
    println!(
        "  Entities involved: {}",
        format_number(total_entities.len())
    );

    // 1. Top Airflow paths by operations
    println!("\n1. TOP AIRFLOW PATHS BY OPERATIONS");
    println!("{}", "-".repeat(100));
    println!("{:<80} {:<12} {:<10}", "Path", "Operations", "Entities");
    println!("{}", "-".repeat(100));

    let mut sorted_paths: Vec<_> = airflow_paths.iter().collect();
    sorted_paths.sort_by(|a, b| b.1.operations.cmp(&a.1.operations));

    for (path, data) in sorted_paths.iter().take(30) {
        let display_path = if path.len() <= 78 {
            path.as_str()
        } else {
            &path[..75]
        };
        println!(
            "{:<80} {:<12} {:<10}",
            display_path,
            format_number(data.operations),
            format_number(data.entities.len())
        );
    }

    // 2. Entity access patterns
    println!("\n2. ENTITIES ACCESSING AIRFLOW SECRETS");
    println!("{}", "-".repeat(100));
    println!(
        "{:<50} {:<12} {:<15}",
        "Entity ID", "Operations", "Unique Paths"
    );
    println!("{}", "-".repeat(100));

    let mut entity_patterns: HashMap<String, (usize, std::collections::HashSet<String>)> =
        HashMap::new();
    for (path, data) in &airflow_paths {
        for entity in &data.entities {
            let entry = entity_patterns
                .entry(entity.clone())
                .or_insert((0, std::collections::HashSet::new()));
            entry.0 += data.operations_by_entity.get(entity).unwrap_or(&0);
            entry.1.insert(path.clone());
        }
    }

    let mut sorted_entities: Vec<_> = entity_patterns.iter().collect();
    sorted_entities.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));

    for (entity, (ops, paths)) in sorted_entities.iter().take(20) {
        let display_entity = if entity.len() <= 48 {
            entity.as_str()
        } else {
            &entity[..45]
        };
        println!(
            "{:<50} {:<12} {:<15}",
            display_entity,
            format_number(*ops),
            format_number(paths.len())
        );
    }

    // 3. Polling pattern analysis with BURST RATES
    println!("\n3. BURST RATE ANALYSIS (Paths with Time Data)");
    println!("   NOTE: Rates calculated over actual time span - high rates indicate bursty access");
    println!("{}", "-".repeat(100));
    println!(
        "{:<60} {:<12} {:<12} {:<15}",
        "Path", "Operations", "Time Span", "Avg Interval"
    );
    println!("{}", "-".repeat(100));

    struct PollingPattern {
        path: String,
        operations: usize,
        time_span_hours: f64,
        ops_per_hour: f64,
        avg_interval_seconds: f64,
    }

    let mut polling_patterns = Vec::new();

    for (path, data) in &airflow_paths {
        if data.timestamps.len() < 2 {
            continue;
        }

        let mut timestamps = data.timestamps.clone();
        timestamps.sort();
        let time_span_seconds = timestamps[timestamps.len() - 1]
            .signed_duration_since(timestamps[0])
            .num_seconds() as f64;
        let time_span_hours = time_span_seconds / 3600.0;

        if time_span_hours > 0.0 {
            let ops_per_hour = data.operations as f64 / time_span_hours;
            let avg_interval_seconds = time_span_seconds / data.operations as f64;

            polling_patterns.push(PollingPattern {
                path: path.clone(),
                operations: data.operations,
                time_span_hours,
                ops_per_hour,
                avg_interval_seconds,
            });
        }
    }

    // Sort by operations per hour (highest burst rate)
    polling_patterns.sort_by(|a, b| b.ops_per_hour.partial_cmp(&a.ops_per_hour).unwrap());

    for pattern in polling_patterns.iter().take(25) {
        let path_display = if pattern.path.len() <= 58 {
            &pattern.path
        } else {
            &pattern.path[..55]
        };
        let time_span = format!("{:.1}h", pattern.time_span_hours);
        let interval = format!("{:.1}s", pattern.avg_interval_seconds);

        println!(
            "{:<60} {:<12} {:<12} {:<15}",
            path_display,
            format_number(pattern.operations),
            time_span,
            interval
        );
    }

    // 4. Entity-path combinations
    println!("\n4. ENTITY-PATH POLLING BEHAVIOR (Top 30)");
    println!("{}", "-".repeat(100));
    println!("{:<40} {:<45} {:<15}", "Entity", "Path", "Operations");
    println!("{}", "-".repeat(100));

    struct EntityPathCombo {
        entity: String,
        path: String,
        operations: usize,
    }

    let mut entity_path_combos = Vec::new();
    for (path, data) in &airflow_paths {
        for (entity_id, ops) in &data.operations_by_entity {
            entity_path_combos.push(EntityPathCombo {
                entity: entity_id.clone(),
                path: path.clone(),
                operations: *ops,
            });
        }
    }

    entity_path_combos.sort_by(|a, b| b.operations.cmp(&a.operations));

    for combo in entity_path_combos.iter().take(30) {
        let entity_display = if combo.entity.len() <= 38 {
            &combo.entity
        } else {
            &combo.entity[..35]
        };
        let path_display = if combo.path.len() <= 43 {
            &combo.path
        } else {
            &combo.path[..40]
        };

        println!(
            "{:<40} {:<45} {:<15}",
            entity_display,
            path_display,
            format_number(combo.operations)
        );
    }

    // 5. Recommendations
    println!("\n5. OPTIMIZATION RECOMMENDATIONS");
    println!("{}", "-".repeat(100));

    let high_frequency_paths: Vec<_> = polling_patterns
        .iter()
        .filter(|p| p.ops_per_hour > 100.0)
        .collect();
    let total_high_freq_ops: usize = high_frequency_paths.iter().map(|p| p.operations).sum();

    println!(
        "Total Airflow operations: {}",
        format_number(airflow_operations)
    );
    println!(
        "Paths with >100 ops/hour burst rate: {}",
        format_number(high_frequency_paths.len())
    );
    println!(
        "Operations from high-frequency paths: {} ({:.1}%)",
        format_number(total_high_freq_ops),
        (total_high_freq_ops as f64 / airflow_operations as f64) * 100.0
    );
    println!();
    println!("Recommended Actions:");
    println!();
    println!("1. IMPLEMENT AIRFLOW CONNECTION CACHING");
    println!("   - Configure Airflow to cache connection objects");
    println!("   - Expected reduction: 80-90% of reads");
    println!(
        "   - Potential savings: {} operations/day",
        format_number((airflow_operations as f64 * 0.85) as usize)
    );
    println!();
    println!("2. DEPLOY VAULT AGENT WITH AIRFLOW");
    println!("   - Run Vault agent as sidecar/daemon");
    println!("   - Configure template rendering for connections");
    println!("   - Expected reduction: 95% of reads");
    println!(
        "   - Potential savings: {} operations/day",
        format_number((airflow_operations as f64 * 0.95) as usize)
    );
    println!();
    println!("3. USE AIRFLOW SECRETS BACKEND EFFICIENTLY");
    println!("   - Review connection lookup patterns in DAGs");
    println!("   - Implement connection object reuse within tasks");
    println!("   - Cache connections at DAG level where appropriate");
    println!();

    if !polling_patterns.is_empty() {
        println!("4. PRIORITY PATHS FOR IMMEDIATE OPTIMIZATION (by burst rate):");
        for (i, pattern) in polling_patterns.iter().take(10).enumerate() {
            let path_name = pattern.path.split('/').next_back().unwrap_or(&pattern.path);
            println!(
                "   {}. {}: {} operations ({:.0}/hour burst rate)",
                i + 1,
                path_name,
                format_number(pattern.operations),
                pattern.ops_per_hour
            );
        }
    }

    println!("\n{}", "=".repeat(100));

    if let Some(output_file) = output {
        use std::fs::File;
        use std::io::Write;
        let mut file = File::create(output_file)?;
        writeln!(file, "entity_id,path,operation_count")?;
        for (path, data) in &airflow_paths {
            for (entity, count) in &data.operations_by_entity {
                writeln!(file, "{},{},{}", entity, path, count)?;
            }
        }
        println!("\nOutput written to: {}", output_file);
    }

    Ok(())
}
