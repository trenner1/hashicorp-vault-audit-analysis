//! Path hotspot analysis command.
//!
//! Identifies the most frequently accessed paths in Vault to help
//! understand usage patterns and potential performance bottlenecks.
//! Supports multi-file analysis for long-term trending.
//!
//! # Usage
//!
//! ```bash
//! # Single file - show top 20 hotspots (default)
//! vault-audit path-hotspots audit.log
//!
//! # Multi-day analysis with top 50
//! vault-audit path-hotspots logs/*.log --top 50
//!
//! # Filter by mount point across multiple files
//! vault-audit path-hotspots day*.log --mount secret
//! ```
//!
//! # Output
//!
//! Displays top accessed paths with:
//! - Path name
//! - Total operations
//! - Unique entities accessing
//! - Operation breakdown (read/write/list/delete)
//! - Access rate (ops per hour)
//! - Top entity contributors
//!
//! Helps identify:
//! - Performance bottlenecks
//! - Heavily used secrets
//! - Caching opportunities
//! - Load distribution

use crate::audit::types::AuditEntry;
use crate::utils::progress::ProgressBar;
use crate::utils::time::parse_timestamp;
use anyhow::Result;
use chrono::DateTime;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Statistics for a single path
#[derive(Debug)]
struct PathStats {
    operations: usize,
    entities: HashSet<String>,
    operations_by_type: HashMap<String, usize>,
    timestamps: Vec<DateTime<Utc>>,
    entity_operations: HashMap<String, usize>,
}

impl PathStats {
    fn new() -> Self {
        Self {
            operations: 0,
            entities: HashSet::new(),
            operations_by_type: HashMap::new(),
            timestamps: Vec::new(),
            entity_operations: HashMap::new(),
        }
    }
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

pub fn run(log_files: &[String], top: usize) -> Result<()> {
    let mut path_stats: HashMap<String, PathStats> = HashMap::new();
    let mut total_lines = 0;
    let mut total_operations = 0;

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

            let path = match &entry.request {
                Some(r) => match &r.path {
                    Some(p) => p.as_str(),
                    None => continue,
                },
                None => continue,
            };

            let operation = match &entry.request {
                Some(r) => match &r.operation {
                    Some(o) => o.as_str(),
                    None => continue,
                },
                None => continue,
            };

            total_operations += 1;

            let entity_id = entry
                .auth
                .as_ref()
                .and_then(|a| a.entity_id.as_deref())
                .unwrap_or("no-entity");

            // Parse timestamp
            let ts = parse_timestamp(&entry.time).ok();

            // Track path statistics
            let stats = path_stats
                .entry(path.to_string())
                .or_insert_with(PathStats::new);
            stats.operations += 1;
            stats.entities.insert(entity_id.to_string());
            *stats
                .operations_by_type
                .entry(operation.to_string())
                .or_insert(0) += 1;
            *stats
                .entity_operations
                .entry(entity_id.to_string())
                .or_insert(0) += 1;
            if let Some(t) = ts {
                stats.timestamps.push(t);
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
        "\nTotal: Processed {} lines, {} operations",
        format_number(total_lines),
        format_number(total_operations)
    );

    // Sort paths by operation count
    let mut sorted_paths: Vec<_> = path_stats.iter().collect();
    sorted_paths.sort_by(|a, b| b.1.operations.cmp(&a.1.operations));

    // 1. Summary table
    println!("\n{}", "=".repeat(120));
    println!("TOP {} PATH HOT SPOTS ANALYSIS", top);
    println!("{}", "=".repeat(120));

    println!(
        "\n{:<5} {:<60} {:<12} {:<10} {:<10} {:<10}",
        "#", "Path", "Ops", "Entities", "Top Op", "%"
    );
    println!("{}", "-".repeat(120));

    for (i, (path, data)) in sorted_paths.iter().take(top).enumerate() {
        let ops = data.operations;
        let entity_count = data.entities.len();
        let percentage = (ops as f64 / total_operations as f64) * 100.0;

        let top_op = data
            .operations_by_type
            .iter()
            .max_by_key(|x| x.1)
            .map(|x| x.0.as_str())
            .unwrap_or("N/A");

        let display_path = if path.len() <= 58 {
            path.to_string()
        } else {
            format!("{}...", &path[..55])
        };

        println!(
            "{:<5} {:<60} {:<12} {:<10} {:<10} {:<10.2}%",
            i + 1,
            display_path,
            format_number(ops),
            format_number(entity_count),
            top_op,
            percentage
        );
    }

    // 2. Detailed analysis for top 20 paths
    println!("\n\nDETAILED ANALYSIS OF TOP {} PATHS", top.min(20));
    println!("{}", "=".repeat(120));

    for (i, (path, data)) in sorted_paths.iter().take(top.min(20)).enumerate() {
        println!("\n{}. PATH: {}", i + 1, path);
        println!("{}", "-".repeat(120));

        let ops = data.operations;
        let entity_count = data.entities.len();
        let percentage = (ops as f64 / total_operations as f64) * 100.0;

        println!(
            "   Total Operations: {} ({:.2}% of all traffic)",
            format_number(ops),
            percentage
        );
        println!("   Unique Entities: {}", format_number(entity_count));

        // Calculate time span and rate
        if data.timestamps.len() >= 2 {
            let mut sorted_ts = data.timestamps.clone();
            sorted_ts.sort();
            let time_span = (sorted_ts
                .last()
                .unwrap()
                .signed_duration_since(*sorted_ts.first().unwrap()))
            .num_seconds() as f64
                / 3600.0;
            if time_span > 0.0 {
                let ops_per_hour = ops as f64 / time_span;
                println!(
                    "   Access Rate: {:.1} operations/hour ({:.2}/minute)",
                    ops_per_hour,
                    ops_per_hour / 60.0
                );
            }
        }

        // Operation breakdown
        println!("   Operations by type:");
        let mut ops_by_type: Vec<_> = data.operations_by_type.iter().collect();
        ops_by_type.sort_by(|a, b| b.1.cmp(a.1));
        for (op, count) in ops_by_type.iter().take(5) {
            let op_pct = (**count as f64 / ops as f64) * 100.0;
            println!(
                "      - {}: {} ({:.1}%)",
                op,
                format_number(**count),
                op_pct
            );
        }

        // Top entities
        let mut top_entities: Vec<_> = data.entity_operations.iter().collect();
        top_entities.sort_by(|a, b| b.1.cmp(a.1));
        if !top_entities.is_empty() {
            println!("   Top {} entities:", top_entities.len().min(5));
            for (entity_id, entity_ops) in top_entities.iter().take(5) {
                let entity_pct = (**entity_ops as f64 / ops as f64) * 100.0;
                let entity_display = if entity_id.len() <= 40 {
                    entity_id.to_string()
                } else {
                    format!("{}...", &entity_id[..37])
                };
                println!(
                    "      - {}: {} ops ({:.1}%)",
                    entity_display,
                    format_number(**entity_ops),
                    entity_pct
                );
            }
        }

        // Categorize and provide recommendations
        print!("   Category: ");
        let mut recommendations = Vec::new();

        if path.contains("token/lookup") {
            println!("TOKEN LOOKUP");
            recommendations
                .push("Implement client-side token TTL tracking to eliminate polling".to_string());
            recommendations.push(format!(
                "Potential reduction: 80-90% ({} operations)",
                format_number((ops as f64 * 0.85) as usize)
            ));
        } else if path.to_lowercase().contains("airflow") {
            println!("AIRFLOW SECRET");
            recommendations
                .push("Deploy Vault agent with template rendering for Airflow".to_string());
            recommendations.push("Configure connection caching in Airflow".to_string());
            recommendations.push(format!(
                "Potential reduction: 95% ({} operations)",
                format_number((ops as f64 * 0.95) as usize)
            ));
        } else if path.contains("approle/login") {
            println!("APPROLE AUTHENTICATION");
            if entity_count == 1 {
                recommendations.push(format!(
                    "⚠️  CRITICAL: Single entity making all {} login requests",
                    format_number(ops)
                ));
                recommendations
                    .push("Review token TTL configuration - may be too short".to_string());
                recommendations.push("Consider SecretID caching if appropriate".to_string());
            }
        } else if path.to_lowercase().contains("openshift")
            || path.to_lowercase().contains("kubernetes")
        {
            println!("KUBERNETES/OPENSHIFT AUTH");
            recommendations.push("Review pod authentication token TTLs".to_string());
            recommendations.push("Consider increasing default token lifetime".to_string());
            recommendations.push("Implement token renewal strategy in applications".to_string());
        } else if path.to_lowercase().contains("github") && path.contains("login") {
            println!("GITHUB AUTHENTICATION");
            recommendations.push("Review GitHub auth token TTLs".to_string());
            if entity_count == 1 {
                recommendations.push(format!(
                    "⚠️  Single entity ({}) - investigate why",
                    entity_count
                ));
            }
        } else if path.contains("data/") || path.contains("metadata/") {
            println!("KV SECRET ENGINE");
            if entity_count <= 3 && ops > 10000 {
                recommendations.push(format!(
                    "⚠️  HIGH-FREQUENCY ACCESS: {} operations from only {} entities",
                    format_number(ops),
                    entity_count
                ));
                recommendations.push("Implement caching layer or Vault agent".to_string());
                recommendations.push("Review if secret needs this frequency of access".to_string());
            } else {
                recommendations
                    .push("Consider Vault agent for high-frequency consumers".to_string());
            }
        } else {
            println!("OTHER");
            if ops > 5000 {
                recommendations.push(format!(
                    "High-volume path ({} operations) - review necessity",
                    format_number(ops)
                ));
            }
        }

        // Entity concentration check
        if let Some((_, top_entity_ops)) = top_entities.first() {
            let top_entity_pct = (**top_entity_ops as f64 / ops as f64) * 100.0;
            if top_entity_pct > 50.0 && !recommendations.iter().any(|r| r.contains("CRITICAL")) {
                recommendations.push(format!(
                    "⚠️  Entity concentration: Single entity responsible for {:.1}% of access",
                    top_entity_pct
                ));
            }
        }

        if !recommendations.is_empty() {
            println!("   Recommendations:");
            for rec in recommendations {
                println!("      • {}", rec);
            }
        }
    }

    // 3. Summary by category
    println!("\n\nSUMMARY BY PATH CATEGORY");
    println!("{}", "=".repeat(120));

    let mut categories: HashMap<&str, usize> = HashMap::new();
    categories.insert("Token Operations", 0);
    categories.insert("KV Secret Access", 0);
    categories.insert("Authentication", 0);
    categories.insert("Airflow Secrets", 0);
    categories.insert("System/Admin", 0);
    categories.insert("Other", 0);

    for (path, stats) in path_stats.iter() {
        let ops = stats.operations;
        if path.contains("token/") {
            *categories.get_mut("Token Operations").unwrap() += ops;
        } else if path.contains("/data/") || path.contains("/metadata/") {
            if path.to_lowercase().contains("airflow") {
                *categories.get_mut("Airflow Secrets").unwrap() += ops;
            } else {
                *categories.get_mut("KV Secret Access").unwrap() += ops;
            }
        } else if path.contains("/login") || path.contains("/auth/") {
            *categories.get_mut("Authentication").unwrap() += ops;
        } else if path.contains("sys/") {
            *categories.get_mut("System/Admin").unwrap() += ops;
        } else {
            *categories.get_mut("Other").unwrap() += ops;
        }
    }

    println!(
        "{:<30} {:<15} {:<15}",
        "Category", "Operations", "% of Total"
    );
    println!("{}", "-".repeat(120));

    let mut sorted_categories: Vec<_> = categories.iter().collect();
    sorted_categories.sort_by(|a, b| b.1.cmp(a.1));

    for (category, ops) in sorted_categories {
        let percentage = (*ops as f64 / total_operations as f64) * 100.0;
        println!(
            "{:<30} {:<15} {:<15.2}%",
            category,
            format_number(*ops),
            percentage
        );
    }

    println!("\n{}", "=".repeat(120));

    // 4. Overall recommendations
    println!("\nTOP OPTIMIZATION OPPORTUNITIES (by impact)");
    println!("{}", "=".repeat(120));

    struct Opportunity {
        name: String,
        current_ops: usize,
        potential_reduction: usize,
        effort: String,
        priority: u8,
    }

    let mut opportunities = Vec::new();

    // Calculate token lookup impact
    let token_lookup_ops: usize = path_stats
        .iter()
        .filter(|(path, _)| path.contains("token/lookup"))
        .map(|(_, stats)| stats.operations)
        .sum();

    if token_lookup_ops > 10000 {
        opportunities.push(Opportunity {
            name: "Eliminate Token Lookup Polling".to_string(),
            current_ops: token_lookup_ops,
            potential_reduction: (token_lookup_ops as f64 * 0.85) as usize,
            effort: "Medium".to_string(),
            priority: 1,
        });
    }

    // Calculate Airflow impact
    let airflow_ops: usize = path_stats
        .iter()
        .filter(|(path, _)| path.to_lowercase().contains("airflow"))
        .map(|(_, stats)| stats.operations)
        .sum();

    if airflow_ops > 10000 {
        opportunities.push(Opportunity {
            name: "Deploy Vault Agent for Airflow".to_string(),
            current_ops: airflow_ops,
            potential_reduction: (airflow_ops as f64 * 0.95) as usize,
            effort: "Medium".to_string(),
            priority: 2,
        });
    }

    // Calculate high-frequency path caching opportunities
    let high_freq_ops: usize = path_stats
        .iter()
        .filter(|(_, stats)| stats.operations > 5000 && stats.operations < 100000)
        .map(|(_, stats)| stats.operations)
        .sum();

    let high_freq_count = path_stats
        .iter()
        .filter(|(_, stats)| stats.operations > 5000 && stats.operations < 100000)
        .count();

    if high_freq_ops > 10000 {
        opportunities.push(Opportunity {
            name: format!("Cache High-Frequency Paths ({} paths)", high_freq_count),
            current_ops: high_freq_ops,
            potential_reduction: (high_freq_ops as f64 * 0.70) as usize,
            effort: "Low-Medium".to_string(),
            priority: 3,
        });
    }

    opportunities.sort_by_key(|o| o.priority);

    println!(
        "\n{:<10} {:<50} {:<15} {:<15} {:<15}",
        "Priority", "Opportunity", "Current Ops", "Savings", "Effort"
    );
    println!("{}", "-".repeat(120));

    let mut total_current_ops = 0;
    let mut total_savings = 0;

    for opp in &opportunities {
        println!(
            "{:<10} {:<50} {:<15} {:<15} {:<15}",
            opp.priority,
            opp.name,
            format_number(opp.current_ops),
            format_number(opp.potential_reduction),
            opp.effort
        );
        total_current_ops += opp.current_ops;
        total_savings += opp.potential_reduction;
    }

    println!("{}", "-".repeat(120));
    println!(
        "{:<10} {:<50} {:<15} {:<15}",
        "TOTAL POTENTIAL SAVINGS",
        "",
        format_number(total_current_ops),
        format_number(total_savings)
    );

    let projected_reduction = (total_savings as f64 / total_operations as f64) * 100.0;
    println!(
        "\nProjected reduction: {:.1}% of all Vault operations",
        projected_reduction
    );
    println!("{}", "=".repeat(120));

    Ok(())
}
