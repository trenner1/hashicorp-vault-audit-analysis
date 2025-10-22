//! Multi-day entity churn analysis.
//!
//! Tracks entity lifecycle across multiple audit log files to identify:
//! - New entities appearing each day
//! - Returning vs. churned entities
//! - Entity persistence patterns
//! - Authentication method usage trends
//!
//! # Usage
//!
//! ```bash
//! # Analyze entity churn across a week
//! vault-audit entity-churn day1.log day2.log day3.log day4.log day5.log day6.log day7.log
//!
//! # With baseline for accurate new entity detection
//! vault-audit entity-churn *.log --baseline baseline_entities.json
//!
//! # Export detailed churn data
//! vault-audit entity-churn *.log --output entity_churn.json
//! ```
//!
//! # Output
//!
//! Shows three categories of entities:
//! - **New**: Entities in current file not in baselines
//! - **Churned**: Entities in baselines but not in current
//! - **Active**: Entities present in both
//!
//! Only tracks entities that performed login operations (paths ending in `/login`).

use crate::audit::types::AuditEntry;
use crate::utils::progress::ProgressBar;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Entity mapping from baseline CSV files
#[derive(Debug, Serialize, Deserialize)]
struct EntityMapping {
    display_name: String,
    mount_path: String,
    #[allow(dead_code)]
    mount_accessor: String,
    #[allow(dead_code)]
    login_count: usize,
    #[allow(dead_code)]
    first_seen: String,
    #[allow(dead_code)]
    last_seen: String,
}

/// Represents an entity's churn status
#[derive(Debug, Serialize)]
struct EntityChurnRecord {
    entity_id: String,
    display_name: String,
    mount_path: String,
    mount_type: String,
    first_seen_file: String,
    first_seen_time: DateTime<Utc>,
    files_appeared: Vec<String>,
    total_logins: usize,
    lifecycle: String, // "new_day_1", "new_day_2", "new_day_3", "pre_existing"
}

#[derive(Debug)]
struct DailyStats {
    #[allow(dead_code)]
    file_name: String,
    new_entities: usize,
    returning_entities: usize,
    total_logins: usize,
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

fn get_file_size(path: &str) -> Result<u64> {
    Ok(std::fs::metadata(path)?.len())
}

fn load_entity_mappings(path: &str) -> Result<HashMap<String, EntityMapping>> {
    let file = File::open(path).context("Failed to open entity map file")?;
    let mappings: HashMap<String, EntityMapping> =
        serde_json::from_reader(file).context("Failed to parse entity map JSON")?;
    Ok(mappings)
}

#[derive(Deserialize)]
struct JsonEntity {
    entity_id: String,
}

fn load_baseline_entities(path: &str) -> Result<HashSet<String>> {
    let file = File::open(path).context("Failed to open baseline entities file")?;

    // Check if it's JSON or CSV based on file extension or first character
    let path_lower = path.to_lowercase();
    if path_lower.ends_with(".json") {
        // JSON format from entity-list with --format json
        let entities: Vec<JsonEntity> =
            serde_json::from_reader(file).context("Failed to parse baseline entities JSON")?;
        Ok(entities.into_iter().map(|e| e.entity_id).collect())
    } else {
        // CSV format (default entity-list output)
        let mut reader = BufReader::new(file);
        let mut entity_ids = HashSet::new();
        let mut line = String::new();

        // Skip header line
        reader.read_line(&mut line)?;

        // Read entity IDs from first column
        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line)?;
            if bytes_read == 0 {
                break; // EOF
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Extract entity_id from first CSV column
            if let Some(entity_id) = trimmed.split(',').next() {
                if !entity_id.is_empty() {
                    entity_ids.insert(entity_id.to_string());
                }
            }
        }

        Ok(entity_ids)
    }
}

pub fn run(
    log_files: &[String],
    entity_map: Option<&str>,
    baseline_entities: Option<&str>,
    output: Option<&str>,
) -> Result<()> {
    println!("\n=== Multi-Day Entity Churn Analysis ===\n");
    println!("Analyzing {} log files:", log_files.len());
    for (i, file) in log_files.iter().enumerate() {
        let size = get_file_size(file)?;
        println!(
            "  Day {}: {} ({:.2} GB)",
            i + 1,
            file,
            size as f64 / 1_000_000_000.0
        );
    }
    println!();

    // Load baseline entities if provided
    let baseline = if let Some(path) = baseline_entities {
        println!("Loading baseline entity list from {}...", path);
        let baseline_set = load_baseline_entities(path)?;
        println!(
            "Loaded {} pre-existing entities from baseline",
            format_number(baseline_set.len())
        );
        println!();
        Some(baseline_set)
    } else {
        println!("⚠️  No baseline entity list provided. Cannot distinguish truly NEW entities from pre-existing.");
        println!("   All Day 1 entities will be marked as 'pre_existing_or_new_day_1'.");
        println!("   To get accurate results, run: ./vault-audit entity-list --output baseline_entities.json\n");
        None
    };

    // Load entity mappings if provided (currently unused, but kept for future enhancement)
    let _entity_mappings = if let Some(path) = entity_map {
        println!("Loading entity mappings from {}...", path);
        Some(load_entity_mappings(path)?)
    } else {
        None
    };

    // Track all entities across all files
    let mut entities: HashMap<String, EntityChurnRecord> = HashMap::new();
    let mut daily_stats: Vec<DailyStats> = Vec::new();

    // Process each log file in order
    for (file_idx, log_file) in log_files.iter().enumerate() {
        let file_name = Path::new(log_file)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        println!("\nProcessing Day {} ({})...", file_idx + 1, file_name);

        let file = File::open(log_file)
            .with_context(|| format!("Failed to open log file: {}", log_file))?;
        let file_size = get_file_size(log_file)? as usize;

        let reader = BufReader::new(file);
        let mut progress = ProgressBar::new(file_size, "Processing");

        let mut new_entities_this_file = 0;
        let mut returning_entities_this_file = HashSet::new();
        let mut logins_this_file = 0;
        let mut bytes_processed = 0;

        for line in reader.lines() {
            let line = line.context("Failed to read line from log file")?;
            bytes_processed += line.len() + 1; // +1 for newline

            // Update progress periodically
            if bytes_processed % 10_000 == 0 {
                progress.update(bytes_processed.min(file_size));
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let entry: AuditEntry = match serde_json::from_str(trimmed) {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Only process login operations (auth paths ending in /login)
            let Some(ref request) = entry.request else {
                continue;
            };
            let Some(ref path) = request.path else {
                continue;
            };
            if !path.ends_with("/login") {
                continue;
            }

            logins_this_file += 1;

            // Extract entity info
            let Some(ref auth) = entry.auth else {
                continue;
            };
            let Some(ref entity_id) = auth.entity_id else {
                continue;
            };

            let display_name = auth
                .display_name
                .clone()
                .unwrap_or_else(|| entity_id.clone());
            let mount_path = request.path.clone().unwrap_or_default();
            let mount_type = auth.token_type.clone().unwrap_or_default();

            // Parse timestamp
            let first_seen_time = chrono::DateTime::parse_from_rfc3339(&entry.time)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);

            // Check if this entity exists from a previous file
            if let Some(entity_record) = entities.get_mut(entity_id) {
                // Returning entity
                entity_record.total_logins += 1;
                if !entity_record.files_appeared.contains(&file_name) {
                    entity_record.files_appeared.push(file_name.clone());
                }
                returning_entities_this_file.insert(entity_id.clone());
            } else {
                // New entity (first time across all files)
                new_entities_this_file += 1;

                // Determine lifecycle based on baseline and which file this is
                let lifecycle = if let Some(ref baseline_set) = baseline {
                    if baseline_set.contains(entity_id) {
                        "pre_existing_baseline".to_string()
                    } else {
                        // Not in baseline, so truly NEW during analysis period
                        match file_idx {
                            0 => "new_day_1".to_string(),
                            1 => "new_day_2".to_string(),
                            2 => "new_day_3".to_string(),
                            _ => format!("new_day_{}", file_idx + 1),
                        }
                    }
                } else {
                    // No baseline provided, can't distinguish
                    match file_idx {
                        0 => "pre_existing_or_new_day_1".to_string(),
                        1 => "new_day_2".to_string(),
                        2 => "new_day_3".to_string(),
                        _ => format!("new_day_{}", file_idx + 1),
                    }
                };

                entities.insert(
                    entity_id.clone(),
                    EntityChurnRecord {
                        entity_id: entity_id.clone(),
                        display_name,
                        mount_path,
                        mount_type,
                        first_seen_file: file_name.clone(),
                        first_seen_time,
                        files_appeared: vec![file_name.clone()],
                        total_logins: 1,
                        lifecycle,
                    },
                );
            }
        }

        progress.finish();

        daily_stats.push(DailyStats {
            file_name,
            new_entities: new_entities_this_file,
            returning_entities: returning_entities_this_file.len(),
            total_logins: logins_this_file,
        });

        println!(
            "Day {} Summary: {} new entities, {} returning, {} logins",
            file_idx + 1,
            format_number(new_entities_this_file),
            format_number(returning_entities_this_file.len()),
            format_number(logins_this_file)
        );
    }

    // Generate final report
    println!("\n=== Entity Churn Analysis ===\n");

    println!("Daily Breakdown:");
    for (idx, stats) in daily_stats.iter().enumerate() {
        println!(
            "  Day {}: {} new, {} returning, {} total logins",
            idx + 1,
            format_number(stats.new_entities),
            format_number(stats.returning_entities),
            format_number(stats.total_logins)
        );
    }

    // Lifecycle classification
    let mut lifecycle_counts: HashMap<String, usize> = HashMap::new();
    let mut entities_by_file_count: HashMap<usize, usize> = HashMap::new();

    for entity in entities.values() {
        *lifecycle_counts
            .entry(entity.lifecycle.clone())
            .or_insert(0) += 1;
        *entities_by_file_count
            .entry(entity.files_appeared.len())
            .or_insert(0) += 1;
    }

    println!("\nEntity Lifecycle Classification:");
    let mut lifecycle_vec: Vec<_> = lifecycle_counts.iter().collect();
    lifecycle_vec.sort_by_key(|(k, _)| *k);
    for (lifecycle, count) in lifecycle_vec {
        println!("  {}: {}", lifecycle, format_number(*count));
    }

    println!("\nEntity Persistence:");
    for day_count in 1..=log_files.len() {
        if let Some(count) = entities_by_file_count.get(&day_count) {
            let label = if day_count == 1 {
                "Appeared 1 day only"
            } else if day_count == log_files.len() {
                "Appeared all days (persistent)"
            } else {
                "Appeared some days"
            };
            println!(
                "  {} day(s): {} entities ({})",
                day_count,
                format_number(*count),
                label
            );
        }
    }

    // Mount path breakdown
    let mut mount_stats: HashMap<String, (usize, String)> = HashMap::new();
    for entity in entities.values() {
        let entry = mount_stats
            .entry(entity.mount_path.clone())
            .or_insert((0, entity.mount_type.clone()));
        entry.0 += 1;
    }

    println!("\nTop Authentication Methods (Total Entities):");
    let mut mount_vec: Vec<_> = mount_stats.iter().collect();
    mount_vec.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));

    for (idx, (path, (count, mount_type))) in mount_vec.iter().take(20).enumerate() {
        println!(
            "  {}. {} ({}): {}",
            idx + 1,
            path,
            mount_type,
            format_number(*count)
        );
    }

    // Calculate GitHub duplication if present
    let github_entities: Vec<_> = entities
        .values()
        .filter(|e| e.mount_path.contains("/github"))
        .collect();

    if !github_entities.is_empty() {
        println!("\n=== GitHub Entity Analysis ===");
        println!(
            "Total GitHub entities: {}",
            format_number(github_entities.len())
        );

        // Extract repo names and count duplicates
        let mut repo_counts: HashMap<String, usize> = HashMap::new();
        for entity in &github_entities {
            // Extract repo from "github-repo:org/repo:..." pattern
            if let Some(repo) = entity.display_name.split(':').nth(1) {
                *repo_counts.entry(repo.to_string()).or_insert(0) += 1;
            }
        }

        println!("Unique repositories: {}", format_number(repo_counts.len()));
        println!("\nTop repositories by entity count:");
        let mut repo_vec: Vec<_> = repo_counts.iter().collect();
        repo_vec.sort_by(|a, b| b.1.cmp(a.1));

        for (idx, (repo, count)) in repo_vec.iter().take(20).enumerate() {
            if **count > 1 {
                println!(
                    "  {}. {}: {} entities",
                    idx + 1,
                    repo,
                    format_number(**count)
                );
            }
        }
    }

    // Export to JSON if requested
    if let Some(output_path) = output {
        println!("\nExporting detailed entity records to {}...", output_path);
        let mut entities_vec: Vec<_> = entities.into_values().collect();
        entities_vec.sort_by(|a, b| a.first_seen_time.cmp(&b.first_seen_time));

        let output_file = File::create(output_path)
            .with_context(|| format!("Failed to create output file: {}", output_path))?;
        serde_json::to_writer_pretty(output_file, &entities_vec)
            .context("Failed to write JSON output")?;
        println!(
            "Exported {} entity records",
            format_number(entities_vec.len())
        );
    }

    println!("\n=== Analysis Complete ===\n");
    Ok(())
}
