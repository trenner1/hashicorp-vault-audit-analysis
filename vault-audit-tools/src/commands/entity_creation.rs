//! Entity creation analysis command.
//!
//! Identifies when entities first appear in audit logs, grouped by
//! authentication method and mount path.
//! Supports multi-file analysis for tracking entity creation over time.
//!
//! # Usage
//!
//! ```bash
//! # Single file analysis
//! vault-audit entity-creation audit.log
//!
//! # Multi-day analysis
//! vault-audit entity-creation logs/*.log --output entity-creation.json
//!
//! # With entity mappings from entity-list (CSV or JSON)
//! vault-audit entity-creation logs/*.log --entity-map entities.csv
//! vault-audit entity-creation logs/*.log --entity-map entities.json
//! ```
//!
//! # Output
//!
//! Displays entity creation events grouped by authentication path:
//! - Entity ID
//! - Display name
//! - Mount path (authentication method)
//! - First seen timestamp
//! - Creation count by auth method
//!
//! Use `--json` to output structured data for further processing.

use crate::audit::types::AuditEntry;
use crate::utils::progress::ProgressBar;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Entity mapping data structure for JSON output
#[derive(Debug, Serialize, Deserialize)]
struct EntityMapping {
    display_name: String,
    mount_path: String,
    #[allow(dead_code)]
    mount_accessor: String,
    #[allow(dead_code)]
    username: Option<String>,
    #[allow(dead_code)]
    login_count: usize,
    #[allow(dead_code)]
    first_seen: String,
    #[allow(dead_code)]
    last_seen: String,
}

/// Represents a single entity creation event
#[derive(Debug)]
struct EntityCreation {
    entity_id: String,
    display_name: String,
    mount_path: String,
    mount_type: String,
    first_seen: DateTime<Utc>,
    login_count: usize,
}

#[derive(Debug)]
struct MountStats {
    mount_path: String,
    mount_type: String,
    entities_created: usize,
    total_logins: usize,
    sample_entities: Vec<String>, // Store up to 5 sample display names
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

/// Load entity mappings from either JSON or CSV format
fn load_entity_mappings(path: &str) -> Result<HashMap<String, EntityMapping>> {
    let file =
        File::open(path).with_context(|| format!("Failed to open entity map file: {}", path))?;

    // Auto-detect format based on file extension or content
    let path_lower = path.to_lowercase();
    if path_lower.ends_with(".json") {
        // JSON format (from preprocess-entities)
        serde_json::from_reader(file)
            .with_context(|| format!("Failed to parse entity map JSON: {}", path))
    } else if path_lower.ends_with(".csv") {
        // CSV format (from entity-list)
        let mut reader = csv::Reader::from_reader(file);
        let mut mappings = HashMap::new();

        for result in reader.records() {
            let record = result?;
            if record.len() < 8 {
                continue; // Skip malformed rows
            }

            let entity_id = record.get(0).unwrap_or("").to_string();
            let display_name = record.get(1).unwrap_or("").to_string();
            let mount_path = record.get(7).unwrap_or("").to_string(); // mount_path column
            let mount_accessor = record.get(9).unwrap_or("").to_string(); // mount_accessor column

            if !entity_id.is_empty() {
                mappings.insert(
                    entity_id,
                    EntityMapping {
                        display_name,
                        mount_path,
                        mount_accessor,
                        username: None,
                        login_count: 0,
                        first_seen: String::new(),
                        last_seen: String::new(),
                    },
                );
            }
        }

        Ok(mappings)
    } else {
        // Try JSON first, fall back to CSV
        let file = File::open(path)?;
        match serde_json::from_reader::<_, HashMap<String, EntityMapping>>(file) {
            Ok(mappings) => Ok(mappings),
            Err(_) => {
                // Try CSV
                let file = File::open(path)?;
                let mut reader = csv::Reader::from_reader(file);
                let mut mappings = HashMap::new();

                for result in reader.records() {
                    let record = result?;
                    if record.len() < 8 {
                        continue;
                    }

                    let entity_id = record.get(0).unwrap_or("").to_string();
                    let display_name = record.get(1).unwrap_or("").to_string();
                    let mount_path = record.get(7).unwrap_or("").to_string();
                    let mount_accessor = record.get(9).unwrap_or("").to_string();

                    if !entity_id.is_empty() {
                        mappings.insert(
                            entity_id,
                            EntityMapping {
                                display_name,
                                mount_path,
                                mount_accessor,
                                username: None,
                                login_count: 0,
                                first_seen: String::new(),
                                last_seen: String::new(),
                            },
                        );
                    }
                }

                Ok(mappings)
            }
        }
    }
}

pub fn run(
    log_files: &[String],
    entity_map_file: Option<&str>,
    output: Option<&str>,
) -> Result<()> {
    eprintln!("Analyzing entity creation by authentication path...\n");

    // Load entity mappings if provided (supports both JSON and CSV)
    let entity_mappings: HashMap<String, EntityMapping> = if let Some(map_file) = entity_map_file {
        eprintln!("Loading entity mappings from: {}", map_file);
        load_entity_mappings(map_file)?
    } else {
        HashMap::new()
    };

    if !entity_mappings.is_empty() {
        eprintln!(
            "Loaded {} entity mappings for display name enrichment\n",
            format_number(entity_mappings.len())
        );
    }

    let mut entity_creations: HashMap<String, EntityCreation> = HashMap::new();
    let mut seen_entities: HashSet<String> = HashSet::new();
    let mut lines_processed = 0;
    let mut login_events = 0;
    let mut new_entities_found = 0;

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

        let file = File::open(log_file)
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

            // Look for login events in auth paths
            let request = match &entry.request {
                Some(r) => r,
                None => continue,
            };

            let path = match &request.path {
                Some(p) => p.as_str(),
                None => continue,
            };

            if !path.starts_with("auth/") || !path.contains("/login") {
                continue;
            }

            let auth = match &entry.auth {
                Some(a) => a,
                None => continue,
            };

            let entity_id = match &auth.entity_id {
                Some(id) if !id.is_empty() => id.clone(),
                _ => continue,
            };

            login_events += 1;

            // Check if this is the first time we've seen this entity
            let is_new_entity = seen_entities.insert(entity_id.clone());

            if is_new_entity {
                new_entities_found += 1;

                let display_name = auth
                    .display_name
                    .clone()
                    .or_else(|| {
                        entity_mappings
                            .get(&entity_id)
                            .map(|m| m.display_name.clone())
                    })
                    .unwrap_or_else(|| "unknown".to_string());

                let mount_path = path
                    .trim_end_matches("/login")
                    .trim_end_matches(&format!("/{}", display_name))
                    .to_string();

                let mount_type = request
                    .mount_type
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());

                let first_seen = match chrono::DateTime::parse_from_rfc3339(&entry.time) {
                    Ok(dt) => dt.with_timezone(&Utc),
                    Err(_) => Utc::now(),
                };

                entity_creations.insert(
                    entity_id.clone(),
                    EntityCreation {
                        entity_id,
                        display_name,
                        mount_path,
                        mount_type,
                        first_seen,
                        login_count: 1,
                    },
                );
            } else {
                // Increment login count for existing entity
                if let Some(creation) = entity_creations.get_mut(&entity_id) {
                    creation.login_count += 1;
                }
            }
        }

        if let Some(size) = file_size {
            progress.update(size);
        } else {
            progress.update(file_lines);
        }

        progress.finish_with_message(&format!("Processed {} lines from this file", file_lines));
    }

    eprintln!(
        "\nTotal: Processed {} lines, {} login events, {} new entities created",
        format_number(lines_processed),
        format_number(login_events),
        format_number(new_entities_found)
    );

    // Aggregate by mount path
    let mut mount_stats: HashMap<String, MountStats> = HashMap::new();

    for creation in entity_creations.values() {
        let key = creation.mount_path.clone();
        mount_stats
            .entry(key.clone())
            .and_modify(|stats| {
                stats.entities_created += 1;
                stats.total_logins += creation.login_count;
                if stats.sample_entities.len() < 5 {
                    stats.sample_entities.push(creation.display_name.clone());
                }
            })
            .or_insert_with(|| MountStats {
                mount_path: creation.mount_path.clone(),
                mount_type: creation.mount_type.clone(),
                entities_created: 1,
                total_logins: creation.login_count,
                sample_entities: vec![creation.display_name.clone()],
            });
    }

    // Sort by entities created
    let mut sorted_mounts: Vec<_> = mount_stats.values().collect();
    sorted_mounts.sort_by(|a, b| b.entities_created.cmp(&a.entities_created));

    // Print report
    eprintln!("\n{}", "=".repeat(100));
    eprintln!("ENTITY CREATION ANALYSIS BY AUTHENTICATION PATH");
    eprintln!("{}", "=".repeat(100));
    eprintln!();
    eprintln!("Summary:");
    eprintln!("  Total login events: {}", format_number(login_events));
    eprintln!(
        "  Unique entities discovered: {}",
        format_number(new_entities_found)
    );
    eprintln!(
        "  Authentication methods: {}",
        format_number(mount_stats.len())
    );
    eprintln!();
    eprintln!("{}", "-".repeat(100));
    eprintln!(
        "{:<50} {:<15} {:<15} {:<20}",
        "Authentication Path", "Mount Type", "Entities", "Total Logins"
    );
    eprintln!("{}", "-".repeat(100));

    for stats in &sorted_mounts {
        eprintln!(
            "{:<50} {:<15} {:>15} {:>15}",
            if stats.mount_path.len() > 49 {
                format!("{}...", &stats.mount_path[..46])
            } else {
                stats.mount_path.clone()
            },
            if stats.mount_type.len() > 14 {
                format!("{}...", &stats.mount_type[..11])
            } else {
                stats.mount_type.clone()
            },
            format_number(stats.entities_created),
            format_number(stats.total_logins)
        );
    }

    eprintln!("{}", "-".repeat(100));
    eprintln!();

    // Show top 10 with sample entities
    eprintln!("Top 10 Authentication Paths with Sample Entities:");
    eprintln!("{}", "=".repeat(100));
    for (i, stats) in sorted_mounts.iter().take(10).enumerate() {
        eprintln!();
        eprintln!("{}. {} ({})", i + 1, stats.mount_path, stats.mount_type);
        eprintln!(
            "   Entities created: {} | Total logins: {}",
            format_number(stats.entities_created),
            format_number(stats.total_logins)
        );
        eprintln!("   Sample entities:");
        for (j, name) in stats.sample_entities.iter().enumerate() {
            eprintln!("      {}. {}", j + 1, name);
        }
    }
    eprintln!();
    eprintln!("{}", "=".repeat(100));

    // Write detailed output if requested
    if let Some(output_file) = output {
        eprintln!(
            "\nWriting detailed entity creation data to: {}",
            output_file
        );

        let mut entities: Vec<_> = entity_creations.values().collect();
        entities.sort_by(|a, b| a.first_seen.cmp(&b.first_seen));

        #[derive(Serialize)]
        struct EntityCreationOutput {
            entity_id: String,
            display_name: String,
            mount_path: String,
            mount_type: String,
            first_seen: String,
            login_count: usize,
        }

        let output_data: Vec<EntityCreationOutput> = entities
            .into_iter()
            .map(|e| EntityCreationOutput {
                entity_id: e.entity_id.clone(),
                display_name: e.display_name.clone(),
                mount_path: e.mount_path.clone(),
                mount_type: e.mount_type.clone(),
                first_seen: e.first_seen.to_rfc3339(),
                login_count: e.login_count,
            })
            .collect();

        let output_file_handle = File::create(output_file)
            .with_context(|| format!("Failed to create output file: {}", output_file))?;
        serde_json::to_writer_pretty(output_file_handle, &output_data)
            .with_context(|| format!("Failed to write JSON output: {}", output_file))?;

        eprintln!(
            "✓ Wrote {} entity records to {}",
            format_number(output_data.len()),
            output_file
        );
    }

    Ok(())
}
