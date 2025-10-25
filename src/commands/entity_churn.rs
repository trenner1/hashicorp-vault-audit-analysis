//! Multi-day entity churn analysis with intelligent ephemeral pattern detection.
//!
//! ⚠️ **DEPRECATED**: Use `entity-analysis churn` instead.
//!
//! ```bash
//! # Old (deprecated):
//! vault-audit entity-churn day1.log day2.log day3.log
//!
//! # New (recommended):
//! vault-audit entity-analysis churn day1.log day2.log day3.log
//! ```
//!
//! See [`entity_analysis`](crate::commands::entity_analysis) for the unified command.
//!
//! ---
//!
//! Tracks entity lifecycle across multiple audit log files (compressed or uncompressed)
//! to identify:
//! - New entities appearing each day
//! - Returning vs. churned entities
//! - Entity persistence patterns
//! - Authentication method usage trends
//! - **Ephemeral entities** using data-driven pattern learning
//!
//! # Usage
//!
//! ```bash
//! # Analyze entity churn across a week (compressed files)
//! vault-audit entity-churn day1.log.gz day2.log.gz day3.log.gz day4.log.gz day5.log.gz day6.log.gz day7.log.gz
//!
//! # With baseline for accurate new entity detection
//! vault-audit entity-churn *.log --baseline baseline_entities.json
//!
//! # With entity mappings for enriched display names
//! vault-audit entity-churn *.log --baseline baseline.json --entity-map entity_mappings.json
//!
//! # Export detailed churn data with ephemeral analysis
//! vault-audit entity-churn *.log --output entity_churn.json
//!
//! # Export as CSV format
//! vault-audit entity-churn *.log --output entity_churn.csv --format csv
//! ```
//!
//! **Compressed File Support**: Automatically handles `.gz` and `.zst` files - no manual
//! decompression required. Mix compressed and uncompressed files freely.
//!
//! # Ephemeral Pattern Detection
//!
//! The command uses a sophisticated two-pass analysis to detect ephemeral entities
//! (e.g., CI/CD pipeline entities, temporary build entities) with confidence scoring:
//!
//! **Pass 1: Data Collection**
//! - Track all entities across log files
//! - Record first/last seen times and files
//! - Count login activity per entity
//!
//! **Pass 2: Pattern Learning & Classification**
//! - Learn patterns from entities that appeared 1-2 days
//! - Identify naming patterns (e.g., `github-repo:org/repo:ref:branch`)
//! - Calculate confidence scores (0.0-1.0) based on:
//!   - Days active (1 day = high confidence, 2 days = medium)
//!   - Similar entities on same mount path
//!   - Activity levels (low login counts)
//!   - Gaps in activity (reduces confidence for sporadic access)
//!
//! # Output
//!
//! ## Entity Lifecycle Classification:
//! - **`new_day_N`**: Entities first seen on day N (not in baseline)
//! - **`pre_existing_baseline`**: Entities that existed before analysis period
//!
//! ## Activity Patterns:
//! - **consistent**: Appeared in most/all log files
//! - **sporadic**: Appeared intermittently with gaps
//! - **declining**: Activity decreased over time
//! - **`single_burst`**: Appeared only once
//!
//! ## Ephemeral Detection:
//! - Confidence levels: High (≥70%), Medium (50-69%), Low (40-49%)
//! - Detailed reasoning for each classification
//! - Top ephemeral entities by confidence
//! - Pattern statistics and mount path analysis
//!
//! # JSON Output Fields
//!
//! When using `--output`, each entity record includes:
//! - `entity_id`: Vault entity identifier
//! - `display_name`: Human-readable name
//! - `first_seen_file` / `first_seen_time`: When first observed
//! - `last_seen_file` / `last_seen_time`: When last observed
//! - `files_appeared`: List of log files entity was active in
//! - `total_logins`: Total login count across all files
//! - `lifecycle`: Entity lifecycle classification
//! - `activity_pattern`: Behavioral pattern classification
//! - `is_ephemeral_pattern`: Boolean flag for ephemeral detection
//! - `ephemeral_confidence`: Confidence score (0.0-1.0)
//! - `ephemeral_reasons`: Array of human-readable reasons
//!
//! Only tracks entities that performed login operations (paths ending in `/login`).

use crate::audit::types::AuditEntry;
use crate::utils::format::format_number;
use crate::utils::progress::ProgressBar;
use crate::utils::reader::open_file;
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
#[derive(Debug, Serialize, Clone)]
struct EntityChurnRecord {
    entity_id: String,
    display_name: String,
    mount_path: String,
    mount_type: String,
    token_type: String,
    first_seen_file: String,
    first_seen_time: DateTime<Utc>,
    last_seen_file: String,
    last_seen_time: DateTime<Utc>,
    files_appeared: Vec<String>,
    total_logins: usize,
    lifecycle: String, // "new_day_1", "new_day_2", "new_day_3", "pre_existing"
    activity_pattern: String, // "consistent", "sporadic", "declining", "single_burst", "unknown"
    is_ephemeral_pattern: bool,
    ephemeral_confidence: f32, // 0.0 to 1.0
    ephemeral_reasons: Vec<String>,
    // Baseline metadata (if entity existed in baseline)
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline_entity_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline_created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline_alias_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline_mount_path: Option<String>,
    // Entity-map metadata (from historical audit logs via preprocess-entities)
    #[serde(skip_serializing_if = "Option::is_none")]
    historical_display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    historical_first_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    historical_last_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    historical_login_count: Option<usize>,
}

/// CSV-compatible representation of entity churn record
#[derive(Debug, Serialize)]
struct EntityChurnRecordCsv {
    entity_id: String,
    display_name: String,
    mount_path: String,
    mount_type: String,
    token_type: String,
    first_seen_file: String,
    first_seen_time: String,
    last_seen_file: String,
    last_seen_time: String,
    files_appeared: String, // Comma-separated list
    days_active: usize,
    total_logins: usize,
    lifecycle: String,
    activity_pattern: String,
    is_ephemeral_pattern: bool,
    ephemeral_confidence: f32,
    ephemeral_reasons: String, // Semicolon-separated list
    baseline_entity_name: String,
    baseline_created: String,
    baseline_alias_name: String,
    baseline_mount_path: String,
    historical_display_name: String,
    historical_first_seen: String,
    historical_last_seen: String,
    historical_login_count: String,
}

impl From<EntityChurnRecord> for EntityChurnRecordCsv {
    fn from(record: EntityChurnRecord) -> Self {
        Self {
            entity_id: record.entity_id,
            display_name: record.display_name,
            mount_path: record.mount_path,
            mount_type: record.mount_type,
            token_type: record.token_type,
            first_seen_file: record.first_seen_file,
            first_seen_time: record.first_seen_time.to_rfc3339(),
            last_seen_file: record.last_seen_file,
            last_seen_time: record.last_seen_time.to_rfc3339(),
            files_appeared: record.files_appeared.join(", "),
            days_active: record.files_appeared.len(),
            total_logins: record.total_logins,
            lifecycle: record.lifecycle,
            activity_pattern: record.activity_pattern,
            is_ephemeral_pattern: record.is_ephemeral_pattern,
            ephemeral_confidence: record.ephemeral_confidence,
            ephemeral_reasons: record.ephemeral_reasons.join("; "),
            baseline_entity_name: record.baseline_entity_name.unwrap_or_default(),
            baseline_created: record.baseline_created.unwrap_or_default(),
            baseline_alias_name: record.baseline_alias_name.unwrap_or_default(),
            baseline_mount_path: record.baseline_mount_path.unwrap_or_default(),
            historical_display_name: record.historical_display_name.unwrap_or_default(),
            historical_first_seen: record.historical_first_seen.unwrap_or_default(),
            historical_last_seen: record.historical_last_seen.unwrap_or_default(),
            historical_login_count: record
                .historical_login_count
                .map(|n| n.to_string())
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug)]
struct DailyStats {
    #[allow(dead_code)]
    file_name: String,
    new_entities: usize,
    returning_entities: usize,
    total_logins: usize,
}

/// Analyzes entity behavior patterns to detect ephemeral entities
#[derive(Debug)]
struct EphemeralPatternAnalyzer {
    total_files: usize,
    short_lived_patterns: Vec<ShortLivedPattern>,
}

#[derive(Debug)]
struct ShortLivedPattern {
    days_active: usize,
    display_name: String,
    mount_path: String,
}

impl EphemeralPatternAnalyzer {
    const fn new(total_files: usize) -> Self {
        Self {
            total_files,
            short_lived_patterns: Vec::new(),
        }
    }

    /// Learn patterns from entities that appeared 1-2 days (potential ephemeral patterns)
    fn learn_from_entities(&mut self, entities: &HashMap<String, EntityChurnRecord>) {
        for entity in entities.values() {
            let days_active = entity.files_appeared.len();

            // Learn from entities that appeared 1-2 days only
            if days_active <= 2 {
                self.short_lived_patterns.push(ShortLivedPattern {
                    days_active,
                    display_name: entity.display_name.clone(),
                    mount_path: entity.mount_path.clone(),
                });
            }
        }
    }

    /// Analyze an entity and determine if it matches ephemeral patterns
    fn analyze_entity(&self, entity: &EntityChurnRecord) -> (bool, f32, Vec<String>) {
        let days_active = entity.files_appeared.len();
        let mut confidence = 0.0;
        let mut reasons = Vec::new();

        // Strong indicators (high confidence)
        if days_active == 1 {
            confidence += 0.5;
            reasons.push(format!("Appeared only 1 day ({})", entity.first_seen_file));
        } else if days_active == 2 {
            confidence += 0.3;
            reasons.push(format!(
                "Appeared only 2 days: {}, {}",
                entity.files_appeared.first().unwrap_or(&String::new()),
                entity.files_appeared.last().unwrap_or(&String::new())
            ));
        }

        // Pattern matching: Check if display name follows patterns seen in other short-lived entities
        if days_active <= 2 {
            // Count how many other short-lived entities share similar patterns
            let similar_count = self
                .short_lived_patterns
                .iter()
                .filter(|p| {
                    // Same mount path
                    if p.mount_path == entity.mount_path && p.days_active <= 2 {
                        return true;
                    }
                    // Similar naming pattern (e.g., github-repo:* or airflow-*)
                    if entity.display_name.contains(':') && p.display_name.contains(':') {
                        let entity_prefix = entity.display_name.split(':').next().unwrap_or("");
                        let pattern_prefix = p.display_name.split(':').next().unwrap_or("");
                        if entity_prefix == pattern_prefix && !entity_prefix.is_empty() {
                            return true;
                        }
                    }
                    false
                })
                .count();

            if similar_count > 5 {
                confidence += 0.2;
                reasons.push(format!(
                    "Matches pattern seen in {} other short-lived entities",
                    similar_count
                ));
            } else if similar_count > 0 {
                confidence += 0.1;
                reasons.push(format!(
                    "Similar to {} other short-lived entities",
                    similar_count
                ));
            }
        }

        // Low activity indicator
        if entity.total_logins <= 5 && days_active <= 2 {
            confidence += 0.1;
            reasons.push(format!(
                "Low activity: only {} login(s)",
                entity.total_logins
            ));
        }

        // Non-continuous appearance (sporadic pattern suggests not churned, just periodic)
        if days_active >= 2 {
            let first_day_idx = entity.files_appeared.first().and_then(|f| {
                f.split('_')
                    .next_back()
                    .and_then(|s| s.trim_end_matches(".log").parse::<usize>().ok())
            });
            let last_day_idx = entity.files_appeared.last().and_then(|f| {
                f.split('_')
                    .next_back()
                    .and_then(|s| s.trim_end_matches(".log").parse::<usize>().ok())
            });

            if let (Some(first), Some(last)) = (first_day_idx, last_day_idx) {
                let span = last - first + 1;
                if span > days_active {
                    // Gaps in activity - reduce confidence
                    confidence *= 0.7;
                    reasons.push(
                        "Has gaps in activity (possibly sporadic access, not churned)".to_string(),
                    );
                }
            }
        }

        // Cap confidence and determine ephemeral status
        confidence = f32::min(confidence, 1.0);
        let is_ephemeral = confidence >= 0.4; // Threshold for classification

        // Add absence indicator if not seen in recent files
        if is_ephemeral && days_active < self.total_files {
            reasons.push(format!(
                "Not seen in most recent {} file(s)",
                self.total_files - days_active
            ));
        }

        (is_ephemeral, confidence, reasons)
    }

    /// Determine activity pattern based on appearance across files
    fn classify_activity_pattern(&self, entity: &EntityChurnRecord) -> String {
        let days_active = entity.files_appeared.len();

        if days_active == 1 {
            return "single_burst".to_string();
        }

        if days_active == self.total_files {
            return "consistent".to_string();
        }

        if days_active >= (self.total_files * 2) / 3 {
            return "consistent".to_string();
        }

        // Check if activity is declining (appeared early but stopped)
        if let (Some(_first_file), Some(last_file)) =
            (entity.files_appeared.first(), entity.files_appeared.last())
        {
            // Simple heuristic: if last seen was in first half of files, it's declining
            let last_file_num = last_file
                .split('_')
                .next_back()
                .and_then(|s| s.trim_end_matches(".log").parse::<usize>().ok())
                .unwrap_or(self.total_files);

            if last_file_num < self.total_files / 2 {
                return "declining".to_string();
            }
        }

        if days_active <= 2 {
            return "single_burst".to_string();
        }

        "sporadic".to_string()
    }
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

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
struct BaselineEntity {
    entity_id: String,
    // Fields from entity-list (Vault API) - full metadata
    #[serde(default)]
    entity_name: String,
    #[serde(default)]
    entity_disabled: bool,
    #[serde(default)]
    entity_created: String,
    #[serde(default)]
    entity_updated: String,
    #[serde(default)]
    alias_id: String,
    #[serde(default)]
    alias_name: String,
    #[serde(default)]
    mount_path: String,
    #[serde(default)]
    mount_type: String,
    #[serde(default)]
    mount_accessor: String,
    #[serde(default)]
    alias_created: String,
    #[serde(default)]
    alias_updated: String,
    #[serde(default)]
    alias_metadata: String,
}

impl BaselineEntity {
    /// Get the best available name (`entity_name` if available, otherwise `alias_name`)
    fn get_name(&self) -> String {
        if !self.entity_name.is_empty() {
            self.entity_name.clone()
        } else if !self.alias_name.is_empty() {
            self.alias_name.clone()
        } else {
            String::new()
        }
    }

    /// Get the entity creation time
    fn get_created(&self) -> String {
        self.entity_created.clone()
    }
}

fn load_baseline_entities(path: &str) -> Result<HashMap<String, BaselineEntity>> {
    let file = File::open(path).context("Failed to open baseline entities file")?;

    // Check if it's JSON or CSV based on file extension
    let path_lower = path.to_lowercase();
    if std::path::Path::new(&path_lower)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    {
        // JSON format from entity-list with --format json
        let entities: Vec<BaselineEntity> =
            serde_json::from_reader(file).context("Failed to parse baseline entities JSON")?;
        Ok(entities
            .into_iter()
            .map(|e| (e.entity_id.clone(), e))
            .collect())
    } else {
        // CSV format (default entity-list output)
        let mut reader = csv::Reader::from_reader(file);
        let mut entities = HashMap::with_capacity(5000); // Pre-allocate for entity mappings

        for result in reader.deserialize() {
            let entity: BaselineEntity = result.context("Failed to parse baseline CSV row")?;
            // Use first occurrence of each entity_id (entities can have multiple aliases)
            entities.entry(entity.entity_id.clone()).or_insert(entity);
        }

        Ok(entities)
    }
}

pub fn run(
    log_files: &[String],
    entity_map: Option<&str>,
    baseline_entities: Option<&str>,
    output: Option<&str>,
    format: Option<&str>,
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
        println!(
            "Loading baseline entity list (Vault API metadata) from {}...",
            path
        );
        let baseline_set = load_baseline_entities(path)?;
        println!(
            "Loaded {} pre-existing entities from Vault API baseline",
            format_number(baseline_set.len())
        );
        println!();
        Some(baseline_set)
    } else {
        println!("No baseline entity list provided. Cannot distinguish truly NEW entities from pre-existing.");
        println!("   All Day 1 entities will be marked as 'pre_existing_or_new_day_1'.");
        println!("   To get accurate results, run: ./vault-audit entity-list --output baseline_entities.json\n");
        None
    };

    // Load entity mappings if provided (historical data from audit logs)
    let entity_mappings = if let Some(path) = entity_map {
        println!(
            "Loading historical entity mappings (audit log enrichment) from {}...",
            path
        );
        let mappings = load_entity_mappings(path)?;
        println!(
            "Loaded {} entity mappings with historical audit log data",
            format_number(mappings.len())
        );
        println!();
        Some(mappings)
    } else {
        None
    };

    // Track all entities across all files
    // Pre-allocate for typical entity counts in enterprise environments
    let mut entities: HashMap<String, EntityChurnRecord> = HashMap::with_capacity(5000);
    let mut daily_stats: Vec<DailyStats> = Vec::new();

    // Process each log file in order
    for (file_idx, log_file) in log_files.iter().enumerate() {
        let file_name = Path::new(log_file)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        println!("\nProcessing Day {} ({})...", file_idx + 1, file_name);

        let file = open_file(log_file)
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
            let mount_type = request.mount_type.clone().unwrap_or_default();
            let token_type = auth.token_type.clone().unwrap_or_default();

            // Parse timestamp
            let first_seen_time = chrono::DateTime::parse_from_rfc3339(&entry.time)
                .ok()
                .map_or_else(Utc::now, |dt| dt.with_timezone(&Utc));

            // Check if this entity exists from a previous file
            if let Some(entity_record) = entities.get_mut(entity_id) {
                // Returning entity
                entity_record.total_logins += 1;
                entity_record.last_seen_file.clone_from(&file_name);
                entity_record.last_seen_time = first_seen_time;
                if !entity_record.files_appeared.contains(&file_name) {
                    entity_record.files_appeared.push(file_name.clone());
                }
                returning_entities_this_file.insert(entity_id.clone());
            } else {
                // New entity (first time across all files)
                new_entities_this_file += 1;

                // Determine lifecycle based on baseline and which file this is
                let lifecycle = if let Some(ref baseline_set) = baseline {
                    if baseline_set.contains_key(entity_id) {
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

                // Get baseline metadata if entity exists in baseline
                let (
                    baseline_entity_name,
                    baseline_created,
                    baseline_alias_name,
                    baseline_mount_path,
                ) = if let Some(ref baseline_map) = baseline {
                    if let Some(baseline_entity) = baseline_map.get(entity_id) {
                        let name = baseline_entity.get_name();
                        let created = baseline_entity.get_created();
                        (
                            if name.is_empty() { None } else { Some(name) },
                            if created.is_empty() {
                                None
                            } else {
                                Some(created)
                            },
                            if baseline_entity.alias_name.is_empty() {
                                None
                            } else {
                                Some(baseline_entity.alias_name.clone())
                            },
                            if baseline_entity.mount_path.is_empty() {
                                None
                            } else {
                                Some(baseline_entity.mount_path.clone())
                            },
                        )
                    } else {
                        (None, None, None, None)
                    }
                } else {
                    (None, None, None, None)
                };

                // Fetch historical data from entity_mappings
                let (
                    historical_display_name,
                    historical_first_seen,
                    historical_last_seen,
                    historical_login_count,
                ) = if let Some(ref mappings) = entity_mappings {
                    if let Some(mapping) = mappings.get(entity_id) {
                        (
                            Some(mapping.display_name.clone()),
                            Some(mapping.first_seen.clone()),
                            Some(mapping.last_seen.clone()),
                            Some(mapping.login_count),
                        )
                    } else {
                        (None, None, None, None)
                    }
                } else {
                    (None, None, None, None)
                };

                entities.insert(
                    entity_id.clone(),
                    EntityChurnRecord {
                        entity_id: entity_id.clone(),
                        display_name: display_name.clone(),
                        mount_path: mount_path.clone(),
                        mount_type: mount_type.clone(),
                        token_type: token_type.clone(),
                        first_seen_file: file_name.clone(),
                        first_seen_time,
                        last_seen_file: file_name.clone(),
                        last_seen_time: first_seen_time,
                        files_appeared: vec![file_name.clone()],
                        total_logins: 1,
                        lifecycle,
                        activity_pattern: "unknown".to_string(), // Will be computed in second pass
                        is_ephemeral_pattern: false,             // Will be computed in second pass
                        ephemeral_confidence: 0.0,               // Will be computed in second pass
                        ephemeral_reasons: Vec::new(),           // Will be computed in second pass
                        baseline_entity_name,
                        baseline_created,
                        baseline_alias_name,
                        baseline_mount_path,
                        historical_display_name,
                        historical_first_seen,
                        historical_last_seen,
                        historical_login_count,
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

    // === SECOND PASS: Analyze patterns and classify entities ===
    println!("\nAnalyzing entity behavior patterns...");

    let mut analyzer = EphemeralPatternAnalyzer::new(log_files.len());

    // Step 1: Learn patterns from short-lived entities
    analyzer.learn_from_entities(&entities);
    println!(
        "Learned from {} short-lived entity patterns",
        format_number(analyzer.short_lived_patterns.len())
    );

    // Step 2: Classify all entities using learned patterns
    let entity_ids: Vec<String> = entities.keys().cloned().collect();
    for entity_id in entity_ids {
        if let Some(entity) = entities.get_mut(&entity_id) {
            // Classify activity pattern
            entity.activity_pattern = analyzer.classify_activity_pattern(entity);

            // Analyze for ephemeral patterns
            let (is_ephemeral, confidence, reasons) = analyzer.analyze_entity(entity);
            entity.is_ephemeral_pattern = is_ephemeral;
            entity.ephemeral_confidence = confidence;
            entity.ephemeral_reasons = reasons;
        }
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
    let mut lifecycle_counts: HashMap<String, usize> = HashMap::with_capacity(20); // Small set of lifecycle categories
    let mut entities_by_file_count: HashMap<usize, usize> = HashMap::with_capacity(log_files.len());

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

    // Activity pattern analysis
    let mut activity_pattern_counts: HashMap<String, usize> = HashMap::with_capacity(10); // Small set of activity patterns
    let mut ephemeral_entities = Vec::new();

    for entity in entities.values() {
        *activity_pattern_counts
            .entry(entity.activity_pattern.clone())
            .or_insert(0) += 1;

        if entity.is_ephemeral_pattern {
            ephemeral_entities.push(entity.clone());
        }
    }

    println!("\nActivity Pattern Distribution:");
    let mut pattern_vec: Vec<_> = activity_pattern_counts.iter().collect();
    pattern_vec.sort_by(|a, b| b.1.cmp(a.1));
    for (pattern, count) in pattern_vec {
        println!("  {}: {}", pattern, format_number(*count));
    }

    println!("\nEphemeral Entity Detection:");
    println!(
        "  Detected {} likely ephemeral entities (confidence ≥ 0.4)",
        format_number(ephemeral_entities.len())
    );

    if !ephemeral_entities.is_empty() {
        // Sort by confidence
        ephemeral_entities.sort_by(|a, b| {
            b.ephemeral_confidence
                .partial_cmp(&a.ephemeral_confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        println!("  Top 10 by confidence:");
        for (idx, entity) in ephemeral_entities.iter().take(10).enumerate() {
            println!(
                "    {}. {} (confidence: {:.1}%)",
                idx + 1,
                entity.display_name,
                entity.ephemeral_confidence * 100.0
            );
            for reason in &entity.ephemeral_reasons {
                println!("       - {}", reason);
            }
        }

        // Breakdown by confidence ranges
        let high_conf = ephemeral_entities
            .iter()
            .filter(|e| e.ephemeral_confidence >= 0.7)
            .count();
        let med_conf = ephemeral_entities
            .iter()
            .filter(|e| e.ephemeral_confidence >= 0.5 && e.ephemeral_confidence < 0.7)
            .count();
        let low_conf = ephemeral_entities
            .iter()
            .filter(|e| e.ephemeral_confidence >= 0.4 && e.ephemeral_confidence < 0.5)
            .count();

        println!("\n  Confidence distribution:");
        println!("    High (≥70%): {}", format_number(high_conf));
        println!("    Medium (50-69%): {}", format_number(med_conf));
        println!("    Low (40-49%): {}", format_number(low_conf));
    }

    // Mount path breakdown
    let mut mount_stats: HashMap<String, (usize, String)> = HashMap::with_capacity(100); // Typical: dozens of mount points
    for entity in entities.values() {
        let entry = mount_stats
            .entry(entity.mount_path.clone())
            .or_insert_with(|| (0, entity.mount_type.clone()));
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

    // Export to file if requested
    if let Some(output_path) = output {
        let mut entities_vec: Vec<_> = entities.into_values().collect();
        entities_vec.sort_by(|a, b| a.first_seen_time.cmp(&b.first_seen_time));

        // Determine format from parameter or file extension
        let output_format = format.unwrap_or_else(|| {
            if std::path::Path::new(output_path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("csv"))
            {
                "csv"
            } else {
                "json"
            }
        });

        println!(
            "\nExporting detailed entity records to {} (format: {})...",
            output_path, output_format
        );

        let output_file = File::create(output_path)
            .with_context(|| format!("Failed to create output file: {}", output_path))?;

        match output_format {
            "csv" => {
                let mut writer = csv::Writer::from_writer(output_file);
                for entity in &entities_vec {
                    let csv_record: EntityChurnRecordCsv = entity.clone().into();
                    writer
                        .serialize(&csv_record)
                        .context("Failed to write CSV record")?;
                }
                writer.flush().context("Failed to flush CSV writer")?;
            }
            _ => {
                // Default to JSON
                serde_json::to_writer_pretty(output_file, &entities_vec)
                    .context("Failed to write JSON output")?;
            }
        }

        println!(
            "Exported {} entity records",
            format_number(entities_vec.len())
        );
    }

    println!("\n=== Analysis Complete ===\n");
    Ok(())
}
