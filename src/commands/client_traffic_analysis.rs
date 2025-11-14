//! Client traffic analysis for understanding request patterns and client behavior.
//!
//! Analyzes aggregated audit logs to provide insights into:
//! - Client-to-Vault traffic patterns (top clients, request volumes)
//! - Request distribution analysis (temporal patterns, operation types)
//! - Client behavior clustering (automated vs interactive patterns)
//!
//! # Usage
//!
//! ```bash
//! # Analyze all audit logs
//! vault-audit client-traffic-analysis audit*.log
//!
//! # Export detailed metrics to CSV
//! vault-audit client-traffic-analysis audit*.log --output traffic.csv --format csv
//!
//! # Analyze compressed logs
//! vault-audit client-traffic-analysis logs/*.log.gz
//! ```

use crate::audit::types::AuditEntry;
use crate::utils::format::format_number;
use crate::utils::parallel::process_files_parallel;
use crate::utils::progress::ProgressBar;
use anyhow::{Context, Result};
use chrono::{DateTime, Timelike, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Detailed error instance linking entity, error type, and path
#[derive(Debug, Clone)]
struct ErrorInstance {
    entity_id: String,
    display_name: String,
    error_type: String,
    path: String,
    timestamp: String,
}

/// Statistics for a single client
#[derive(Debug, Clone)]
struct ClientStats {
    /// Total number of requests from this client
    request_count: usize,
    /// Breakdown by operation type (read, write, list, delete)
    operations: HashMap<String, usize>,
    /// Breakdown by path accessed
    paths: HashMap<String, usize>,
    /// Breakdown by mount point
    mount_points: HashMap<String, usize>,
    /// Unique entities accessing from this client
    entities: HashMap<String, String>, // entity_id -> display_name
    /// First seen timestamp
    first_seen: Option<String>,
    /// Last seen timestamp
    last_seen: Option<String>,
    /// Requests with errors
    error_count: usize,
    /// Breakdown of error types
    error_types: HashMap<String, usize>,
    /// Paths that generated errors
    error_paths: HashMap<String, usize>,
    /// Detailed error instances (entity + error + path + timestamp)
    error_instances: Vec<ErrorInstance>,
    /// Requests by hour of day (0-23)
    hourly_distribution: HashMap<u32, usize>,
}

/// Export structure for client metrics
#[derive(Debug, Serialize)]
struct ClientExport {
    client_ip: String,
    total_requests: usize,
    unique_entities: usize,
    unique_paths: usize,
    unique_mount_points: usize,
    error_count: usize,
    error_rate: f64,
    first_seen: String,
    last_seen: String,
    top_operation: String,
    top_operation_count: usize,
    top_path: String,
    top_path_count: usize,
    // Error details
    top_error_type: String,
    top_error_type_count: usize,
    top_error_type_percentage: f64,
    second_error_type: String,
    second_error_type_count: usize,
    third_error_type: String,
    third_error_type_count: usize,
    top_error_path: String,
    top_error_path_count: usize,
    classification: String,
}

impl ClientStats {
    fn new() -> Self {
        Self {
            request_count: 0,
            operations: HashMap::new(),
            paths: HashMap::new(),
            mount_points: HashMap::new(),
            entities: HashMap::new(),
            first_seen: None,
            last_seen: None,
            error_count: 0,
            error_types: HashMap::new(),
            error_paths: HashMap::new(),
            error_instances: Vec::new(),
            hourly_distribution: HashMap::new(),
        }
    }

    /// Update stats with a new entry
    fn update(&mut self, entry: &AuditEntry) {
        self.request_count += 1;

        // Track operation type
        if let Some(op) = entry.operation() {
            *self.operations.entry(op.to_string()).or_insert(0) += 1;
        }

        // Track path
        if let Some(path) = entry.path() {
            *self.paths.entry(path.to_string()).or_insert(0) += 1;
        }

        // Track mount point
        if let Some(mp) = entry.mount_point() {
            *self.mount_points.entry(mp.to_string()).or_insert(0) += 1;
        }

        // Track entity
        if let Some(entity_id) = entry.entity_id() {
            if let Some(display_name) = entry.display_name() {
                self.entities
                    .entry(entity_id.to_string())
                    .or_insert_with(|| display_name.to_string());
            }
        }

        // Track timestamps
        if self.first_seen.is_none() {
            self.first_seen = Some(entry.time.clone());
        }
        self.last_seen = Some(entry.time.clone());

        // Track errors with detailed information
        if let Some(error_msg) = &entry.error {
            self.error_count += 1;

            // Clean and categorize error message
            let cleaned_error = error_msg.trim().replace(['\n', '\t'], " ");

            // Extract the core error type
            let error_type = if cleaned_error.contains("permission denied") {
                "permission denied"
            } else if cleaned_error.contains("service account name not authorized") {
                "service account not authorized"
            } else if cleaned_error.contains("namespace not authorized") {
                "namespace not authorized"
            } else if cleaned_error.contains("invalid credentials") {
                "invalid credentials"
            } else if cleaned_error.contains("wrapping token") {
                "invalid wrapping token"
            } else if cleaned_error.contains("internal error") {
                "internal error"
            } else if cleaned_error.contains("unsupported operation") {
                "unsupported operation"
            } else if cleaned_error.contains("max TTL") {
                "max TTL exceeded"
            } else if cleaned_error.is_empty() || cleaned_error == "null" {
                "unknown error"
            } else {
                // Use first 50 chars of error message as type
                if cleaned_error.len() > 50 {
                    &cleaned_error[..50]
                } else {
                    &cleaned_error
                }
            };

            *self.error_types.entry(error_type.to_string()).or_insert(0) += 1;

            // Track which path generated the error
            let path = entry.path().unwrap_or("unknown").to_string();
            *self.error_paths.entry(path.clone()).or_insert(0) += 1;

            // Create detailed error instance linking entity, error, and path
            let entity_id = entry.entity_id().unwrap_or("unknown").to_string();
            let display_name = entry.display_name().unwrap_or("unknown").to_string();

            self.error_instances.push(ErrorInstance {
                entity_id,
                display_name,
                error_type: error_type.to_string(),
                path,
                timestamp: entry.time.clone(),
            });
        }

        // Track hourly distribution
        if let Ok(dt) = entry.time.parse::<DateTime<Utc>>() {
            let hour = dt.hour();
            *self.hourly_distribution.entry(hour).or_insert(0) += 1;
        }
    }

    /// Merge another `ClientStats` into this one
    fn merge(&mut self, other: Self) {
        self.request_count += other.request_count;
        self.error_count += other.error_count;

        // Merge operations
        for (op, count) in other.operations {
            *self.operations.entry(op).or_insert(0) += count;
        }

        // Merge paths
        for (path, count) in other.paths {
            *self.paths.entry(path).or_insert(0) += count;
        }

        // Merge mount points
        for (mp, count) in other.mount_points {
            *self.mount_points.entry(mp).or_insert(0) += count;
        }

        // Merge entities
        for (entity_id, display_name) in other.entities {
            self.entities.entry(entity_id).or_insert(display_name);
        }

        // Merge error types
        for (error_type, count) in other.error_types {
            *self.error_types.entry(error_type).or_insert(0) += count;
        }

        // Merge error paths
        for (path, count) in other.error_paths {
            *self.error_paths.entry(path).or_insert(0) += count;
        }

        // Merge error instances
        self.error_instances.extend(other.error_instances);

        // Merge hourly distribution
        for (hour, count) in other.hourly_distribution {
            *self.hourly_distribution.entry(hour).or_insert(0) += count;
        }

        // Update timestamps
        if self.first_seen.is_none()
            || (other.first_seen.is_some() && other.first_seen < self.first_seen)
        {
            self.first_seen = other.first_seen;
        }
        if self.last_seen.is_none()
            || (other.last_seen.is_some() && other.last_seen > self.last_seen)
        {
            self.last_seen = other.last_seen;
        }
    }

    /// Classify client behavior
    fn classify_behavior(&self) -> String {
        let paths_per_request = self.paths.len() as f64 / self.request_count as f64;
        if self.request_count > 1000 || paths_per_request < 0.1 {
            "automated".to_string()
        } else {
            "interactive".to_string()
        }
    }

    /// Convert to export format
    fn to_export(&self, client_ip: String) -> ClientExport {
        let error_rate = if self.request_count > 0 {
            (self.error_count as f64 / self.request_count as f64) * 100.0
        } else {
            0.0
        };

        let (top_operation, top_operation_count) = self
            .operations
            .iter()
            .max_by_key(|(_, count)| *count)
            .map_or_else(
                || ("none".to_string(), 0),
                |(op, count)| (op.clone(), *count),
            );

        let (top_path, top_path_count) = self
            .paths
            .iter()
            .max_by_key(|(_, count)| *count)
            .map_or_else(
                || ("none".to_string(), 0),
                |(path, count)| (path.clone(), *count),
            );

        // Get top 3 error types
        let mut error_types_sorted: Vec<_> = self.error_types.iter().collect();
        error_types_sorted.sort_by(|a, b| b.1.cmp(a.1));

        let (top_error_type, top_error_type_count) = error_types_sorted
            .first()
            .map_or_else(|| ("none".to_string(), 0), |(t, c)| ((*t).clone(), **c));

        let top_error_type_percentage = if self.error_count > 0 {
            (top_error_type_count as f64 / self.error_count as f64) * 100.0
        } else {
            0.0
        };

        let (second_error_type, second_error_type_count) = error_types_sorted
            .get(1)
            .map_or_else(|| ("none".to_string(), 0), |(t, c)| ((*t).clone(), **c));

        let (third_error_type, third_error_type_count) = error_types_sorted
            .get(2)
            .map_or_else(|| ("none".to_string(), 0), |(t, c)| ((*t).clone(), **c));

        // Get top error path
        let (top_error_path, top_error_path_count) = self
            .error_paths
            .iter()
            .max_by_key(|(_, count)| *count)
            .map_or_else(
                || ("none".to_string(), 0),
                |(path, count)| (path.clone(), *count),
            );

        ClientExport {
            client_ip,
            total_requests: self.request_count,
            unique_entities: self.entities.len(),
            unique_paths: self.paths.len(),
            unique_mount_points: self.mount_points.len(),
            error_count: self.error_count,
            error_rate,
            first_seen: self
                .first_seen
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            last_seen: self
                .last_seen
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            top_operation,
            top_operation_count,
            top_path,
            top_path_count,
            top_error_type,
            top_error_type_count,
            top_error_type_percentage,
            second_error_type,
            second_error_type_count,
            third_error_type,
            third_error_type_count,
            top_error_path,
            top_error_path_count,
            classification: self.classify_behavior(),
        }
    }
}

/// Global progress tracking for parallel processing
static PARALLEL_PROGRESS: OnceLock<(Arc<AtomicUsize>, Arc<Mutex<ProgressBar>>)> = OnceLock::new();

/// Initialize parallel progress tracking (called by parallel processor)
pub fn init_parallel_progress(processed: Arc<AtomicUsize>, progress: Arc<Mutex<ProgressBar>>) {
    let _ = PARALLEL_PROGRESS.set((processed, progress));
}

/// Overall traffic statistics
#[derive(Debug)]
struct TrafficStats {
    /// Stats per client IP
    clients: HashMap<String, ClientStats>,
    /// Total requests processed
    total_requests: usize,
}

impl TrafficStats {
    fn new() -> Self {
        Self {
            clients: HashMap::new(),
            total_requests: 0,
        }
    }

    fn merge(&mut self, other: Self) {
        self.total_requests += other.total_requests;

        for (client_ip, stats) in other.clients {
            self.clients
                .entry(client_ip)
                .or_insert_with(ClientStats::new)
                .merge(stats);
        }
    }
}

/// Process a single file and extract client traffic stats
fn process_file(file_path: &str) -> Result<TrafficStats> {
    let file = crate::utils::reader::open_file(file_path)?;
    let reader = BufReader::new(file);

    let mut stats = TrafficStats::new();
    let mut lines_processed = 0usize;

    // Check if we're in parallel mode with progress tracking
    let parallel_progress = PARALLEL_PROGRESS.get();

    for line_result in reader.lines() {
        let line = line_result?;
        lines_processed += 1;

        // Update progress every 1000 lines to reduce contention
        if lines_processed % 1000 == 0 {
            if let Some((processed_lines, progress)) = parallel_progress {
                processed_lines.fetch_add(1000, Ordering::Relaxed);
                if let Ok(progress) = progress.lock() {
                    progress.inc(1000);
                }
            }
        }

        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }

        // Parse JSON entry
        let entry: AuditEntry = match serde_json::from_str(&line) {
            Ok(entry) => entry,
            Err(_) => continue,
        };

        // Only process request entries (responses are duplicates)
        if entry.entry_type != "request" {
            continue;
        }

        // Get client IP
        let Some(client_ip) = entry.remote_address() else {
            continue;
        };

        // Update client stats
        stats
            .clients
            .entry(client_ip.to_string())
            .or_insert_with(ClientStats::new)
            .update(&entry);

        stats.total_requests += 1;
    }

    // Update progress with any remaining lines
    let remainder = lines_processed % 1000;
    if remainder > 0 {
        if let Some((processed_lines, progress)) = parallel_progress {
            processed_lines.fetch_add(remainder, Ordering::Relaxed);
            if let Ok(progress) = progress.lock() {
                progress.inc(remainder as u64);
            }
        }
    }

    Ok(stats)
}

/// Main command function
#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
pub fn run(
    log_files: &[String],
    output: Option<String>,
    format: Option<&str>,
    error_details_output: Option<String>,
    top_n: usize,
    show_temporal: bool,
    min_requests: usize,
    show_operations: bool,
    show_errors: bool,
    show_details: bool,
) -> Result<()> {
    if log_files.len() == 1 {
        eprintln!("Analyzing client traffic patterns from 1 file...");
    } else {
        eprintln!(
            "Analyzing client traffic patterns from {} files...",
            log_files.len()
        );
    }

    // Process files in parallel
    let (combined_stats, _total_lines) =
        process_files_parallel(log_files, process_file, |results| {
            let mut combined = TrafficStats::new();
            for result in results {
                combined.merge(result.data);
            }
            combined
        })?;

    // Filter clients by minimum request threshold
    let filtered_stats = if min_requests > 1 {
        let mut filtered = TrafficStats::new();
        filtered.total_requests = combined_stats.total_requests;
        for (ip, stats) in combined_stats.clients {
            if stats.request_count >= min_requests {
                filtered.clients.insert(ip, stats);
            }
        }
        filtered
    } else {
        combined_stats
    };

    // Export summary data if requested
    if let Some(output_file) = output {
        export_data(&filtered_stats, &output_file, format)?;
        eprintln!("Exported summary data to {}", output_file);
    }

    // Export detailed error analysis with entity information if requested
    if let Some(error_output_file) = error_details_output {
        export_error_details(&filtered_stats, &error_output_file)?;
        eprintln!(
            "Exported detailed error analysis (with entities) to {}",
            error_output_file
        );
    }

    // Generate report
    print_summary(&filtered_stats);
    print_top_clients(&filtered_stats, top_n);
    print_client_behavior_analysis(&filtered_stats);

    if show_operations {
        print_operation_breakdown(&filtered_stats, top_n.min(10));
    }

    if show_errors {
        print_error_analysis(&filtered_stats, top_n.min(10));
    }

    if show_details {
        print_detailed_client_analysis(&filtered_stats, top_n.min(10));
    }

    if show_temporal {
        print_temporal_analysis(&filtered_stats, top_n.min(10));
    }

    Ok(())
}

/// Print overall summary
fn print_summary(stats: &TrafficStats) {
    println!("\n{}", "=".repeat(100));
    println!("Client Traffic Analysis Summary");
    println!("{}", "=".repeat(100));
    println!("Total Requests: {}", format_number(stats.total_requests));
    println!("Unique Clients: {}", format_number(stats.clients.len()));
    println!(
        "Avg Requests per Client: {:.2}",
        stats.total_requests as f64 / stats.clients.len() as f64
    );
}

/// Print top clients by request volume
fn print_top_clients(stats: &TrafficStats, top_n: usize) {
    println!("\n{}", "=".repeat(100));
    println!("Top {} Clients by Request Volume", top_n);
    println!("{}", "=".repeat(100));
    println!(
        "{:<20} {:>15} {:>15} {:>15} {:>15}",
        "Client IP", "Requests", "Entities", "Errors", "Error %"
    );
    println!("{}", "-".repeat(100));

    let mut clients: Vec<_> = stats.clients.iter().collect();
    clients.sort_by(|a, b| b.1.request_count.cmp(&a.1.request_count));

    for (ip, client_stats) in clients.iter().take(top_n) {
        let error_pct = if client_stats.request_count > 0 {
            (client_stats.error_count as f64 / client_stats.request_count as f64) * 100.0
        } else {
            0.0
        };

        println!(
            "{:<20} {:>15} {:>15} {:>15} {:>14.2}%",
            ip,
            format_number(client_stats.request_count),
            format_number(client_stats.entities.len()),
            format_number(client_stats.error_count),
            error_pct
        );
    }
}

/// Analyze and print client behavior patterns
fn print_client_behavior_analysis(stats: &TrafficStats) {
    println!("\n{}", "=".repeat(100));
    println!("Client Behavior Analysis");
    println!("{}", "=".repeat(100));

    // Categorize clients
    let mut automated_clients = Vec::new();
    let mut interactive_clients = Vec::new();

    for (ip, client_stats) in &stats.clients {
        // Heuristic: Automated clients typically have higher request volumes
        // and access fewer unique paths per request
        let paths_per_request = client_stats.paths.len() as f64 / client_stats.request_count as f64;

        if client_stats.request_count > 1000 || paths_per_request < 0.1 {
            automated_clients.push((ip, client_stats));
        } else {
            interactive_clients.push((ip, client_stats));
        }
    }

    println!(
        "Automated Clients (likely services): {}",
        automated_clients.len()
    );
    println!(
        "Interactive Clients (likely users): {}",
        interactive_clients.len()
    );

    // Show top automated clients
    if !automated_clients.is_empty() {
        println!("\nTop Automated Clients:");
        println!(
            "{:<20} {:>15} {:>15}",
            "Client IP", "Requests", "Unique Paths"
        );
        println!("{}", "-".repeat(60));

        automated_clients.sort_by(|a, b| b.1.request_count.cmp(&a.1.request_count));
        for (ip, stats) in automated_clients.iter().take(10) {
            println!(
                "{:<20} {:>15} {:>15}",
                ip,
                format_number(stats.request_count),
                format_number(stats.paths.len())
            );
        }
    }
}

/// Print operation type breakdown for top clients
fn print_operation_breakdown(stats: &TrafficStats, top_n: usize) {
    println!("\n{}", "=".repeat(100));
    println!("Operation Type Breakdown - Top {} Clients", top_n);
    println!("{}", "=".repeat(100));

    let mut clients: Vec<_> = stats.clients.iter().collect();
    clients.sort_by(|a, b| b.1.request_count.cmp(&a.1.request_count));

    for (ip, client_stats) in clients.iter().take(top_n) {
        println!(
            "\nClient: {} (Total: {})",
            ip,
            format_number(client_stats.request_count)
        );
        println!("{}", "-".repeat(80));

        let mut operations: Vec<_> = client_stats.operations.iter().collect();
        operations.sort_by(|a, b| b.1.cmp(a.1));

        println!("{:<30} {:>15} {:>15}", "Operation", "Count", "Percentage");
        println!("{}", "-".repeat(60));

        for (op, count) in operations {
            let percentage = (*count as f64 / client_stats.request_count as f64) * 100.0;
            println!(
                "{:<30} {:>15} {:>14.2}%",
                op,
                format_number(*count),
                percentage
            );
        }
    }
}

/// Print error analysis for clients with significant errors
fn print_error_analysis(stats: &TrafficStats, top_n: usize) {
    println!("\n{}", "=".repeat(100));
    println!("Error Analysis - Clients with Errors");
    println!("{}", "=".repeat(100));

    let mut clients_with_errors: Vec<_> = stats
        .clients
        .iter()
        .filter(|(_, client)| client.error_count > 0)
        .collect();

    clients_with_errors.sort_by(|a, b| b.1.error_count.cmp(&a.1.error_count));

    if clients_with_errors.is_empty() {
        println!("No errors detected in the analyzed logs.");
        return;
    }

    println!(
        "{:<20} {:>15} {:>15} {:>15}",
        "Client IP", "Total Requests", "Errors", "Error Rate"
    );
    println!("{}", "-".repeat(80));

    for (ip, client_stats) in clients_with_errors.iter().take(top_n) {
        let error_rate =
            (client_stats.error_count as f64 / client_stats.request_count as f64) * 100.0;
        println!(
            "{:<20} {:>15} {:>15} {:>14.2}%",
            ip,
            format_number(client_stats.request_count),
            format_number(client_stats.error_count),
            error_rate
        );
    }

    // Print detailed error type breakdown
    println!("\n{}", "=".repeat(100));
    println!("Error Type Breakdown by Client");
    println!("{}", "=".repeat(100));

    for (ip, client_stats) in clients_with_errors.iter().take(top_n) {
        if client_stats.error_types.is_empty() {
            continue;
        }

        println!(
            "\nClient: {} (Total Errors: {})",
            ip,
            format_number(client_stats.error_count)
        );
        println!("{}", "-".repeat(80));

        let mut error_types: Vec<_> = client_stats.error_types.iter().collect();
        error_types.sort_by(|a, b| b.1.cmp(a.1));

        println!("{:<50} {:>15} {:>15}", "Error Type", "Count", "Percentage");
        println!("{}", "-".repeat(80));

        for (error_type, count) in error_types.iter().take(10) {
            let percentage = (**count as f64 / client_stats.error_count as f64) * 100.0;
            let truncated = if error_type.len() > 50 {
                format!("{}...", &error_type[..47])
            } else {
                (*error_type).clone()
            };
            println!(
                "{:<50} {:>15} {:>14.2}%",
                truncated,
                format_number(**count),
                percentage
            );
        }

        // Print top error paths
        if !client_stats.error_paths.is_empty() {
            println!("\nTop Paths Generating Errors:");
            println!("{:<60} {:>15}", "Path", "Error Count");
            println!("{}", "-".repeat(80));

            let mut error_paths: Vec<_> = client_stats.error_paths.iter().collect();
            error_paths.sort_by(|a, b| b.1.cmp(a.1));

            for (path, count) in error_paths.iter().take(5) {
                let truncated_path = if path.len() > 60 {
                    format!("{}...", &path[..57])
                } else {
                    (*path).clone()
                };
                println!("{:<60} {:>15}", truncated_path, format_number(**count));
            }
        }
    }

    // Overall error distribution
    println!("\n{}", "=".repeat(100));
    println!("Overall Error Type Distribution");
    println!("{}", "=".repeat(100));

    let mut overall_errors: HashMap<String, usize> = HashMap::new();
    let mut total_errors = 0usize;

    for (_, client_stats) in &clients_with_errors {
        for (error_type, count) in &client_stats.error_types {
            *overall_errors.entry(error_type.clone()).or_insert(0) += count;
            total_errors += count;
        }
    }

    let mut sorted_errors: Vec<_> = overall_errors.iter().collect();
    sorted_errors.sort_by(|a, b| b.1.cmp(a.1));

    println!("{:<50} {:>15} {:>15}", "Error Type", "Count", "Percentage");
    println!("{}", "-".repeat(80));

    for (error_type, count) in sorted_errors.iter().take(15) {
        let percentage = (**count as f64 / total_errors as f64) * 100.0;
        let truncated = if error_type.len() > 50 {
            format!("{}...", &error_type[..47])
        } else {
            (*error_type).clone()
        };
        println!(
            "{:<50} {:>15} {:>14.2}%",
            truncated,
            format_number(**count),
            percentage
        );
    }
}

/// Print detailed per-client analysis
fn print_detailed_client_analysis(stats: &TrafficStats, top_n: usize) {
    println!("\n{}", "=".repeat(100));
    println!("Detailed Client Analysis - Top {} Clients", top_n);
    println!("{}", "=".repeat(100));

    let mut clients: Vec<_> = stats.clients.iter().collect();
    clients.sort_by(|a, b| b.1.request_count.cmp(&a.1.request_count));

    for (ip, client_stats) in clients.iter().take(top_n) {
        println!("\n{}", "=".repeat(100));
        println!("Client: {}", ip);
        println!("{}", "=".repeat(100));
        println!(
            "Total Requests: {}",
            format_number(client_stats.request_count)
        );
        println!(
            "Unique Entities: {}",
            format_number(client_stats.entities.len())
        );
        println!("Unique Paths: {}", format_number(client_stats.paths.len()));
        println!(
            "Unique Mount Points: {}",
            format_number(client_stats.mount_points.len())
        );
        println!("Error Count: {}", format_number(client_stats.error_count));
        println!("Classification: {}", client_stats.classify_behavior());
        println!(
            "First Seen: {}",
            client_stats.first_seen.as_deref().unwrap_or("unknown")
        );
        println!(
            "Last Seen: {}",
            client_stats.last_seen.as_deref().unwrap_or("unknown")
        );

        // Top paths accessed
        println!("\nTop Paths Accessed:");
        println!("{:<60} {:>15}", "Path", "Count");
        println!("{}", "-".repeat(80));

        let mut paths: Vec<_> = client_stats.paths.iter().collect();
        paths.sort_by(|a, b| b.1.cmp(a.1));

        for (path, count) in paths.iter().take(10) {
            let truncated_path = if path.len() > 60 {
                format!("{}...", &path[..57])
            } else {
                (*path).clone()
            };
            println!("{:<60} {:>15}", truncated_path, format_number(**count));
        }

        // Top mount points
        println!("\nTop Mount Points:");
        println!("{:<60} {:>15}", "Mount Point", "Count");
        println!("{}", "-".repeat(80));

        let mut mount_points: Vec<_> = client_stats.mount_points.iter().collect();
        mount_points.sort_by(|a, b| b.1.cmp(a.1));

        for (mp, count) in mount_points.iter().take(10) {
            println!("{:<60} {:>15}", mp, format_number(**count));
        }

        // Associated entities
        if !client_stats.entities.is_empty() {
            println!("\nAssociated Entities:");
            println!("{:<40} {:<}", "Entity ID", "Display Name");
            println!("{}", "-".repeat(80));

            for (entity_id, display_name) in client_stats.entities.iter().take(10) {
                println!("{:<40} {}", entity_id, display_name);
            }
        }
    }
}

/// Print temporal analysis (hourly distribution)
fn print_temporal_analysis(stats: &TrafficStats, top_n: usize) {
    println!("\n{}", "=".repeat(100));
    println!("Temporal Analysis - Hourly Request Distribution");
    println!("{}", "=".repeat(100));

    let mut clients: Vec<_> = stats.clients.iter().collect();
    clients.sort_by(|a, b| b.1.request_count.cmp(&a.1.request_count));

    for (ip, client_stats) in clients.iter().take(top_n) {
        println!(
            "\nClient: {} (Total: {})",
            ip,
            format_number(client_stats.request_count)
        );
        println!("{}", "-".repeat(80));

        // Create sorted list of hours
        let mut hourly: Vec<_> = client_stats.hourly_distribution.iter().collect();
        hourly.sort_by_key(|(hour, _)| *hour);

        // Print hourly distribution
        for (hour, count) in hourly {
            let percentage = (*count as f64 / client_stats.request_count as f64) * 100.0;
            let bar_length = (percentage / 2.0) as usize; // Scale to max 50 chars
            let bar = "#".repeat(bar_length);
            println!(
                "{:02}:00 {:>8} {:>6.2}% {}",
                hour,
                format_number(*count),
                percentage,
                bar
            );
        }
    }
}

/// Export data to CSV or JSON
fn export_data(stats: &TrafficStats, output_file: &str, format: Option<&str>) -> Result<()> {
    let format = format.unwrap_or("csv");

    // Convert stats to export format
    let mut exports: Vec<ClientExport> = stats
        .clients
        .iter()
        .map(|(ip, stats)| stats.to_export(ip.clone()))
        .collect();

    // Sort by request count descending
    exports.sort_by(|a, b| b.total_requests.cmp(&a.total_requests));

    match format {
        "csv" => export_csv(&exports, output_file),
        "json" => export_json(&exports, output_file),
        _ => Err(anyhow::anyhow!("Unsupported format: {}", format)),
    }
}

/// Export to CSV format
fn export_csv(data: &[ClientExport], output_file: &str) -> Result<()> {
    let file = std::fs::File::create(output_file)
        .context(format!("Failed to create output file: {}", output_file))?;
    let mut writer = csv::Writer::from_writer(file);

    for record in data {
        writer.serialize(record)?;
    }

    writer.flush()?;
    Ok(())
}

/// Export to JSON format
fn export_json(data: &[ClientExport], output_file: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(data)?;
    std::fs::write(output_file, json)
        .context(format!("Failed to write to output file: {}", output_file))?;
    Ok(())
}

/// Detailed error export with entity information
#[derive(Debug, Serialize)]
struct DetailedErrorExport {
    client_ip: String,
    entity_id: String,
    display_name: String,
    error_type: String,
    path: String,
    timestamp: String,
}

/// Export detailed error analysis with entity-level granularity
fn export_error_details(stats: &TrafficStats, output_file: &str) -> Result<()> {
    let file = std::fs::File::create(output_file)
        .context(format!("Failed to create output file: {}", output_file))?;
    let mut writer = csv::Writer::from_writer(file);

    // Collect all error instances from all clients
    let mut all_errors = Vec::new();

    for (client_ip, client_stats) in &stats.clients {
        for error_instance in &client_stats.error_instances {
            all_errors.push(DetailedErrorExport {
                client_ip: client_ip.clone(),
                entity_id: error_instance.entity_id.clone(),
                display_name: error_instance.display_name.clone(),
                error_type: error_instance.error_type.clone(),
                path: error_instance.path.clone(),
                timestamp: error_instance.timestamp.clone(),
            });
        }
    }

    // Sort by timestamp (most recent first)
    all_errors.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    // Write all error records
    for record in all_errors {
        writer.serialize(record)?;
    }

    writer.flush()?;
    Ok(())
}
