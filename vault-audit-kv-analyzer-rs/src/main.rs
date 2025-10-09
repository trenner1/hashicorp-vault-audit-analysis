use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

/// Vault KV Usage Analyzer - Parse audit logs to report client usage by KV path (Rust Edition)
#[derive(Parser, Debug)]
#[command(name = "vault-audit-kv-analyzer-rs")]
#[command(about = "Analyze Vault audit logs to determine KV usage by client/entity", long_about = None)]
struct Args {
    /// Path(s) to Vault audit log file(s)
    #[arg(required = true)]
    log_files: Vec<PathBuf>,

    /// KV mount prefix to filter (default: kv/)
    #[arg(long, default_value = "kv/")]
    kv_prefix: String,

    /// Path to vault_identity_alias_export.csv to map entity IDs to alias names
    #[arg(long)]
    alias_export: Option<PathBuf>,

    /// Output CSV file for KV usage analysis
    #[arg(long, default_value = "data/kv_usage_by_client.csv")]
    output: PathBuf,
}

#[derive(Deserialize, Debug)]
struct AuditLogEntry {
    #[serde(default)]
    auth: Auth,
    #[serde(default)]
    request: Request,
}

#[derive(Deserialize, Debug, Default)]
struct Auth {
    entity_id: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
struct Request {
    path: Option<String>,
    operation: Option<String>,
}

#[derive(Debug)]
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
}

/// Parse a single audit log JSON line
fn parse_audit_log_line(line: &str, kv_prefix: &str) -> Option<(String, String)> {
    let entry: AuditLogEntry = serde_json::from_str(line).ok()?;
    
    let entity_id = entry.auth.entity_id?;
    let path = entry.request.path?;
    let operation = entry.request.operation?;
    
    // Filter for KV operations (read, list)
    if operation != "read" && operation != "list" {
        return None;
    }
    
    // Check if path matches KV pattern
    if !kv_prefix.is_empty() {
        if !path.starts_with(kv_prefix) {
            return None;
        }
    } else {
        // Match any path that contains /data/ or /metadata/ (KV v2 pattern)
        if !path.contains("/data/") && !path.contains("/metadata/") {
            return None;
        }
    }
    
    Some((entity_id, path))
}

/// Normalize KV path to app-level grouping
fn normalize_kv_path(path: &str) -> String {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    
    // Handle KV v2 paths (kv/data/... or kv/metadata/...)
    if parts.len() >= 3 && (parts[1] == "data" || parts[1] == "metadata") {
        let mount = parts[0];
        let remaining: Vec<&str> = parts[2..].to_vec();
        
        return match remaining.len() {
            0 => format!("{}/", mount),
            1 => format!("{}/{}/", mount, remaining[0]),
            2 => format!("{}/{}/{}/", mount, remaining[0], remaining[1]),
            _ => format!("{}/{}/{}/{}/", mount, remaining[0], remaining[1], remaining[2]),
        };
    }
    
    // Handle KV v1 or simple paths
    match parts.len() {
        0 => String::from("/"),
        1 => format!("{}/", parts[0]),
        2 => format!("{}/{}/", parts[0], parts[1]),
        3 => format!("{}/{}/{}/", parts[0], parts[1], parts[2]),
        _ => format!("{}/{}/{}/{}/", parts[0], parts[1], parts[2], parts[3]),
    }
}

/// Analyze audit logs and aggregate KV usage by path
fn analyze_audit_logs(log_files: &[PathBuf], kv_prefix: &str) -> Result<HashMap<String, KvUsageData>> {
    let mut kv_usage: HashMap<String, KvUsageData> = HashMap::new();
    let mut total_lines = 0;
    let mut parsed_lines = 0;
    
    for log_file in log_files {
        eprintln!("Processing: {}", log_file.display());
        
        let file = File::open(log_file)
            .with_context(|| format!("Failed to open log file: {}", log_file.display()))?;
        let reader = BufReader::new(file);
        
        for line in reader.lines() {
            total_lines += 1;
            
            if total_lines % 500_000 == 0 {
                eprintln!("  Processed {} lines...", total_lines);
            }
            
            let line = line.context("Failed to read line")?;
            
            if let Some((entity_id, path)) = parse_audit_log_line(&line, kv_prefix) {
                parsed_lines += 1;
                
                // Normalize path to app-level
                let app_path = normalize_kv_path(&path);
                
                // Get or create entry
                let entry = kv_usage.entry(app_path).or_insert_with(KvUsageData::new);
                
                // Aggregate
                entry.entity_ids.insert(entity_id);
                entry.operations_count += 1;
                entry.paths_accessed.insert(path);
            }
        }
    }
    
    eprintln!("[INFO] Processed {} lines, parsed {} KV operations", total_lines, parsed_lines);
    
    Ok(kv_usage)
}

/// Load entity/alias mapping from CSV
fn load_entity_alias_mapping(alias_export: &Option<PathBuf>) -> Result<HashMap<String, Vec<String>>> {
    let mut entity_aliases: HashMap<String, Vec<String>> = HashMap::new();
    
    let Some(path) = alias_export else {
        return Ok(entity_aliases);
    };
    
    if !path.exists() {
        eprintln!("[WARN] Entity alias export not found: {}", path.display());
        return Ok(entity_aliases);
    }
    
    let file = File::open(path)
        .with_context(|| format!("Failed to open alias export: {}", path.display()))?;
    let mut reader = csv::Reader::from_reader(file);
    
    for result in reader.records() {
        let record = result.context("Failed to read CSV record")?;
        if let (Some(entity_id), Some(alias_name)) = (record.get(0), record.get(1)) {
            entity_aliases
                .entry(entity_id.to_string())
                .or_insert_with(Vec::new)
                .push(alias_name.to_string());
        }
    }
    
    Ok(entity_aliases)
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Ensure data directory exists
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create output directory")?;
    }
    
    // Parse audit logs
    let kv_usage = analyze_audit_logs(&args.log_files, &args.kv_prefix)?;
    
    if kv_usage.is_empty() {
        eprintln!("[ERROR] No KV operations found in audit logs.");
        std::process::exit(1);
    }
    
    // Load entity/alias mapping for enrichment
    let entity_aliases = load_entity_alias_mapping(&args.alias_export)?;
    
    // Write output CSV with CRLF line endings (to match Python csv module default)
    let output_file = File::create(&args.output)
        .with_context(|| format!("Failed to create output file: {}", args.output.display()))?;
    let mut writer = csv::WriterBuilder::new()
        .terminator(csv::Terminator::CRLF)
        .from_writer(output_file);
    
    // Write header
    writer.write_record(&[
        "kv_path",
        "unique_clients",
        "operations_count",
        "entity_ids",
        "alias_names",
        "sample_paths_accessed",
    ])?;
    
    // Sort paths for consistent output
    let mut sorted_paths: Vec<_> = kv_usage.keys().collect();
    sorted_paths.sort();
    
    for kv_path in sorted_paths {
        let data = &kv_usage[kv_path];
        
        let mut entity_ids: Vec<_> = data.entity_ids.iter().cloned().collect();
        entity_ids.sort();
        
        let unique_clients = data.entity_ids.len();
        let operations = data.operations_count;
        
        // Collect alias names for these entities
        let mut alias_names = Vec::new();
        for eid in &entity_ids {
            if let Some(aliases) = entity_aliases.get(eid) {
                alias_names.extend(aliases.iter().cloned());
            }
        }
        
        // Sample of paths accessed (limit to 5 for readability)
        let mut sample_paths: Vec<_> = data.paths_accessed.iter().cloned().collect();
        sample_paths.sort();
        sample_paths.truncate(5);
        
        writer.write_record(&[
            kv_path.clone(),
            unique_clients.to_string(),
            operations.to_string(),
            entity_ids.join(", "),
            alias_names.join(", "),
            sample_paths.join(", "),
        ])?;
    }
    
    writer.flush()?;
    
    println!("Done. Output written to: {}", args.output.display());
    println!("Summary: {} KV paths analyzed", kv_usage.len());
    
    Ok(())
}
