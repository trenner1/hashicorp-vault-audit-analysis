use anyhow::Result;
use clap::{Parser, Subcommand};

mod audit;
mod commands;
mod utils;

#[derive(Parser)]
#[command(name = "vault-audit")]
#[command(about = "Vault audit log analysis tools", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze KV usage by path and entity
    KvAnalyzer {
        /// Path to audit log file
        log_file: String,
        
        /// KV mount prefix to filter (e.g., "kv/", leave empty for all KV mounts)
        #[arg(long, default_value = "")]
        kv_prefix: String,
        
        /// Output CSV file path
        #[arg(short, long)]
        output: Option<String>,
        
        /// Entity alias CSV for enrichment (columns: entity_id, name)
        #[arg(long)]
        entity_csv: Option<String>,
    },

    /// Compare KV usage between two time periods
    KvCompare {
        /// First CSV file (older period)
        csv1: String,
        
        /// Second CSV file (newer period)
        csv2: String,
    },

    /// Summarize KV usage from CSV
    KvSummary {
        /// KV usage CSV file
        csv_file: String,
    },

    /// System overview - identify high-volume operations
    SystemOverview {
        /// Path to audit log file
        log_file: String,
        
        /// Number of top operations to show
        #[arg(long, default_value = "30")]
        top: usize,
        
        /// Minimum operations to report
        #[arg(long, default_value = "1000")]
        min_operations: usize,
    },

    /// Analyze token operations by entity
    TokenOperations {
        /// Path to audit log file
        log_file: String,
        
        /// Output CSV file path
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Export token lookup patterns to CSV
    TokenExport {
        /// Path to audit log file
        log_file: String,
        
        /// Output CSV file
        #[arg(short, long, default_value = "token_lookups.csv")]
        output: String,
        
        /// Minimum lookups to include
        #[arg(long, default_value = "10")]
        min_lookups: usize,
    },

    /// Detect token lookup abuse patterns
    TokenLookupAbuse {
        /// Path to audit log file
        log_file: String,
        
        /// Minimum lookups to flag as suspicious
        #[arg(long, default_value = "1000")]
        threshold: usize,
    },

    /// Analyze entity creation/deletion gaps
    EntityGaps {
        /// Path to audit log file
        log_file: String,
        
        /// Time window in seconds for gap detection
        #[arg(long, default_value = "300")]
        window_seconds: u64,
    },

    /// Show timeline of operations for a specific entity
    EntityTimeline {
        /// Path to audit log file
        log_file: String,
        
        /// Entity ID to analyze
        #[arg(long)]
        entity_id: String,
        
        /// Display name (optional)
        #[arg(long)]
        display_name: Option<String>,
    },

    /// Identify path access hotspots
    PathHotspots {
        /// Path to audit log file
        log_file: String,
        
        /// Number of top paths to show
        #[arg(long, default_value = "50")]
        top: usize,
    },

    /// Analyze Kubernetes auth patterns and entity churn
    K8sAuth {
        /// Path to audit log file
        log_file: String,
        
        /// Output CSV file for service account analysis
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Analyze Airflow polling patterns
    AirflowPolling {
        /// Path to audit log file
        log_file: String,
        
        /// Path pattern to analyze (e.g., "airflow")
        #[arg(long)]
        path_pattern: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::KvAnalyzer { log_file, kv_prefix, output, entity_csv } => {
            commands::kv_analyzer::run(&log_file, &kv_prefix, output.as_deref(), entity_csv.as_deref())
        }
        Commands::KvCompare { csv1, csv2 } => {
            commands::kv_compare::run(&csv1, &csv2)
        }
        Commands::KvSummary { csv_file } => {
            commands::kv_summary::run(&csv_file)
        }
        Commands::SystemOverview { log_file, top, min_operations } => {
            commands::system_overview::run(&log_file, top, min_operations)
        }
        Commands::TokenOperations { log_file, output } => {
            commands::token_operations::run(&log_file, output.as_deref())
        }
        Commands::TokenExport { log_file, output, min_lookups } => {
            commands::token_export::run(&log_file, &output, min_lookups)
        }
        Commands::TokenLookupAbuse { log_file, threshold } => {
            commands::token_lookup_abuse::run(&log_file, threshold)
        }
        Commands::EntityGaps { log_file, window_seconds } => {
            commands::entity_gaps::run(&log_file, window_seconds)
        }
        Commands::EntityTimeline { log_file, entity_id, display_name } => {
            commands::entity_timeline::run(&log_file, &entity_id, &display_name)
        }
        Commands::PathHotspots { log_file, top } => {
            commands::path_hotspots::run(&log_file, top)
        }
        Commands::K8sAuth { log_file, output } => {
            commands::k8s_auth::run(&log_file, output.as_deref())
        }
        Commands::AirflowPolling { log_file, path_pattern } => {
            commands::airflow_polling::run(&log_file, path_pattern.as_deref())
        }
    }
}
