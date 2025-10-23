use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};

mod audit;
mod commands;
mod utils;
mod vault_api;

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
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

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
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Number of top operations to show
        #[arg(long, default_value = "30")]
        top: usize,

        /// Minimum operations to report
        #[arg(long, default_value = "1000")]
        min_operations: usize,
    },

    /// Analyze token operations by entity
    TokenOperations {
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Output CSV file path
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Unified token analysis - operations, abuse detection, and export
    ///
    /// Consolidates all token-related analysis into a single command.
    /// Replaces: token-operations, token-lookup-abuse, token-export
    TokenAnalysis {
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Detect token lookup abuse - show entities exceeding this threshold
        #[arg(long)]
        abuse_threshold: Option<usize>,

        /// Filter by operation type (comma-separated: lookup, create, renew, revoke, login)
        #[arg(long, value_delimiter = ',')]
        filter: Option<Vec<String>>,

        /// Export data to CSV file
        #[arg(long)]
        export: Option<String>,

        /// Minimum operations to include in export
        #[arg(long, default_value = "10")]
        min_operations: usize,
    },

    /// Export token lookup patterns to CSV
    TokenExport {
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Output CSV file
        #[arg(short, long, default_value = "token_lookups.csv")]
        output: String,

        /// Minimum lookups to include
        #[arg(long, default_value = "10")]
        min_lookups: usize,
    },

    /// Detect token lookup abuse patterns
    TokenLookupAbuse {
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Minimum lookups to flag as suspicious
        #[arg(long, default_value = "1000")]
        threshold: usize,
    },

    /// Analyze entity creation/deletion gaps
    EntityGaps {
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Time window in seconds for gap detection
        #[arg(long, default_value = "300")]
        window_seconds: u64,
    },

    /// Show timeline of operations for a specific entity
    EntityTimeline {
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Entity ID to analyze
        #[arg(long)]
        entity_id: String,

        /// Display name (optional)
        #[arg(long)]
        display_name: Option<String>,
    },

    /// Identify path access hotspots
    PathHotspots {
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Number of top paths to show
        #[arg(long, default_value = "50")]
        top: usize,
    },

    /// Analyze Kubernetes auth patterns and entity churn
    K8sAuth {
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Output CSV file for service account analysis
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Analyze Airflow polling patterns
    AirflowPolling {
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Path pattern to analyze (e.g., "airflow")
        #[arg(long)]
        path_pattern: Option<String>,
    },

    /// Preprocess audit logs to extract entity mappings
    PreprocessEntities {
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Output file path
        #[arg(short, long, default_value = "entity_mappings.json")]
        output: String,

        /// Output format: csv or json
        #[arg(long, default_value = "json")]
        format: String,
    },

    /// Analyze entity creation by authentication path
    EntityCreation {
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Optional entity mappings JSON file for display name enrichment
        #[arg(long)]
        entity_map: Option<String>,

        /// Output JSON file path for detailed entity creation data
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Multi-day entity churn analysis with intelligent ephemeral pattern detection
    ///
    /// Tracks entity lifecycle across log files and uses data-driven pattern learning
    /// to detect ephemeral entities (e.g., CI/CD pipelines, temporary build entities)
    /// with confidence scoring and detailed reasoning.
    EntityChurn {
        /// Paths to audit log files (in chronological order)
        #[arg(required = true, num_args = 2..)]
        log_files: Vec<String>,

        /// Optional entity mappings JSON file for display name enrichment
        #[arg(long)]
        entity_map: Option<String>,

        /// Baseline entity list JSON (from entity-list command) to identify pre-existing entities
        #[arg(long)]
        baseline: Option<String>,

        /// Output file path for detailed entity churn data with ephemeral analysis
        #[arg(short, long)]
        output: Option<String>,

        /// Output format: json or csv (auto-detected from file extension if not specified)
        #[arg(long, value_parser = ["json", "csv"])]
        format: Option<String>,
    },

    /// Get Vault client activity by mount (queries Vault API)
    ClientActivity {
        /// Start time in RFC3339 UTC format (e.g., 2025-10-01T00:00:00Z)
        #[arg(long)]
        start: String,

        /// End time in RFC3339 UTC format (e.g., 2025-11-01T00:00:00Z)
        #[arg(long)]
        end: String,

        /// Vault address (default: $VAULT_ADDR or http://127.0.0.1:8200)
        #[arg(long)]
        vault_addr: Option<String>,

        /// Vault token (default: $VAULT_TOKEN or $VAULT_TOKEN_FILE)
        #[arg(long)]
        vault_token: Option<String>,

        /// Skip TLS certificate verification (insecure)
        #[arg(long)]
        insecure: bool,

        /// Group by role/appcode within each mount (uses entity_alias_name)
        #[arg(long)]
        group_by_role: bool,

        /// Path to entity mappings JSON file (for Vault 1.16 compatibility)
        #[arg(long)]
        entity_map: Option<String>,

        /// Output CSV file path
        #[arg(short, long)]
        output: Option<String>,
    },

    /// List Vault entities and aliases (queries Vault API)
    EntityList {
        /// Vault address (default: $VAULT_ADDR or http://127.0.0.1:8200)
        #[arg(long)]
        vault_addr: Option<String>,

        /// Vault token (default: $VAULT_TOKEN or $VAULT_TOKEN_FILE)
        #[arg(long)]
        vault_token: Option<String>,

        /// Skip TLS certificate verification (insecure)
        #[arg(long)]
        insecure: bool,

        /// Output file path
        #[arg(short, long)]
        output: Option<String>,

        /// Output format: csv or json
        #[arg(long, default_value = "csv")]
        format: String,

        /// Filter by specific mount path (e.g., "auth/kubernetes/")
        #[arg(short, long)]
        mount: Option<String>,
    },

    /// Generate shell completion scripts
    GenerateCompletion {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::KvAnalyzer {
            log_files,
            kv_prefix,
            output,
            entity_csv,
        } => commands::kv_analyzer::run(
            &log_files,
            &kv_prefix,
            output.as_deref(),
            entity_csv.as_deref(),
        ),
        Commands::KvCompare { csv1, csv2 } => commands::kv_compare::run(&csv1, &csv2),
        Commands::KvSummary { csv_file } => commands::kv_summary::run(&csv_file),
        Commands::SystemOverview {
            log_files,
            top,
            min_operations,
        } => commands::system_overview::run(&log_files, top, min_operations),
        Commands::TokenOperations { log_files, output } => {
            eprintln!("⚠️  WARNING: 'token-operations' is deprecated.");
            eprintln!("   Use: vault-audit token-analysis [OPTIONS]");
            eprintln!("   Run: vault-audit token-analysis --help for details\n");
            commands::token_operations::run(&log_files, output.as_deref())
        }
        Commands::TokenAnalysis {
            log_files,
            abuse_threshold,
            filter,
            export,
            min_operations,
        } => commands::token_analysis::run(
            &log_files,
            abuse_threshold,
            filter,
            export.as_deref(),
            min_operations,
        ),
        Commands::TokenExport {
            log_files,
            output,
            min_lookups,
        } => {
            eprintln!("⚠️  WARNING: 'token-export' is deprecated.");
            eprintln!("   Use: vault-audit token-analysis --filter lookup --export {} --min-operations {}", output, min_lookups);
            eprintln!("   Run: vault-audit token-analysis --help for details\n");
            commands::token_export::run(&log_files, &output, min_lookups)
        }
        Commands::TokenLookupAbuse {
            log_files,
            threshold,
        } => {
            eprintln!("⚠️  WARNING: 'token-lookup-abuse' is deprecated.");
            eprintln!(
                "   Use: vault-audit token-analysis --abuse-threshold {}",
                threshold
            );
            eprintln!("   Run: vault-audit token-analysis --help for details\n");
            commands::token_lookup_abuse::run(&log_files, threshold)
        }
        Commands::EntityGaps {
            log_files,
            window_seconds,
        } => commands::entity_gaps::run(&log_files, window_seconds),
        Commands::EntityTimeline {
            log_files,
            entity_id,
            display_name,
        } => commands::entity_timeline::run(&log_files, &entity_id, &display_name),
        Commands::PathHotspots { log_files, top } => commands::path_hotspots::run(&log_files, top),
        Commands::K8sAuth { log_files, output } => {
            commands::k8s_auth::run(&log_files, output.as_deref())
        }
        Commands::AirflowPolling {
            log_files,
            path_pattern,
        } => commands::airflow_polling::run(&log_files, path_pattern.as_deref()),
        Commands::PreprocessEntities {
            log_files,
            output,
            format,
        } => commands::preprocess_entities::run(&log_files, &output, format.as_str()),
        Commands::EntityCreation {
            log_files,
            entity_map,
            output,
        } => commands::entity_creation::run(&log_files, entity_map.as_deref(), output.as_deref()),
        Commands::EntityChurn {
            log_files,
            entity_map,
            baseline,
            output,
            format,
        } => commands::entity_churn::run(
            &log_files,
            entity_map.as_deref(),
            baseline.as_deref(),
            output.as_deref(),
            format.as_deref(),
        ),
        Commands::ClientActivity {
            start,
            end,
            vault_addr,
            vault_token,
            insecure,
            group_by_role,
            entity_map,
            output,
        } => {
            commands::client_activity::run(
                &start,
                &end,
                vault_addr.as_deref(),
                vault_token.as_deref(),
                insecure,
                group_by_role,
                entity_map.as_deref(),
                output.as_deref(),
            )
            .await
        }
        Commands::EntityList {
            vault_addr,
            vault_token,
            insecure,
            output,
            format,
            mount,
        } => {
            commands::entity_list::run(
                vault_addr.as_deref(),
                vault_token.as_deref(),
                insecure,
                output.as_deref(),
                format.as_str(),
                mount.as_deref(),
            )
            .await
        }
        Commands::GenerateCompletion { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "vault-audit", &mut std::io::stdout());
            Ok(())
        }
    }
}
