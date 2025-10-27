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

/// Entity analysis subcommands
#[derive(Subcommand)]
enum EntityAnalysisCommands {
    /// Multi-day entity churn analysis with ephemeral pattern detection
    ///
    /// Tracks entity lifecycle across log files with auto-preprocessing enabled by default.
    /// No need to run preprocess-entities separately!
    Churn {
        /// Paths to audit log files (in chronological order)
        #[arg(required = true, num_args = 2..)]
        log_files: Vec<String>,

        /// Optional entity mappings JSON file (auto-generated if not provided)
        #[arg(long)]
        entity_map: Option<String>,

        /// Baseline entity list JSON to identify pre-existing entities
        #[arg(long)]
        baseline: Option<String>,

        /// Output file path for detailed churn data
        #[arg(short, long)]
        output: Option<String>,

        /// Output format: json or csv
        #[arg(long, value_parser = ["json", "csv"])]
        format: Option<String>,

        /// Disable automatic entity preprocessing
        #[arg(long)]
        no_auto_preprocess: bool,
    },

    /// Analyze entity creation by authentication path
    ///
    /// Shows when entities first appear and which auth methods create them.
    /// Auto-preprocessing enabled by default.
    Creation {
        /// Path to audit log file(s)
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Optional entity mappings JSON file (auto-generated if not provided)
        #[arg(long)]
        entity_map: Option<String>,

        /// Output JSON file path for detailed creation data
        #[arg(short, long)]
        output: Option<String>,

        /// Disable automatic entity preprocessing
        #[arg(long)]
        no_auto_preprocess: bool,
    },

    /// Extract entity mappings from audit logs
    ///
    /// Generates entity-to-display-name mappings for external use or manual workflows.
    /// Note: Most commands auto-preprocess, so this is only needed for special cases.
    Preprocess {
        /// Path to audit log file(s)
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Output file path
        #[arg(short, long, default_value = "entity_mappings.json")]
        output: String,

        /// Output format: json or csv
        #[arg(long, default_value = "json")]
        format: String,
    },

    /// Detect activity gaps for entities
    ///
    /// Finds entities with suspicious gaps in activity (potential compromised credentials).
    Gaps {
        /// Path to audit log file(s)
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Time window in seconds for gap detection
        #[arg(long, default_value = "300")]
        window_seconds: u64,
    },

    /// Show timeline of operations for a specific entity
    ///
    /// Displays chronological activity for debugging or investigation.
    Timeline {
        /// Path to audit log file(s)
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Entity ID to analyze
        #[arg(long)]
        entity_id: String,

        /// Display name (optional)
        #[arg(long)]
        display_name: Option<String>,
    },
}

/// KV secrets analysis subcommands
#[derive(Subcommand)]
enum KvAnalysisCommands {
    /// Comprehensive KV usage analysis from audit logs
    ///
    /// Processes audit logs to generate detailed KV usage statistics per path and entity.
    /// Supports multi-file analysis and filtering by KV mount prefix.
    Analyze {
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// KV mount prefix to filter (e.g., "kv/", leave empty for all KV mounts)
        #[arg(long, default_value = "")]
        kv_prefix: String,

        /// Output CSV file path
        #[arg(short, long)]
        output: Option<String>,

        /// Entity alias CSV for enrichment (columns: `entity_id`, name)
        #[arg(long)]
        entity_csv: Option<String>,
    },

    /// Compare KV usage between two time periods
    ///
    /// Identifies changes in access patterns, new secrets, and abandoned secrets.
    Compare {
        /// First CSV file (older period)
        csv1: String,

        /// Second CSV file (newer period)
        csv2: String,
    },

    /// Summarize KV usage from CSV export
    ///
    /// Shows aggregated statistics, top accessed secrets, and breakdown by mount point.
    Summary {
        /// KV usage CSV file
        csv_file: String,
    },
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze KV usage by path and entity (⚠️ DEPRECATED: Use 'kv-analysis analyze' instead)
    #[command(hide = true)]
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

        /// Entity alias CSV for enrichment (columns: `entity_id`, name)
        #[arg(long)]
        entity_csv: Option<String>,
    },

    /// Compare KV usage between two time periods (⚠️ DEPRECATED: Use 'kv-analysis compare' instead)
    #[command(hide = true)]
    KvCompare {
        /// First CSV file (older period)
        csv1: String,

        /// Second CSV file (newer period)
        csv2: String,
    },

    /// Summarize KV usage from CSV (⚠️ DEPRECATED: Use 'kv-analysis summary' instead)
    #[command(hide = true)]
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

        /// Filter by namespace ID (e.g., "root")
        #[arg(long)]
        namespace_filter: Option<String>,

        /// Process files sequentially instead of in parallel (for debugging)
        #[arg(long)]
        sequential: bool,
    },

    /// Analyze token operations by entity (⚠️ DEPRECATED: Use 'token-analysis' instead)
    #[command(hide = true)]
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

    /// Export token lookup patterns to CSV (⚠️ DEPRECATED: Use 'token-analysis --export' instead)
    #[command(hide = true)]
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

    /// Detect token lookup abuse patterns (⚠️ DEPRECATED: Use 'token-analysis --abuse-threshold' instead)
    #[command(hide = true)]
    TokenLookupAbuse {
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Minimum lookups to flag as suspicious
        #[arg(long, default_value = "1000")]
        threshold: usize,
    },

    /// Unified entity lifecycle analysis, creation tracking, and preprocessing
    ///
    /// Consolidates entity analysis with intelligent auto-preprocessing to eliminate
    /// multi-step workflows. Automatically builds entity mappings in-memory when needed.
    #[command(subcommand)]
    EntityAnalysis(EntityAnalysisCommands),

    /// Unified KV secrets analysis - usage, comparison, and summarization
    ///
    /// Consolidates all KV-related analysis commands into a single interface.
    /// Replaces: kv-analyzer, kv-compare, kv-summary
    #[command(subcommand)]
    KvAnalysis(KvAnalysisCommands),

    /// Analyze entity creation/deletion gaps (⚠️ DEPRECATED: Use 'entity-analysis gaps' instead)
    #[command(hide = true)]
    EntityGaps {
        /// Path to audit log file(s) - can specify multiple files
        #[arg(required = true)]
        log_files: Vec<String>,

        /// Time window in seconds for gap detection
        #[arg(long, default_value = "300")]
        window_seconds: u64,
    },

    /// Show timeline of operations for a specific entity (⚠️ DEPRECATED: Use 'entity-analysis timeline' instead)
    #[command(hide = true)]
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

    /// Preprocess audit logs to extract entity mappings (⚠️ DEPRECATED: Use 'entity-analysis preprocess' instead)
    #[command(hide = true)]
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

    /// Analyze entity creation by authentication path (⚠️ DEPRECATED: Use 'entity-analysis creation' instead)
    #[command(hide = true)]
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

    /// Multi-day entity churn analysis with intelligent ephemeral pattern detection (⚠️ DEPRECATED: Use 'entity-analysis churn' instead)
    ///
    /// Tracks entity lifecycle across log files and uses data-driven pattern learning
    /// to detect ephemeral entities (e.g., CI/CD pipelines, temporary build entities)
    /// with confidence scoring and detailed reasoning.
    #[command(hide = true)]
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

        /// Vault address (default: $`VAULT_ADDR` or <http://127.0.0.1:8200>)
        #[arg(long)]
        vault_addr: Option<String>,

        /// Vault token (default: $`VAULT_TOKEN` or $`VAULT_TOKEN_FILE`)
        #[arg(long)]
        vault_token: Option<String>,

        /// Vault namespace (default: $`VAULT_NAMESPACE`)
        #[arg(long)]
        vault_namespace: Option<String>,

        /// Skip TLS certificate verification (insecure)
        #[arg(long)]
        insecure: bool,

        /// Group by role/appcode within each mount (uses `entity_alias_name`)
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
        /// Vault address (default: $`VAULT_ADDR` or <http://127.0.0.1:8200>)
        #[arg(long)]
        vault_addr: Option<String>,

        /// Vault token (default: $`VAULT_TOKEN` or $`VAULT_TOKEN_FILE`)
        #[arg(long)]
        vault_token: Option<String>,

        /// Vault namespace (default: $`VAULT_NAMESPACE`)
        #[arg(long)]
        vault_namespace: Option<String>,

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
        } => {
            eprintln!("⚠️  WARNING: 'kv-analyzer' is deprecated.");
            eprintln!("   Use: vault-audit kv-analysis analyze [OPTIONS]");
            eprintln!("   Run: vault-audit kv-analysis analyze --help for details\n");
            commands::kv_analyzer::run(
                &log_files,
                &kv_prefix,
                output.as_deref(),
                entity_csv.as_deref(),
            )
        }
        Commands::KvCompare { csv1, csv2 } => {
            eprintln!("⚠️  WARNING: 'kv-compare' is deprecated.");
            eprintln!("   Use: vault-audit kv-analysis compare <CSV1> <CSV2>");
            eprintln!("   Run: vault-audit kv-analysis compare --help for details\n");
            commands::kv_compare::run(&csv1, &csv2)
        }
        Commands::KvSummary { csv_file } => {
            eprintln!("⚠️  WARNING: 'kv-summary' is deprecated.");
            eprintln!("   Use: vault-audit kv-analysis summary <CSV_FILE>");
            eprintln!("   Run: vault-audit kv-analysis summary --help for details\n");
            commands::kv_summary::run(&csv_file)
        }
        Commands::SystemOverview {
            log_files,
            top,
            min_operations,
            namespace_filter,
            sequential,
        } => commands::system_overview::run(
            &log_files,
            top,
            min_operations,
            namespace_filter.as_deref(),
            sequential,
        ),
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
            filter.as_deref(),
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
        Commands::EntityAnalysis(entity_cmd) => match entity_cmd {
            EntityAnalysisCommands::Churn {
                log_files,
                entity_map,
                baseline,
                output,
                format,
                no_auto_preprocess,
            } => commands::entity_analysis::run_churn(
                &log_files,
                entity_map.as_ref(),
                baseline.as_ref(),
                output.as_ref(),
                format.as_ref(),
                !no_auto_preprocess,
            ),
            EntityAnalysisCommands::Creation {
                log_files,
                entity_map,
                output,
                no_auto_preprocess,
            } => commands::entity_analysis::run_creation(
                &log_files,
                entity_map.as_ref(),
                output.as_ref(),
                !no_auto_preprocess,
            ),
            EntityAnalysisCommands::Preprocess {
                log_files,
                output,
                format,
            } => commands::entity_analysis::run_preprocess(&log_files, &output, &format),
            EntityAnalysisCommands::Gaps {
                log_files,
                window_seconds,
            } => commands::entity_analysis::run_gaps(&log_files, window_seconds),
            EntityAnalysisCommands::Timeline {
                log_files,
                entity_id,
                display_name,
            } => commands::entity_analysis::run_timeline(
                &log_files,
                &entity_id,
                display_name.as_ref(),
            ),
        },
        Commands::KvAnalysis(kv_cmd) => match kv_cmd {
            KvAnalysisCommands::Analyze {
                log_files,
                kv_prefix,
                output,
                entity_csv,
            } => commands::kv_analysis::run_analyze(
                &log_files,
                &kv_prefix,
                output.as_ref(),
                entity_csv.as_ref(),
            ),
            KvAnalysisCommands::Compare { csv1, csv2 } => {
                commands::kv_analysis::run_compare(&csv1, &csv2)
            }
            KvAnalysisCommands::Summary { csv_file } => {
                commands::kv_analysis::run_summary(&csv_file)
            }
        },
        Commands::EntityGaps {
            log_files,
            window_seconds,
        } => {
            eprintln!("⚠️  WARNING: 'entity-gaps' is deprecated.");
            eprintln!("   Use: vault-audit entity-analysis gaps [OPTIONS]");
            eprintln!("   Run: vault-audit entity-analysis gaps --help for details\n");
            commands::entity_gaps::run(&log_files, window_seconds)
        }
        Commands::EntityTimeline {
            log_files,
            entity_id,
            display_name,
        } => {
            eprintln!("⚠️  WARNING: 'entity-timeline' is deprecated.");
            eprintln!(
                "   Use: vault-audit entity-analysis timeline --entity-id {} [OPTIONS]",
                entity_id
            );
            eprintln!("   Run: vault-audit entity-analysis timeline --help for details\n");
            commands::entity_timeline::run(&log_files, &entity_id, display_name.as_ref())
        }
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
        } => {
            eprintln!("⚠️  WARNING: 'preprocess-entities' is deprecated.");
            eprintln!("   Use: vault-audit entity-analysis preprocess [OPTIONS]");
            eprintln!("   Note: Most commands now auto-preprocess, so this is rarely needed!");
            eprintln!("   Run: vault-audit entity-analysis --help for details\n");
            commands::preprocess_entities::run(&log_files, &output, format.as_str())
        }
        Commands::EntityCreation {
            log_files,
            entity_map,
            output,
        } => {
            eprintln!("⚠️  WARNING: 'entity-creation' is deprecated.");
            eprintln!("   Use: vault-audit entity-analysis creation [OPTIONS]");
            eprintln!("   Run: vault-audit entity-analysis creation --help for details\n");
            commands::entity_creation::run(&log_files, entity_map.as_deref(), output.as_deref())
        }
        Commands::EntityChurn {
            log_files,
            entity_map,
            baseline,
            output,
            format,
        } => {
            eprintln!("⚠️  WARNING: 'entity-churn' is deprecated.");
            eprintln!("   Use: vault-audit entity-analysis churn [OPTIONS]");
            eprintln!("   Run: vault-audit entity-analysis churn --help for details\n");
            commands::entity_churn::run(
                &log_files,
                entity_map.as_deref(),
                baseline.as_deref(),
                output.as_deref(),
                format.as_deref(),
            )
        }
        Commands::ClientActivity {
            start,
            end,
            vault_addr,
            vault_token,
            vault_namespace,
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
                vault_namespace.as_deref(),
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
            vault_namespace,
            insecure,
            output,
            format,
            mount,
        } => {
            commands::entity_list::run(
                vault_addr.as_deref(),
                vault_token.as_deref(),
                vault_namespace.as_deref(),
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
