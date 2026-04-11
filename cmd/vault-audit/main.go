// Command vault-audit provides high-performance tools for analyzing HashiCorp Vault audit logs.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/commands"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "vault-audit",
		Short: "Vault audit log analysis tools",
		Long:  "High-performance command-line tools for analyzing HashiCorp Vault audit logs.",
	}

	root.AddCommand(
		// ── System analysis ──────────────────────────────────────────────────────
		systemOverviewCmd(),
		pathHotspotsCmd(),
		clientTrafficAnalysisCmd(),

		// ── Entity analysis (unified) ─────────────────────────────────────────
		entityAnalysisCmd(),

		// ── Token analysis (unified) ──────────────────────────────────────────
		tokenAnalysisCmd(),

		// ── KV secrets analysis (unified) ─────────────────────────────────────
		kvAnalysisCmd(),

		// ── Authentication analysis ───────────────────────────────────────────
		k8sAuthCmd(),
		airflowPollingCmd(),

		// ── Vault API commands ────────────────────────────────────────────────
		clientActivityCmd(),
		entityListCmd(),
		kvMountsCmd(),
		authMountsCmd(),

		// ── Utilities ─────────────────────────────────────────────────────────
		generateCompletionCmd(root),
	)
	return root
}

// ═══════════════════════════════════════════════════════════════════
// System analysis
// ═══════════════════════════════════════════════════════════════════

func systemOverviewCmd() *cobra.Command {
	var top, minOps int
	var nsFilter string
	var sequential bool

	cmd := &cobra.Command{
		Use:   "system-overview [log-files...]",
		Short: "High-level overview of all operations, entities, and auth methods",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.SystemOverviewRun(args, top, minOps, nsFilter, sequential)
		},
	}
	cmd.Flags().IntVar(&top, "top", 30, "Number of top operations to show")
	cmd.Flags().IntVar(&minOps, "min-operations", 1000, "Minimum operations to report")
	cmd.Flags().StringVar(&nsFilter, "namespace-filter", "", "Filter by namespace ID (e.g. \"root\")")
	cmd.Flags().BoolVar(&sequential, "sequential", false, "Process files sequentially instead of in parallel (for debugging)")
	return cmd
}

func pathHotspotsCmd() *cobra.Command {
	var top int

	cmd := &cobra.Command{
		Use:   "path-hotspots [log-files...]",
		Short: "Find most accessed paths with optimization recommendations",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.PathHotspotsRun(args, top)
		},
	}
	cmd.Flags().IntVar(&top, "top", 50, "Number of top paths to show")
	return cmd
}

func clientTrafficAnalysisCmd() *cobra.Command {
	var output, format, errorDetailsOutput *string
	var top, minRequests int
	var temporal, showOps, showErrs, showDetails, verbose bool

	outputStr := ""
	formatStr := ""
	errorDetailsStr := ""

	cmd := &cobra.Command{
		Use:   "client-traffic-analysis [log-files...]",
		Short: "Analyze client traffic patterns from aggregated audit logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Changed("output") {
				output = &outputStr
			}
			if cmd.Flags().Changed("format") {
				format = &formatStr
			}
			if cmd.Flags().Changed("error-details-output") {
				errorDetailsOutput = &errorDetailsStr
			}
			showOpsEff := verbose || showOps
			showErrsEff := verbose || showErrs
			showDetailsEff := verbose || showDetails
			return commands.RunClientTrafficAnalysis(
				args, output, format, errorDetailsOutput,
				top, temporal, minRequests,
				showOpsEff, showErrsEff, showDetailsEff,
			)
		},
	}
	cmd.Flags().StringVar(&outputStr, "output", "", "Output file path for summary metrics (CSV or JSON)")
	cmd.Flags().StringVar(&formatStr, "format", "", "Output format: json or csv (auto-detected from extension)")
	cmd.Flags().StringVar(&errorDetailsStr, "error-details-output", "", "Output file for detailed error analysis (CSV)")
	cmd.Flags().IntVar(&top, "top", 20, "Number of top clients to show in summary")
	cmd.Flags().IntVar(&minRequests, "min-requests", 100, "Minimum requests threshold for client classification")
	cmd.Flags().BoolVar(&temporal, "temporal", false, "Enable temporal analysis (hourly request patterns)")
	cmd.Flags().BoolVar(&showOps, "show-operations", false, "Show operation type breakdown per client")
	cmd.Flags().BoolVar(&showErrs, "show-errors", false, "Show error details and patterns")
	cmd.Flags().BoolVar(&showDetails, "show-details", false, "Show detailed per-client analysis")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show all available information")
	cmd.Flags().StringVarP(&outputStr, "output-short", "o", "", "")
	cmd.Flags().MarkHidden("output-short") //nolint:errcheck
	return cmd
}

// ═══════════════════════════════════════════════════════════════════
// Entity analysis (unified)
// ═══════════════════════════════════════════════════════════════════

func entityAnalysisCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "entity-analysis",
		Short: "Unified entity lifecycle analysis, creation tracking, and preprocessing",
		Long: `Consolidates entity analysis with intelligent auto-preprocessing to eliminate
multi-step workflows. Automatically builds entity mappings in-memory when needed.`,
	}
	cmd.AddCommand(
		entityChurnSubCmd(),
		entityCreationSubCmd(),
		entityPreprocessSubCmd(),
		entityGapsSubCmd(),
		entityTimelineSubCmd(),
	)
	return cmd
}

func entityChurnSubCmd() *cobra.Command {
	var entityMap, baseline, output, format string
	var noAutoPreprocess bool

	cmd := &cobra.Command{
		Use:   "churn [log-files...]",
		Short: "Multi-day entity lifecycle tracking with ephemeral detection",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var emPtr, blPtr, outPtr, fmtPtr *string
			if cmd.Flags().Changed("entity-map") {
				emPtr = &entityMap
			}
			if cmd.Flags().Changed("baseline") {
				blPtr = &baseline
			}
			if cmd.Flags().Changed("output") {
				outPtr = &output
			}
			if cmd.Flags().Changed("format") {
				fmtPtr = &format
			}
			return commands.RunChurn(args, emPtr, blPtr, outPtr, fmtPtr, !noAutoPreprocess)
		},
	}
	cmd.Flags().StringVar(&entityMap, "entity-map", "", "Optional entity mappings JSON file (auto-generated if not provided)")
	cmd.Flags().StringVar(&baseline, "baseline", "", "Baseline entity list JSON to identify pre-existing entities")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path for detailed churn data")
	cmd.Flags().StringVar(&format, "format", "", "Output format: json or csv")
	cmd.Flags().BoolVar(&noAutoPreprocess, "no-auto-preprocess", false, "Disable automatic entity preprocessing")
	return cmd
}

func entityCreationSubCmd() *cobra.Command {
	var entityMap, output string
	var noAutoPreprocess bool

	cmd := &cobra.Command{
		Use:   "creation [log-files...]",
		Short: "Analyze entity creation by authentication path",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var emPtr, outPtr *string
			if cmd.Flags().Changed("entity-map") {
				emPtr = &entityMap
			}
			if cmd.Flags().Changed("output") {
				outPtr = &output
			}
			return commands.RunCreation(args, emPtr, outPtr, !noAutoPreprocess)
		},
	}
	cmd.Flags().StringVar(&entityMap, "entity-map", "", "Optional entity mappings JSON file")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output JSON file path for detailed creation data")
	cmd.Flags().BoolVar(&noAutoPreprocess, "no-auto-preprocess", false, "Disable automatic entity preprocessing")
	return cmd
}

func entityPreprocessSubCmd() *cobra.Command {
	var output, format string

	cmd := &cobra.Command{
		Use:   "preprocess [log-files...]",
		Short: "Extract entity mappings from audit logs",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.RunPreprocess(args, output, format)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "entity_mappings.json", "Output file path")
	cmd.Flags().StringVar(&format, "format", "json", "Output format: json or csv")
	return cmd
}

func entityGapsSubCmd() *cobra.Command {
	var windowSeconds uint64

	cmd := &cobra.Command{
		Use:   "gaps [log-files...]",
		Short: "Detect activity gaps for entities",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.RunGaps(args, windowSeconds)
		},
	}
	cmd.Flags().Uint64Var(&windowSeconds, "window-seconds", 300, "Time window in seconds for gap detection")
	return cmd
}

func entityTimelineSubCmd() *cobra.Command {
	var entityID, displayName string

	cmd := &cobra.Command{
		Use:   "timeline [log-files...]",
		Short: "Show timeline of operations for a specific entity",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var dnPtr *string
			if cmd.Flags().Changed("display-name") {
				dnPtr = &displayName
			}
			return commands.RunTimeline(args, entityID, dnPtr)
		},
	}
	cmd.Flags().StringVar(&entityID, "entity-id", "", "Entity ID to analyze")
	cmd.Flags().StringVar(&displayName, "display-name", "", "Display name (optional)")
	cmd.MarkFlagRequired("entity-id") //nolint:errcheck
	return cmd
}

// ═══════════════════════════════════════════════════════════════════
// Token analysis (unified)
// ═══════════════════════════════════════════════════════════════════

func tokenAnalysisCmd() *cobra.Command {
	var abuseThresholdInt int
	var abuseThresholdSet bool
	var filter []string
	var minOps int

	cmd := &cobra.Command{
		Use:   "token-analysis [log-files...]",
		Short: "Analyze token usage patterns and detect potential abuse",
		Long:  "Analyze token operations from audit logs. Generates timestamped CSV output with per-accessor token activity details.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var abPtr *int
			if abuseThresholdSet {
				abPtr = &abuseThresholdInt
			}
			return commands.RunTokenAnalysis(args, abPtr, filter, minOps)
		},
	}
	cmd.Flags().IntVar(&abuseThresholdInt, "abuse-threshold", 0, "Threshold for abuse detection (default: 10000)")
	cmd.Flags().StringSliceVar(&filter, "filter", nil, "Filter by operation type (comma-separated: lookup, create, renew, revoke, login)")
	cmd.Flags().IntVar(&minOps, "min-operations", 100, "Minimum operations to include token (default: 100)")
	// Track whether abuse-threshold was explicitly set.
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		abuseThresholdSet = cmd.Flags().Changed("abuse-threshold")
		return nil
	}
	return cmd
}

// ═══════════════════════════════════════════════════════════════════
// KV secrets analysis (unified)
// ═══════════════════════════════════════════════════════════════════

func kvAnalysisCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kv-analysis",
		Short: "Unified KV secrets analysis — usage, comparison, and summarization",
	}
	cmd.AddCommand(kvAnalyzeSubCmd(), kvCompareSubCmd(), kvSummarySubCmd())
	return cmd
}

func kvAnalyzeSubCmd() *cobra.Command {
	var kvPrefix, entityCSV, output string

	cmd := &cobra.Command{
		Use:   "analyze [log-files...]",
		Short: "Comprehensive KV usage analysis from audit logs",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var outPtr, ecPtr *string
			if cmd.Flags().Changed("output") {
				outPtr = &output
			}
			if cmd.Flags().Changed("entity-csv") {
				ecPtr = &entityCSV
			}
			return commands.RunKVAnalyze(args, kvPrefix, outPtr, ecPtr)
		},
	}
	cmd.Flags().StringVar(&kvPrefix, "kv-prefix", "", "KV mount prefix to filter (e.g. \"kv/\", leave empty for all KV mounts)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output CSV file path")
	cmd.Flags().StringVar(&entityCSV, "entity-csv", "", "Entity alias CSV for enrichment (columns: entity_id, name)")
	return cmd
}

func kvCompareSubCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "compare <csv1> <csv2>",
		Short: "Compare KV usage between two time periods",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.RunKVCompare(args[0], args[1])
		},
	}
}

func kvSummarySubCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "summary <csv-file>",
		Short: "Summarize KV usage from CSV export",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.RunKVSummary(args[0])
		},
	}
}

// ═══════════════════════════════════════════════════════════════════
// Authentication & app-specific analysis
// ═══════════════════════════════════════════════════════════════════

func k8sAuthCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "k8s-auth [log-files...]",
		Short: "Analyze Kubernetes/OpenShift authentication patterns and entity churn",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var outPtr *string
			if cmd.Flags().Changed("output") {
				outPtr = &output
			}
			return commands.RunK8sAuth(args, outPtr)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output CSV file for service account analysis")
	return cmd
}

func airflowPollingCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "airflow-polling [log-files...]",
		Short: "Analyze Airflow secret polling patterns with burst rate detection",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var outPtr *string
			if cmd.Flags().Changed("output") {
				outPtr = &output
			}
			return commands.AirflowPollingRun(args, outPtr)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output CSV file for detailed analysis")
	return cmd
}

// ═══════════════════════════════════════════════════════════════════
// Vault API commands
// ═══════════════════════════════════════════════════════════════════

func optionalStr(cmd *cobra.Command, flag string, val *string) *string {
	if cmd.Flags().Changed(flag) {
		return val
	}
	return nil
}

func clientActivityCmd() *cobra.Command {
	var start, end string
	var groupByRole bool
	var entityMap, output string
	addr := ""
	token := ""
	ns := ""
	ins := false

	cmd := &cobra.Command{
		Use:   "client-activity",
		Short: "Query Vault for client activity metrics by mount",
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.RunClientActivity(
				start, end,
				optionalStr(cmd, "vault-addr", &addr),
				optionalStr(cmd, "vault-token", &token),
				optionalStr(cmd, "vault-namespace", &ns),
				ins, groupByRole,
				optionalStr(cmd, "entity-map", &entityMap),
				optionalStr(cmd, "output", &output),
			)
		},
	}
	cmd.Flags().StringVar(&start, "start", "", "Start time in RFC3339 UTC (e.g. 2025-10-01T00:00:00Z)")
	cmd.Flags().StringVar(&end, "end", "", "End time in RFC3339 UTC")
	cmd.Flags().StringVar(&addr, "vault-addr", "", "Vault address (default: $VAULT_ADDR)")
	cmd.Flags().StringVar(&token, "vault-token", "", "Vault token (default: $VAULT_TOKEN)")
	cmd.Flags().StringVar(&ns, "vault-namespace", "", "Vault namespace (default: $VAULT_NAMESPACE)")
	cmd.Flags().BoolVar(&ins, "insecure", false, "Skip TLS certificate verification")
	cmd.Flags().BoolVar(&groupByRole, "group-by-role", false, "Group by role/appcode within each mount")
	cmd.Flags().StringVar(&entityMap, "entity-map", "", "Path to entity mappings JSON file")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output CSV file path")
	cmd.MarkFlagRequired("start") //nolint:errcheck
	cmd.MarkFlagRequired("end")   //nolint:errcheck
	return cmd
}

func entityListCmd() *cobra.Command {
	var format, mount, output string
	addr := ""
	token := ""
	ns := ""
	ins := false

	cmd := &cobra.Command{
		Use:   "entity-list",
		Short: "List Vault entities and aliases (queries Vault API)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.RunEntityList(
				optionalStr(cmd, "vault-addr", &addr),
				optionalStr(cmd, "vault-token", &token),
				optionalStr(cmd, "vault-namespace", &ns),
				ins,
				optionalStr(cmd, "output", &output),
				format,
				optionalStr(cmd, "mount", &mount),
			)
		},
	}
	cmd.Flags().StringVar(&addr, "vault-addr", "", "Vault address (default: $VAULT_ADDR)")
	cmd.Flags().StringVar(&token, "vault-token", "", "Vault token (default: $VAULT_TOKEN)")
	cmd.Flags().StringVar(&ns, "vault-namespace", "", "Vault namespace (default: $VAULT_NAMESPACE)")
	cmd.Flags().BoolVar(&ins, "insecure", false, "Skip TLS certificate verification")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	cmd.Flags().StringVar(&format, "format", "csv", "Output format: csv or json")
	cmd.Flags().StringVarP(&mount, "mount", "m", "", "Filter by specific mount path (e.g. auth/kubernetes/)")
	return cmd
}

func kvMountsCmd() *cobra.Command {
	var format, output string
	var depth int
	var depthSet bool
	addr := ""
	token := ""
	ns := ""
	ins := false

	cmd := &cobra.Command{
		Use:   "kv-mounts",
		Short: "List KV secret mounts (queries Vault API)",
		RunE: func(cmd *cobra.Command, args []string) error {
			maxDepth := -1 // unlimited
			if depthSet {
				maxDepth = depth
			}
			return commands.RunKVMounts(
				optionalStr(cmd, "vault-addr", &addr),
				optionalStr(cmd, "vault-token", &token),
				optionalStr(cmd, "vault-namespace", &ns),
				ins,
				optionalStr(cmd, "output", &output),
				format,
				maxDepth,
			)
		},
	}
	cmd.Flags().StringVar(&addr, "vault-addr", "", "Vault address (default: $VAULT_ADDR)")
	cmd.Flags().StringVar(&token, "vault-token", "", "Vault token (default: $VAULT_TOKEN)")
	cmd.Flags().StringVar(&ns, "vault-namespace", "", "Vault namespace (default: $VAULT_NAMESPACE)")
	cmd.Flags().BoolVar(&ins, "insecure", false, "Skip TLS certificate verification")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	cmd.Flags().StringVar(&format, "format", "csv", "Output format: csv, json, or stdout")
	cmd.Flags().IntVarP(&depth, "depth", "d", 0, "Max depth to traverse within KV mounts (default: unlimited; 0 = mounts only)")
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		depthSet = cmd.Flags().Changed("depth")
		return nil
	}
	return cmd
}

func authMountsCmd() *cobra.Command {
	var format, output string
	var depth int
	var depthSet bool
	addr := ""
	token := ""
	ns := ""
	ins := false

	cmd := &cobra.Command{
		Use:   "auth-mounts",
		Short: "List authentication mounts (queries Vault API)",
		RunE: func(cmd *cobra.Command, args []string) error {
			maxDepth := -1
			if depthSet {
				maxDepth = depth
			}
			return commands.RunAuthMounts(
				optionalStr(cmd, "vault-addr", &addr),
				optionalStr(cmd, "vault-token", &token),
				optionalStr(cmd, "vault-namespace", &ns),
				ins,
				optionalStr(cmd, "output", &output),
				format,
				maxDepth,
			)
		},
	}
	cmd.Flags().StringVar(&addr, "vault-addr", "", "Vault address (default: $VAULT_ADDR)")
	cmd.Flags().StringVar(&token, "vault-token", "", "Vault token (default: $VAULT_TOKEN)")
	cmd.Flags().StringVar(&ns, "vault-namespace", "", "Vault namespace (default: $VAULT_NAMESPACE)")
	cmd.Flags().BoolVar(&ins, "insecure", false, "Skip TLS certificate verification")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	cmd.Flags().StringVar(&format, "format", "csv", "Output format: csv, json, or stdout")
	cmd.Flags().IntVar(&depth, "depth", 0, "Max depth to traverse within auth mounts (0 = mounts only, 1 = include roles/users)")
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		depthSet = cmd.Flags().Changed("depth")
		return nil
	}
	return cmd
}

// ═══════════════════════════════════════════════════════════════════
// Shell completion
// ═══════════════════════════════════════════════════════════════════

func generateCompletionCmd(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:       "generate-completion [bash|zsh|fish|powershell|elvish]",
		Short:     "Generate shell completion scripts",
		ValidArgs: []string{"bash", "zsh", "fish", "powershell", "elvish"},
		Args:      cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(os.Stdout)
			case "zsh":
				return root.GenZshCompletion(os.Stdout)
			case "fish":
				return root.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return root.GenPowerShellCompletion(os.Stdout)
			case "elvish":
				return root.GenFishCompletion(os.Stdout, false) // best effort
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	}
}
