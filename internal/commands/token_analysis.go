// Package commands provides the CLI command implementations.
package commands

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/audit"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/output"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/processor"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/utils"
)

// tokenOps tracks token operation statistics for a single entity.
type tokenOps struct {
	lookupSelf  int
	renewSelf   int
	revokeSelf  int
	create      int
	login       int
	other       int
	displayName *string
	username    *string
	firstSeen   *string
	lastSeen    *string
}

func (to *tokenOps) total() int {
	return to.lookupSelf + to.renewSelf + to.revokeSelf + to.create + to.login + to.other
}

func (to *tokenOps) updateTimestamps(timestamp string) {
	if to.firstSeen == nil {
		to.firstSeen = &timestamp
	}
	to.lastSeen = &timestamp
}

// accessorData tracks per-accessor token activity.
type accessorData struct {
	operations int
	firstSeen  string
	lastSeen   string
}

// entityAccessors tracks per-accessor token activity for an entity.
type entityAccessors struct {
	accessors   map[string]*accessorData
	displayName *string
}

// tokenAnalysisState is the combined state for token processing.
type tokenAnalysisState struct {
	tokenOps     map[string]*tokenOps
	accessorData map[string]*entityAccessors
}

func newTokenAnalysisState() tokenAnalysisState {
	return tokenAnalysisState{
		tokenOps:     make(map[string]*tokenOps),
		accessorData: make(map[string]*entityAccessors),
	}
}

// mergeTokenAnalysisState merges two states together.
func mergeTokenAnalysisState(a, b tokenAnalysisState) tokenAnalysisState {
	// Merge token_ops
	for entityID, otherOps := range b.tokenOps {
		ops, exists := a.tokenOps[entityID]
		if !exists {
			ops = &tokenOps{}
			a.tokenOps[entityID] = ops
		}

		ops.lookupSelf += otherOps.lookupSelf
		ops.renewSelf += otherOps.renewSelf
		ops.revokeSelf += otherOps.revokeSelf
		ops.create += otherOps.create
		ops.login += otherOps.login
		ops.other += otherOps.other

		// Update display name if not set
		if ops.displayName == nil {
			ops.displayName = otherOps.displayName
		}
		if ops.username == nil {
			ops.username = otherOps.username
		}

		// Update timestamps (earliest first_seen, latest last_seen)
		if ops.firstSeen == nil || (otherOps.firstSeen != nil && *ops.firstSeen > *otherOps.firstSeen) {
			ops.firstSeen = otherOps.firstSeen
		}
		if ops.lastSeen == nil || (otherOps.lastSeen != nil && *ops.lastSeen < *otherOps.lastSeen) {
			ops.lastSeen = otherOps.lastSeen
		}
	}

	// Merge accessor_data
	for entityID, otherEntity := range b.accessorData {
		entity, exists := a.accessorData[entityID]
		if !exists {
			entity = &entityAccessors{
				accessors: make(map[string]*accessorData),
			}
			a.accessorData[entityID] = entity
		}

		// Merge accessors
		for accessor, otherData := range otherEntity.accessors {
			data, exists := entity.accessors[accessor]
			if !exists {
				data = &accessorData{}
				entity.accessors[accessor] = data
			}

			data.operations += otherData.operations

			// Update timestamps
			if data.firstSeen == "" || data.firstSeen > otherData.firstSeen {
				data.firstSeen = otherData.firstSeen
			}
			if data.lastSeen == "" || data.lastSeen < otherData.lastSeen {
				data.lastSeen = otherData.lastSeen
			}
		}

		// Update display name if not set
		if entity.displayName == nil {
			entity.displayName = otherEntity.displayName
		}
	}

	return a
}

// RunTokenAnalysis processes token operations with optional abuse detection and automatic CSV export.
// Parameters:
//   - logFiles: slice of audit log file paths
//   - abuseThreshold: if set, shows entities exceeding this lookup count
//   - operationFilter: if set, only includes these operation types
//   - minOperations: minimum operations to include in export
func RunTokenAnalysis(logFiles []string, abuseThreshold *int, operationFilter []string, minOperations int) error {
	// Generate timestamped output filename
	outputFile := output.GenerateTimestampedFilename("token_analysis", ".csv")

	fmt.Fprintf(os.Stderr, "Token Analysis\n")
	fmt.Fprintf(os.Stderr, "   Files: %d\n", len(logFiles))
	if len(operationFilter) > 0 {
		fmt.Fprintf(os.Stderr, "   Filter: %s\n", strings.Join(operationFilter, ", "))
	}
	if abuseThreshold != nil {
		fmt.Fprintf(os.Stderr, "   Abuse threshold: %s\n", utils.FormatNumber(*abuseThreshold))
	}
	fmt.Fprintf(os.Stderr, "   Output: %s\n", outputFile)
	fmt.Fprintln(os.Stderr)

	// Build the filter map for faster lookup
	filterMap := make(map[string]bool)
	if len(operationFilter) > 0 {
		for _, f := range operationFilter {
			filterMap[f] = true
		}
	}

	// Process logs
	result, stats, err := processor.RunFiles(
		processor.DefaultConfig(),
		logFiles,
		newTokenAnalysisState,
		func(entry *audit.AuditEntry, state *tokenAnalysisState) {
			// Skip if no request or auth info
			if entry.Request == nil || entry.Auth == nil {
				return
			}

			entityID := entry.EntityID()
			if entityID == "" {
				return
			}

			// Determine operation type
			path := entry.Path()
			op := entry.Operation()

			var opType string
			switch path {
			case "auth/token/lookup-self":
				opType = "lookup"
			case "auth/token/renew-self":
				opType = "renew"
			case "auth/token/revoke-self":
				opType = "revoke"
			case "auth/token/create":
				opType = "create"
			default:
				if strings.HasPrefix(path, "auth/") && op == "update" {
					opType = "login"
				} else if strings.HasPrefix(path, "auth/token/") {
					opType = "other"
				} else {
					return // Not a token operation
				}
			}

			// Apply operation filter if specified
			if len(filterMap) > 0 {
				found := false
				for filter := range filterMap {
					if strings.Contains(opType, filter) {
						found = true
						break
					}
				}
				if !found {
					return
				}
			}

			// Update token operations summary
			ops, exists := state.tokenOps[entityID]
			if !exists {
				ops = &tokenOps{}
				state.tokenOps[entityID] = ops
			}

			switch opType {
			case "lookup":
				ops.lookupSelf++
			case "renew":
				ops.renewSelf++
			case "revoke":
				ops.revokeSelf++
			case "create":
				ops.create++
			case "login":
				ops.login++
			default:
				ops.other++
			}

			if ops.displayName == nil {
				dn := entry.DisplayName()
				if dn != "" {
					ops.displayName = &dn
				}
			}
			if ops.username == nil {
				username := entry.MetadataString("username")
				if username != "" {
					ops.username = &username
				}
			}
			ops.updateTimestamps(entry.Time)

			// Track accessor-level data for detailed analysis
			accessor := entry.Accessor()
			if accessor != "" {
				entity, exists := state.accessorData[entityID]
				if !exists {
					entity = &entityAccessors{
						accessors: make(map[string]*accessorData),
					}
					state.accessorData[entityID] = entity
				}

				if entity.displayName == nil {
					dn := entry.DisplayName()
					if dn != "" {
						entity.displayName = &dn
					}
				}

				data, exists := entity.accessors[accessor]
				if !exists {
					data = &accessorData{
						firstSeen: entry.Time,
						lastSeen:  entry.Time,
					}
					entity.accessors[accessor] = data
				}
				data.operations++
				data.lastSeen = entry.Time
			}
		},
		mergeTokenAnalysisState,
	)
	if err != nil {
		return err
	}

	stats.Report()

	fmt.Fprintf(os.Stderr, "\n Processed %s total lines\n", utils.FormatNumber(stats.TotalLines))
	fmt.Fprintf(os.Stderr, "  %s unique entities with token operations\n", utils.FormatNumber(len(result.tokenOps)))

	// Display based on mode
	if abuseThreshold != nil {
		displayAbuse(result.tokenOps, *abuseThreshold)
	} else {
		displaySummary(result.tokenOps, stats.TotalLines)
	}

	// Always export to timestamped file
	if err := exportTokenCSV(result.accessorData, outputFile, minOperations); err != nil {
		return err
	}

	// Write metadata file
	meta := output.FileMetadata{
		Command:     "token-analysis",
		Description: fmt.Sprintf("Token operations analysis (%d entities)", len(result.tokenOps)),
		InputFiles:  logFiles,
	}
	if err := output.WriteMetadata(outputFile, meta); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Failed to write metadata: %v\n", err)
	}

	fmt.Fprintf(os.Stderr, "\n Exported data to: %s\n", outputFile)

	return nil
}

// displaySummary shows operations summary
func displaySummary(opsMap map[string]*tokenOps, totalLines int) {
	type opEntry struct {
		id    string
		ops   *tokenOps
		total int
	}

	var opsVec []opEntry
	for id, ops := range opsMap {
		opsVec = append(opsVec, opEntry{id, ops, ops.total()})
	}

	sort.Slice(opsVec, func(i, j int) bool {
		return opsVec[i].total > opsVec[j].total
	})

	// Calculate totals
	var totalOps, totalLookup, totalRenew, totalRevoke, totalCreate, totalLogin, totalOther int
	for _, e := range opsVec {
		totalOps += e.ops.total()
		totalLookup += e.ops.lookupSelf
		totalRenew += e.ops.renewSelf
		totalRevoke += e.ops.revokeSelf
		totalCreate += e.ops.create
		totalLogin += e.ops.login
		totalOther += e.ops.other
	}

	fmt.Printf("Total: Processed %s lines\n\n", utils.FormatNumber(totalLines))
	fmt.Printf("%s\n", strings.Repeat("=", 150))
	fmt.Printf("%-30s %-25s %10s %10s %10s %10s %10s %10s %10s\n",
		"Display Name", "Username", "Total", "Lookup", "Renew", "Revoke", "Create", "Login", "Other")
	fmt.Printf("%s\n", strings.Repeat("=", 150))

	// Show top 50
	for i, e := range opsVec {
		if i >= 50 {
			break
		}

		display := ""
		if e.ops.displayName != nil {
			display = *e.ops.displayName
		}
		if len(display) > 30 {
			display = display[:30]
		}

		username := ""
		if e.ops.username != nil {
			username = *e.ops.username
		}
		if len(username) > 25 {
			username = username[:25]
		}

		fmt.Printf("%-30s %-25s %10s %10s %10s %10s %10s %10s %10s\n",
			display, username,
			utils.FormatNumber(e.ops.total()),
			utils.FormatNumber(e.ops.lookupSelf),
			utils.FormatNumber(e.ops.renewSelf),
			utils.FormatNumber(e.ops.revokeSelf),
			utils.FormatNumber(e.ops.create),
			utils.FormatNumber(e.ops.login),
			utils.FormatNumber(e.ops.other),
		)
	}

	fmt.Printf("%s\n", strings.Repeat("=", 150))
	fmt.Printf("TOTAL (top 50)                                                       %10s\n",
		utils.FormatNumber(totalOps))
	fmt.Printf("TOTAL ENTITIES                                                       %10s\n",
		utils.FormatNumber(len(opsMap)))
	fmt.Printf("%s\n", strings.Repeat("=", 150))
	fmt.Println()
	fmt.Println("Operation Type Breakdown:")
	fmt.Printf("%s\n", strings.Repeat("-", 60))

	if totalOps > 0 {
		fmt.Printf("Lookup (lookup-self):   %12s  (%5.1f%%)\n",
			utils.FormatNumber(totalLookup),
			float64(totalLookup)/float64(totalOps)*100.0)
		fmt.Printf("Renew (renew-self):     %12s  (%5.1f%%)\n",
			utils.FormatNumber(totalRenew),
			float64(totalRenew)/float64(totalOps)*100.0)
		fmt.Printf("Revoke (revoke-self):   %12s  (%5.1f%%)\n",
			utils.FormatNumber(totalRevoke),
			float64(totalRevoke)/float64(totalOps)*100.0)
		fmt.Printf("Create (child token):   %12s  (%5.1f%%)\n",
			utils.FormatNumber(totalCreate),
			float64(totalCreate)/float64(totalOps)*100.0)
		fmt.Printf("Login (auth token):     %12s  (%5.1f%%)\n",
			utils.FormatNumber(totalLogin),
			float64(totalLogin)/float64(totalOps)*100.0)
		fmt.Printf("Other:                  %12s  (%5.1f%%)\n",
			utils.FormatNumber(totalOther),
			float64(totalOther)/float64(totalOps)*100.0)
	}

	fmt.Printf("%s\n", strings.Repeat("-", 60))
	fmt.Printf("TOTAL:              %16s\n", utils.FormatNumber(totalOps))
}

// displayAbuse shows entities exceeding the lookup threshold
func displayAbuse(opsMap map[string]*tokenOps, threshold int) {
	type abuserEntry struct {
		id    string
		ops   *tokenOps
		count int
	}

	var abusers []abuserEntry
	for id, ops := range opsMap {
		if ops.lookupSelf >= threshold {
			abusers = append(abusers, abuserEntry{id, ops, ops.lookupSelf})
		}
	}

	sort.Slice(abusers, func(i, j int) bool {
		return abusers[i].count > abusers[j].count
	})

	if len(abusers) == 0 {
		fmt.Printf("\n No entities found exceeding threshold of %s lookup operations\n",
			utils.FormatNumber(threshold))
		return
	}

	fmt.Printf("\n Found %d entities exceeding %s lookup operations:\n\n",
		len(abusers), utils.FormatNumber(threshold))

	fmt.Printf("%-50s %12s %20s %12s\n",
		"Entity", "Lookups", "Time Span", "Rate/Hour")
	fmt.Printf("%s\n", strings.Repeat("=", 106))

	for _, e := range abusers {
		display := e.id
		if e.ops.displayName != nil {
			display = *e.ops.displayName
		} else if e.ops.username != nil {
			display = *e.ops.username
		}

		timeSpan := 0.0
		if e.ops.firstSeen != nil && e.ops.lastSeen != nil {
			if hours, err := utils.HoursBetween(*e.ops.firstSeen, *e.ops.lastSeen); err == nil {
				timeSpan = hours
			} else {
				fmt.Fprintf(os.Stderr, "Warning: Failed to calculate time span for entity %s: %v\n", e.id, err)
			}
		}

		rate := 0.0
		if timeSpan > 0.0 {
			rate = float64(e.ops.lookupSelf) / timeSpan
		}

		if len(display) > 50 {
			display = display[:47] + "..."
		}

		fmt.Printf("%-50s %12s %17.1fh %12.1f\n",
			display,
			utils.FormatNumber(e.ops.lookupSelf),
			timeSpan,
			rate)
	}
}

// exportTokenCSV exports per-accessor data to CSV
func exportTokenCSV(accessorMap map[string]*entityAccessors, output string, minOperations int) error {
	file, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	if err := writer.Write([]string{
		"entity_id", "display_name", "accessor", "operations", "first_seen", "last_seen", "duration_hours",
	}); err != nil {
		return err
	}

	type rowData struct {
		entityID    string
		displayName string
		accessor    string
		data        *accessorData
	}

	var rows []rowData
	for entityID, entity := range accessorMap {
		for accessor, data := range entity.accessors {
			if data.operations >= minOperations {
				display := entityID
				if entity.displayName != nil {
					display = *entity.displayName
				}
				rows = append(rows, rowData{entityID, display, accessor, data})
			}
		}
	}

	// Sort by operations descending
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].data.operations > rows[j].data.operations
	})

	// Write rows
	for _, row := range rows {
		duration := 0.0
		if hours, err := utils.HoursBetween(row.data.firstSeen, row.data.lastSeen); err == nil {
			duration = hours
		} else {
			fmt.Fprintf(os.Stderr, "Warning: Failed to calculate duration for accessor %s: %v\n",
				row.accessor, err)
		}

		if err := writer.Write([]string{
			row.entityID,
			row.displayName,
			row.accessor,
			fmt.Sprintf("%d", row.data.operations),
			row.data.firstSeen,
			row.data.lastSeen,
			fmt.Sprintf("%.2f", duration),
		}); err != nil {
			return err
		}
	}

	return nil
}
