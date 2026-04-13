// Package commands provides CLI command implementations.
package commands

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/audit"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/output"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/processor"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/utils"
)

// kvUsageData tracks statistics for a specific KV path.
type kvUsageData struct {
	entityIDs       map[string]bool // Set of unique entity IDs
	operationsCount int
	pathsAccessed   map[string]bool // Set of unique paths
}

// kvAnalyzerState aggregates KV usage data during processing.
type kvAnalyzerState struct {
	kvUsage     map[string]*kvUsageData
	kvPrefix    string
	parsedLines int
}

// normalizeKVPath removes KV v2 /data/ and /metadata/ components.
func normalizeKVPath(path string) string {
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")

	// Handle KV v2 paths (kv/data/... or kv/metadata/...)
	if len(parts) >= 3 && (parts[1] == "data" || parts[1] == "metadata") {
		mount := parts[0]
		remaining := parts[2:]

		if len(remaining) >= 3 {
			return mount + "/" + remaining[0] + "/" + remaining[1] + "/" + remaining[2] + "/"
		} else if len(remaining) == 2 {
			return mount + "/" + remaining[0] + "/" + remaining[1] + "/"
		} else if len(remaining) == 1 {
			return mount + "/" + remaining[0] + "/"
		} else {
			return mount + "/"
		}
	}

	// Handle KV v1 or simple paths
	if len(parts) >= 4 {
		return parts[0] + "/" + parts[1] + "/" + parts[2] + "/" + parts[3] + "/"
	} else if len(parts) == 3 {
		return parts[0] + "/" + parts[1] + "/" + parts[2] + "/"
	} else if len(parts) == 2 {
		return parts[0] + "/" + parts[1] + "/"
	} else if len(parts) == 1 {
		return parts[0] + "/"
	}
	return ""
}

// loadEntityAliasMapping loads entity-to-alias mappings from a CSV file.
func loadEntityAliasMapping(aliasExportCSV string) map[string][]string {
	entityAliases := make(map[string][]string)

	file, err := os.Open(aliasExportCSV)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Entity alias export not found: %s\n", aliasExportCSV)
		return entityAliases
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Failed to read entity alias file: %v\n", err)
		return entityAliases
	}

	for _, record := range records {
		if len(record) >= 2 {
			entityID := record[0]
			aliasName := record[1]
			entityAliases[entityID] = append(entityAliases[entityID], aliasName)
		}
	}

	return entityAliases
}

// RunKVAnalyze analyzes KV secrets engine usage from audit logs.
func RunKVAnalyze(logFiles []string, kvPrefix string, outputFlag, entityCSV *string) error {
	// Generate timestamped filename if no output specified or if it's a relative path
	var outputFile string
	if outputFlag != nil && *outputFlag != "" && filepath.IsAbs(*outputFlag) {
		// User provided absolute path - use as-is
		outputFile = *outputFlag
	} else {
		// Generate timestamped filename
		base := "kv_analysis"
		if outputFlag != nil && *outputFlag != "" {
			// Use provided name as base (without extension)
			base = strings.TrimSuffix(*outputFlag, filepath.Ext(*outputFlag))
		}
		outputFile = output.GenerateTimestampedFilename(base, ".csv")
	}

	// Initialize state factory
	newState := func() kvAnalyzerState {
		return kvAnalyzerState{
			kvUsage:  make(map[string]*kvUsageData),
			kvPrefix: kvPrefix,
		}
	}

	// Process entries
	processEntry := func(entry *audit.AuditEntry, state *kvAnalyzerState) {
		if entry.Request == nil {
			return
		}

		path := entry.Path()
		if path == "" {
			return
		}

		// Check prefix filter
		if kvPrefix != "" && !strings.HasPrefix(path, kvPrefix) {
			return
		}
		if kvPrefix == "" && !strings.Contains(path, "/data/") && !strings.Contains(path, "/metadata/") {
			return
		}

		// Filter for read/list operations
		op := entry.Operation()
		if op != "read" && op != "list" {
			return
		}

		entityID := entry.EntityID()
		if entityID == "" {
			return
		}

		state.parsedLines++

		// Normalize and track
		appPath := normalizeKVPath(path)
		if appPath == "" {
			return
		}

		if state.kvUsage[appPath] == nil {
			state.kvUsage[appPath] = &kvUsageData{
				entityIDs:     make(map[string]bool),
				pathsAccessed: make(map[string]bool),
			}
		}

		state.kvUsage[appPath].entityIDs[entityID] = true
		state.kvUsage[appPath].operationsCount++
		state.kvUsage[appPath].pathsAccessed[path] = true
	}

	// Merge function
	merge := func(a, b kvAnalyzerState) kvAnalyzerState {
		a.parsedLines += b.parsedLines
		for path, bData := range b.kvUsage {
			if a.kvUsage[path] == nil {
				a.kvUsage[path] = bData
			} else {
				// Merge sets
				for eid := range bData.entityIDs {
					a.kvUsage[path].entityIDs[eid] = true
				}
				a.kvUsage[path].operationsCount += bData.operationsCount
				for p := range bData.pathsAccessed {
					a.kvUsage[path].pathsAccessed[p] = true
				}
			}
		}
		return a
	}

	result, stats, err := processor.RunFiles(
		processor.DefaultConfig(),
		logFiles,
		newState,
		processEntry,
		merge,
	)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nTotal: Processed %s lines, parsed %s KV operations\n",
		utils.FormatNumber(stats.TotalLines),
		utils.FormatNumber(result.parsedLines))

	if len(result.kvUsage) == 0 {
		fmt.Fprintf(os.Stderr, "[ERROR] No KV operations found in audit logs.\n")
		os.Exit(1)
	}

	// Load entity aliases
	entityAliases := make(map[string][]string)
	if entityCSV != nil && *entityCSV != "" {
		entityAliases = loadEntityAliasMapping(*entityCSV)
	}

	// Ensure output directory exists
	if err := output.EnsureOutputDir(outputFile); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write CSV
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	writer.Write([]string{
		"kv_path",
		"unique_clients",
		"operations_count",
		"entity_ids",
		"alias_names",
		"sample_paths_accessed",
	}) //nolint:errcheck

	// Sort paths
	var paths []string
	for path := range result.kvUsage {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	// Write records
	for _, kvPath := range paths {
		data := result.kvUsage[kvPath]

		// Collect and sort entity IDs
		var entityIDs []string
		for eid := range data.entityIDs {
			entityIDs = append(entityIDs, eid)
		}
		sort.Strings(entityIDs)

		// Collect alias names
		var aliasNames []string
		for _, eid := range entityIDs {
			if aliases, ok := entityAliases[eid]; ok {
				aliasNames = append(aliasNames, aliases...)
			}
		}

		// Collect and sort sample paths (limit to 5)
		var samplePaths []string
		for path := range data.pathsAccessed {
			samplePaths = append(samplePaths, path)
		}
		sort.Strings(samplePaths)
		if len(samplePaths) > 5 {
			samplePaths = samplePaths[:5]
		}

		writer.Write([]string{
			kvPath,
			fmt.Sprintf("%d", len(data.entityIDs)),
			fmt.Sprintf("%d", data.operationsCount),
			strings.Join(entityIDs, ", "),
			strings.Join(aliasNames, ", "),
			strings.Join(samplePaths, ", "),
		}) //nolint:errcheck
	}

	// Write metadata file
	meta := output.FileMetadata{
		Command:     "kv-analysis",
		Subcommand:  "analyze",
		Description: fmt.Sprintf("KV secrets usage analysis (%d paths analyzed)", len(result.kvUsage)),
		InputFiles:  logFiles,
	}
	if err := output.WriteMetadata(outputFile, meta); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Failed to write metadata: %v\n", err)
	}

	fmt.Printf("Done. Output written to: %s\n", outputFile)
	fmt.Printf("Summary: %d KV paths analyzed\n", len(result.kvUsage))

	return nil
}

// RunKVCompare compares KV usage between two CSV exports.
func RunKVCompare(csv1, csv2 string) error {
	analyzeMount := func(csvFile string) (map[string]interface{}, error) {
		file, err := os.Open(csvFile)
		if err != nil {
			return nil, nil // File not found is OK
		}
		defer file.Close()

		reader := csv.NewReader(file)
		records, err := reader.ReadAll()
		if err != nil {
			return nil, fmt.Errorf("failed to read CSV: %w", err)
		}

		operations := 0
		paths := 0
		entities := make(map[string]bool)

		for _, record := range records {
			if len(record) < 4 {
				continue
			}

			// Get operations_count (column 2)
			if len(record) > 2 {
				ops, _ := strconv.Atoi(record[2]) // parse error → 0, safe default
				operations += ops
			}

			paths++

			// Get entity_ids (column 3)
			if len(record) > 3 {
				for _, eid := range strings.Split(record[3], ",") {
					if trimmed := strings.TrimSpace(eid); trimmed != "" {
						entities[trimmed] = true
					}
				}
			}
		}

		if paths == 0 {
			return nil, nil
		}

		return map[string]interface{}{
			"operations": operations,
			"paths":      paths,
			"entities":   len(entities),
		}, nil
	}

	csvFiles := []string{csv1, csv2}

	fmt.Println(strings.Repeat("=", 95))
	fmt.Printf("%-20s %-18s %-18s %-20s\n", "KV Mount", "Operations", "Unique Paths", "Unique Entities")
	fmt.Println(strings.Repeat("=", 95))

	var results []struct {
		name string
		data map[string]interface{}
	}
	totalOps := 0
	totalPaths := 0
	allEntities := make(map[string]bool)

	for _, csvFile := range csvFiles {
		mountName := strings.TrimSuffix(strings.TrimSuffix(csvFile, ".csv"), "/")
		if idx := strings.LastIndexAny(mountName, "/\\"); idx >= 0 {
			mountName = mountName[idx+1:]
		}

		data, err := analyzeMount(csvFile)
		if err != nil {
			return err
		}

		if data != nil {
			fmt.Printf("%-20s %-18d %-18d %-20d\n",
				mountName,
				data["operations"],
				data["paths"],
				data["entities"])

			totalOps += data["operations"].(int)
			totalPaths += data["paths"].(int)

			// Collect entities (placeholder)
			results = append(results, struct {
				name string
				data map[string]interface{}
			}{mountName, data})
		} else {
			fmt.Printf("%-20s %-18s\n", mountName, "(file not found)")
		}
	}

	fmt.Println(strings.Repeat("=", 95))
	fmt.Printf("%-20s %-18d %-18d %-20d\n", "TOTAL", totalOps, totalPaths, len(allEntities))
	fmt.Println(strings.Repeat("=", 95))

	// Show percentage breakdown
	if len(results) > 0 {
		fmt.Println("\nPercentage Breakdown by Operations:")
		fmt.Println(strings.Repeat("-", 50))

		// Sort by operations descending
		sort.Slice(results, func(i, j int) bool {
			return results[i].data["operations"].(int) > results[j].data["operations"].(int)
		})

		for _, r := range results {
			pct := 0.0
			if totalOps > 0 {
				pct = float64(r.data["operations"].(int)) / float64(totalOps) * 100.0
			}
			fmt.Printf("%-20s %6.2f%%\n", r.name, pct)
		}
	}

	return nil
}

// RunKVSummary summarizes KV usage from a CSV export.
func RunKVSummary(csvFile string) error {
	file, err := os.Open(csvFile)
	if err != nil {
		return fmt.Errorf("failed to open CSV file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read CSV: %w", err)
	}

	if len(records) == 0 {
		fmt.Printf("No data found in %s\n", csvFile)
		return nil
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("%70s\n", "KV Usage Summary Report")
	fmt.Printf("%70s\n", fmt.Sprintf("Source: %s", csvFile))
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()

	// Read all rows
	var rows [][]string
	for _, record := range records {
		rows = append(rows, record)
	}

	_ = len(rows) // totalPaths unused
	totalClients := 0
	totalOperations := 0

	// Find column indices from header (first row if it looks like headers)
	var uniqueClientsIdx, operationsIdx int
	if len(rows) > 0 {
		for i, col := range rows[0] {
			switch col {
			case "unique_clients":
				uniqueClientsIdx = i
			case "operations_count":
				operationsIdx = i
			}
		}
	}

	// Calculate totals (skip header if it exists)
	startIdx := 0
	if len(rows) > 0 && rows[0][0] == "kv_path" {
		startIdx = 1
	}

	for i := startIdx; i < len(rows); i++ {
		if uniqueClientsIdx < len(rows[i]) {
			n, _ := strconv.Atoi(rows[i][uniqueClientsIdx]) // parse error → 0, safe default
			totalClients += n
		}
		if operationsIdx < len(rows[i]) {
			n, _ := strconv.Atoi(rows[i][operationsIdx]) // parse error → 0, safe default
			totalOperations += n
		}
	}

	fmt.Println("Overview:")
	fmt.Printf("   • Total KV Paths: %d\n", len(rows)-1) // Subtract header
	fmt.Printf("   • Total Unique Clients: %s\n", utils.FormatNumber(totalClients))
	fmt.Printf("   • Total Operations: %s\n", utils.FormatNumber(totalOperations))
	fmt.Println()
	fmt.Println(strings.Repeat("-", 70))
	fmt.Println()

	// Print each row
	for i, row := range rows {
		if i == 0 {
			continue // Skip header
		}

		if len(row) > 0 {
			fmt.Printf("%d. KV Path: %s\n", i, row[0])

			if uniqueClientsIdx < len(row) {
				fmt.Printf("   Unique Clients: %s\n", row[uniqueClientsIdx])
			}

			if operationsIdx < len(row) {
				fmt.Printf("   Total Operations: %s\n", row[operationsIdx])
			}

			if len(row) > 3 {
				fmt.Printf("   Entity IDs: %s\n", row[3])
			}

			if len(row) > 4 && row[4] != "" {
				fmt.Printf("   Alias Names: %s\n", row[4])
			}

			if len(row) > 5 && row[5] != "" {
				display := row[5]
				if len(display) > 80 {
					display = display[:77] + "..."
				}
				fmt.Printf("   Sample Paths: %s\n", display)
			}
		}

		fmt.Println()
	}

	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("Report complete. Analyzed %d KV paths.\n\n", len(rows)-1)

	return nil
}
