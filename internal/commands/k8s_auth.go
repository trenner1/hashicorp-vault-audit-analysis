package commands

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/audit"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/processor"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/utils"
)

// K8sAuthState tracks Kubernetes authentication statistics.
type K8sAuthState struct {
	K8sLogins    int
	EntitiesSeen map[string]int
}

// RunK8sAuth processes audit logs to extract Kubernetes authentication patterns.
//
// Analyzes audit logs for Kubernetes auth method operations, tracking service account
// authentication counts and associated entities. Outputs statistics and optionally
// writes CSV with entity login counts.
func RunK8sAuth(logFiles []string, output *string) error {
	// Create processor with default config
	cfg := processor.DefaultConfig()

	// Process files and aggregate results
	result, stats, err := processor.RunFiles(
		cfg,
		logFiles,
		func() K8sAuthState {
			return K8sAuthState{
				EntitiesSeen: make(map[string]int),
			}
		},
		processK8sAuthEntry,
		mergeK8sAuthStates,
	)

	if err != nil {
		return fmt.Errorf("process files: %w", err)
	}

	// Print stats report
	stats.Report()

	// Extract results
	totalLines := stats.TotalLines
	k8sLogins := result.K8sLogins
	entitiesSeen := result.EntitiesSeen

	fmt.Fprintf(os.Stderr, "\nTotal: Processed %s lines, found %s K8s logins\n",
		utils.FormatNumber(totalLines),
		utils.FormatNumber(k8sLogins),
	)

	fmt.Println("\n" + repeatChar("=", 80))
	fmt.Println("KUBERNETES/OPENSHIFT AUTHENTICATION ANALYSIS")
	fmt.Println(repeatChar("=", 80))

	fmt.Println("\nSummary:")
	fmt.Printf("  Total lines processed: %s\n", utils.FormatNumber(totalLines))
	fmt.Printf("  Total K8s/OpenShift logins: %s\n", utils.FormatNumber(k8sLogins))
	fmt.Printf("  Unique entities: %s\n", utils.FormatNumber(len(entitiesSeen)))

	if k8sLogins > 0 && len(entitiesSeen) > 0 {
		ratio := float64(k8sLogins) / float64(len(entitiesSeen))
		fmt.Printf("  Login-to-Entity ratio: %.2f\n", ratio)

		fmt.Println("\nTop 20 Entities by Login Count:")
		fmt.Println(repeatChar("-", 80))

		// Sort entities by count
		type entityCount struct {
			ID    string
			Count int
		}
		var sorted []entityCount
		for id, count := range entitiesSeen {
			sorted = append(sorted, entityCount{id, count})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Count > sorted[j].Count
		})

		for i, ec := range sorted {
			if i >= 20 {
				break
			}
			fmt.Printf("%d. %s - %s logins\n", i+1, ec.ID, utils.FormatNumber(ec.Count))
		}
	}

	// Output CSV if requested
	if output != nil && *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()

		w := csv.NewWriter(f)
		w.Write([]string{"entity_id", "login_count"})

		for entity, count := range entitiesSeen {
			w.Write([]string{entity, fmt.Sprintf("%d", count)})
		}

		w.Flush()
		if err := w.Error(); err != nil {
			return fmt.Errorf("write csv: %w", err)
		}

		fmt.Printf("\nOutput written to: %s\n", *output)
	}

	fmt.Println("\n" + repeatChar("=", 80))

	return nil
}

// processK8sAuthEntry processes a single audit entry for K8s auth operations.
func processK8sAuthEntry(entry *audit.AuditEntry, state *K8sAuthState) {
	// Filter for successful Kubernetes auth operations (response type, no error)
	if entry.EntryType != "response" || entry.HasError() {
		return
	}

	path := entry.Path()
	if path == "" || !pathEndsWithLogin(path) {
		return
	}

	// Check if it's a K8s/OpenShift login by path
	isK8sByPath := pathContains(path, "kubernetes") || pathContains(path, "openshift")

	// Check if it's a K8s/OpenShift login by mount type
	mountType := entry.MountType()
	isK8sByMount := mountType == "kubernetes" || mountType == "openshift"

	if !isK8sByPath && !isK8sByMount {
		return
	}

	state.K8sLogins++

	// Track entity IDs
	if entityID := entry.EntityID(); entityID != "" {
		state.EntitiesSeen[entityID]++
	}
}

// mergeK8sAuthStates combines two K8sAuthState objects.
func mergeK8sAuthStates(a, b K8sAuthState) K8sAuthState {
	a.K8sLogins += b.K8sLogins

	for entityID, count := range b.EntitiesSeen {
		a.EntitiesSeen[entityID] += count
	}

	return a
}

// Helper functions

// pathEndsWithLogin checks if a path ends with /login.
func pathEndsWithLogin(path string) bool {
	const suffix = "/login"
	return len(path) >= len(suffix) &&
		path[len(path)-len(suffix):] == suffix
}


// repeatChar repeats a character n times.
func repeatChar(c string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += c
	}
	return result
}
