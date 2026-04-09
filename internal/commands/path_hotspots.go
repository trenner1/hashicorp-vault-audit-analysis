// Package commands provides CLI command implementations for audit analysis.
package commands

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/audit"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/processor"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/utils"
)

// PathHotspotStats holds statistics for a single path.
type PathHotspotStats struct {
	Operations       int
	Entities         map[string]bool
	OperationsByType map[string]int
	Timestamps       []time.Time
	EntityOperations map[string]int
}

// PathHotspotsState accumulates path hotspot statistics.
type PathHotspotsState struct {
	PathStats       map[string]*PathHotspotStats
	TotalOperations int
}

// PathHotspotsRun processes audit logs and outputs path hotspot analysis.
func PathHotspotsRun(logFiles []string, top int) error {
	newState := func() PathHotspotsState {
		return PathHotspotsState{
			PathStats:       make(map[string]*PathHotspotStats),
			TotalOperations: 0,
		}
	}

	process := func(entry *audit.AuditEntry, state *PathHotspotsState) {
		path := entry.Path()
		operation := entry.Operation()

		if path == "" || operation == "" {
			return
		}

		state.TotalOperations++

		entityID := entry.EntityID()
		if entityID == "" {
			entityID = "no-entity"
		}

		// Parse timestamp
		var ts time.Time
		if parsedTs, err := utils.ParseTimestamp(entry.Time); err == nil {
			ts = parsedTs
		}

		// Track path statistics
		if _, ok := state.PathStats[path]; !ok {
			state.PathStats[path] = &PathHotspotStats{
				Operations:       0,
				Entities:         make(map[string]bool),
				OperationsByType: make(map[string]int),
				Timestamps:       []time.Time{},
				EntityOperations: make(map[string]int),
			}
		}
		pathStats := state.PathStats[path]
		pathStats.Operations++
		pathStats.Entities[entityID] = true
		pathStats.OperationsByType[operation]++
		pathStats.EntityOperations[entityID]++
		if !ts.IsZero() {
			pathStats.Timestamps = append(pathStats.Timestamps, ts)
		}
	}

	merge := func(a, b PathHotspotsState) PathHotspotsState {
		a.TotalOperations += b.TotalOperations
		for path, bStats := range b.PathStats {
			if aStats, ok := a.PathStats[path]; ok {
				aStats.Operations += bStats.Operations
				for entity := range bStats.Entities {
					aStats.Entities[entity] = true
				}
				for op, count := range bStats.OperationsByType {
					aStats.OperationsByType[op] += count
				}
				for entity, count := range bStats.EntityOperations {
					aStats.EntityOperations[entity] += count
				}
				aStats.Timestamps = append(aStats.Timestamps, bStats.Timestamps...)
			} else {
				a.PathStats[path] = bStats
			}
		}
		return a
	}

	result, stats, err := processor.RunFiles(processor.DefaultConfig(), logFiles, newState, process, merge)
	if err != nil {
		return fmt.Errorf("process files: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nTotal: Processed %s lines, %s operations\n",
		utils.FormatNumber(stats.TotalLines), utils.FormatNumber(result.TotalOperations))

	// Sort paths by operation count
	type pathPair struct {
		path  string
		stats *PathHotspotStats
	}
	var sortedPaths []pathPair
	for path, stats := range result.PathStats {
		sortedPaths = append(sortedPaths, pathPair{path, stats})
	}
	sort.Slice(sortedPaths, func(i, j int) bool {
		return sortedPaths[i].stats.Operations > sortedPaths[j].stats.Operations
	})

	// 1. Summary table
	fmt.Println("\n" + stringRepeat("=", 120))
	fmt.Printf("TOP %d PATH HOT SPOTS ANALYSIS\n", top)
	fmt.Println(stringRepeat("=", 120))

	fmt.Printf("\n%-5s %-60s %-12s %-10s %-10s %-10s\n", "#", "Path", "Ops", "Entities", "Top Op", "%")
	fmt.Println(stringRepeat("-", 120))

	for i, p := range sortedPaths {
		if i >= top {
			break
		}
		ops := p.stats.Operations
		entityCount := len(p.stats.Entities)
		percentage := float64(ops) / float64(result.TotalOperations) * 100.0

		topOp := "N/A"
		maxCount := 0
		for op, count := range p.stats.OperationsByType {
			if count > maxCount {
				maxCount = count
				topOp = op
			}
		}

		displayPath := p.path
		if len(displayPath) > 58 {
			displayPath = displayPath[:55] + "..."
		}

		fmt.Printf("%-5d %-60s %-12s %-10s %-10s %-10.2f%%\n", i+1, displayPath,
			utils.FormatNumber(ops), utils.FormatNumber(entityCount), topOp, percentage)
	}

	// 2. Detailed analysis for top paths
	maxDetail := top
	if top > 20 {
		maxDetail = 20
	}
	fmt.Printf("\n\nDETAILED ANALYSIS OF TOP %d PATHS\n", maxDetail)
	fmt.Println(stringRepeat("=", 120))

	for i, p := range sortedPaths {
		if i >= maxDetail {
			break
		}

		fmt.Printf("\n%d. PATH: %s\n", i+1, p.path)
		fmt.Println(stringRepeat("-", 120))

		ops := p.stats.Operations
		entityCount := len(p.stats.Entities)
		percentage := float64(ops) / float64(result.TotalOperations) * 100.0

		fmt.Printf("   Total Operations: %s (%.2f%% of all traffic)\n",
			utils.FormatNumber(ops), percentage)
		fmt.Printf("   Unique Entities: %s\n", utils.FormatNumber(entityCount))

		// Calculate time span and rate
		if len(p.stats.Timestamps) >= 2 {
			timestamps := make([]time.Time, len(p.stats.Timestamps))
			copy(timestamps, p.stats.Timestamps)
			sort.Slice(timestamps, func(i, j int) bool {
				return timestamps[i].Before(timestamps[j])
			})
			timeSpan := timestamps[len(timestamps)-1].Sub(timestamps[0]).Hours()
			if timeSpan > 0.0 {
				opsPerHour := float64(ops) / timeSpan
				fmt.Printf("   Access Rate: %.1f operations/hour (%.2f/minute)\n",
					opsPerHour, opsPerHour/60.0)
			}
		}

		// Operation breakdown
		fmt.Println("   Operations by type:")
		type opPair struct {
			name  string
			count int
		}
		var opsList []opPair
		for op, count := range p.stats.OperationsByType {
			opsList = append(opsList, opPair{op, count})
		}
		sort.Slice(opsList, func(i, j int) bool {
			return opsList[i].count > opsList[j].count
		})
		for j, op := range opsList {
			if j >= 5 {
				break
			}
			opPct := float64(op.count) / float64(ops) * 100.0
			fmt.Printf("      - %s: %s (%.1f%%)\n", op.name, utils.FormatNumber(op.count), opPct)
		}

		// Top entities
		type entityPair struct {
			id  string
			ops int
		}
		var entityList []entityPair
		for id, ops := range p.stats.EntityOperations {
			entityList = append(entityList, entityPair{id, ops})
		}
		sort.Slice(entityList, func(i, j int) bool {
			return entityList[i].ops > entityList[j].ops
		})

		if len(entityList) > 0 {
			maxEntities := len(entityList)
			if maxEntities > 5 {
				maxEntities = 5
			}
			fmt.Printf("   Top %d entities:\n", maxEntities)
			for j, e := range entityList {
				if j >= 5 {
					break
				}
				entityPct := float64(e.ops) / float64(ops) * 100.0
				entityDisplay := e.id
				if len(entityDisplay) > 40 {
					entityDisplay = entityDisplay[:37] + "..."
				}
				fmt.Printf("      - %s: %s ops (%.1f%%)\n", entityDisplay,
					utils.FormatNumber(e.ops), entityPct)
			}
		}

		// Categorize and provide recommendations
		fmt.Print("   Category: ")
		var recommendations []string

		if contains(p.path, "token/lookup") {
			fmt.Println("TOKEN LOOKUP")
			recommendations = append(recommendations,
				"Implement client-side token TTL tracking to eliminate polling")
			recommendations = append(recommendations,
				fmt.Sprintf("Potential reduction: 80-90%% (%s operations)",
					utils.FormatNumber(int(float64(ops)*0.85))))
		} else if containsLower(p.path, "airflow") {
			fmt.Println("AIRFLOW SECRET")
			recommendations = append(recommendations,
				"Deploy Vault agent with template rendering for Airflow")
			recommendations = append(recommendations,
				"Configure connection caching in Airflow")
			recommendations = append(recommendations,
				fmt.Sprintf("Potential reduction: 95%% (%s operations)",
					utils.FormatNumber(int(float64(ops)*0.95))))
		} else if contains(p.path, "approle/login") {
			fmt.Println("APPROLE AUTHENTICATION")
			if entityCount == 1 {
				recommendations = append(recommendations,
					fmt.Sprintf("⚠️  CRITICAL: Single entity making all %s login requests",
						utils.FormatNumber(ops)))
				recommendations = append(recommendations,
					"Review token TTL configuration - may be too short")
				recommendations = append(recommendations,
					"Consider SecretID caching if appropriate")
			}
		} else if containsLower(p.path, "openshift") || containsLower(p.path, "kubernetes") {
			fmt.Println("KUBERNETES/OPENSHIFT AUTH")
			recommendations = append(recommendations,
				"Review pod authentication token TTLs")
			recommendations = append(recommendations,
				"Consider increasing default token lifetime")
			recommendations = append(recommendations,
				"Implement token renewal strategy in applications")
		} else if containsLower(p.path, "github") && contains(p.path, "login") {
			fmt.Println("GITHUB AUTHENTICATION")
			recommendations = append(recommendations,
				"Review GitHub auth token TTLs")
			if entityCount == 1 {
				recommendations = append(recommendations,
					fmt.Sprintf("⚠️  Single entity (%d) - investigate why", entityCount))
			}
		} else if contains(p.path, "data/") || contains(p.path, "metadata/") {
			fmt.Println("KV SECRET ENGINE")
			if entityCount <= 3 && ops > 10000 {
				recommendations = append(recommendations,
					fmt.Sprintf("⚠️  HIGH-FREQUENCY ACCESS: %s operations from only %d entities",
						utils.FormatNumber(ops), entityCount))
				recommendations = append(recommendations,
					"Implement caching layer or Vault agent")
				recommendations = append(recommendations,
					"Review if secret needs this frequency of access")
			} else {
				recommendations = append(recommendations,
					"Consider Vault agent for high-frequency consumers")
			}
		} else {
			fmt.Println("OTHER")
			if ops > 5000 {
				recommendations = append(recommendations,
					fmt.Sprintf("High-volume path (%s operations) - review necessity",
						utils.FormatNumber(ops)))
			}
		}

		// Entity concentration check
		if len(entityList) > 0 {
			topEntityOps := entityList[0].ops
			topEntityPct := float64(topEntityOps) / float64(ops) * 100.0
			hasCritical := false
			for _, rec := range recommendations {
				if contains(rec, "CRITICAL") {
					hasCritical = true
					break
				}
			}
			if topEntityPct > 50.0 && !hasCritical {
				recommendations = append(recommendations,
					fmt.Sprintf("⚠️  Entity concentration: Single entity responsible for %.1f%% of access",
						topEntityPct))
			}
		}

		if len(recommendations) > 0 {
			fmt.Println("   Recommendations:")
			for _, rec := range recommendations {
				fmt.Printf("      • %s\n", rec)
			}
		}
	}

	// 3. Summary by category
	fmt.Println("\n\nSUMMARY BY PATH CATEGORY")
	fmt.Println(stringRepeat("=", 120))

	categories := map[string]int{
		"Token Operations": 0,
		"KV Secret Access": 0,
		"Authentication":   0,
		"Airflow Secrets":  0,
		"System/Admin":     0,
		"Other":            0,
	}

	for path, stats := range result.PathStats {
		ops := stats.Operations
		if contains(path, "token/") {
			categories["Token Operations"] += ops
		} else if contains(path, "/data/") || contains(path, "/metadata/") {
			if containsLower(path, "airflow") {
				categories["Airflow Secrets"] += ops
			} else {
				categories["KV Secret Access"] += ops
			}
		} else if contains(path, "/login") || contains(path, "/auth/") {
			categories["Authentication"] += ops
		} else if contains(path, "sys/") {
			categories["System/Admin"] += ops
		} else {
			categories["Other"] += ops
		}
	}

	fmt.Printf("%-30s %-15s %-15s\n", "Category", "Operations", "% of Total")
	fmt.Println(stringRepeat("-", 120))

	type catPair struct {
		name string
		ops  int
	}
	var catList []catPair
	for name, ops := range categories {
		catList = append(catList, catPair{name, ops})
	}
	sort.Slice(catList, func(i, j int) bool {
		return catList[i].ops > catList[j].ops
	})

	for _, cat := range catList {
		percentage := float64(cat.ops) / float64(result.TotalOperations) * 100.0
		fmt.Printf("%-30s %-15s %-15.2f%%\n", cat.name, utils.FormatNumber(cat.ops), percentage)
	}

	fmt.Println("\n" + stringRepeat("=", 120))

	// 4. Overall recommendations
	fmt.Println("\nTOP OPTIMIZATION OPPORTUNITIES (by impact)")
	fmt.Println(stringRepeat("=", 120))

	type opportunity struct {
		name               string
		currentOps         int
		potentialReduction int
		effort             string
		priority           int
	}

	var opportunities []opportunity

	// Calculate token lookup impact
	tokenLookupOps := 0
	for path, stats := range result.PathStats {
		if contains(path, "token/lookup") {
			tokenLookupOps += stats.Operations
		}
	}

	if tokenLookupOps > 10000 {
		opportunities = append(opportunities, opportunity{
			name:               "Eliminate Token Lookup Polling",
			currentOps:         tokenLookupOps,
			potentialReduction: int(float64(tokenLookupOps) * 0.85),
			effort:             "Medium",
			priority:           1,
		})
	}

	// Calculate Airflow impact
	airflowOps := 0
	for path, stats := range result.PathStats {
		if containsLower(path, "airflow") {
			airflowOps += stats.Operations
		}
	}

	if airflowOps > 10000 {
		opportunities = append(opportunities, opportunity{
			name:               "Deploy Vault Agent for Airflow",
			currentOps:         airflowOps,
			potentialReduction: int(float64(airflowOps) * 0.95),
			effort:             "Medium",
			priority:           2,
		})
	}

	// Calculate high-frequency path caching
	highFreqOps := 0
	highFreqCount := 0
	for _, stats := range result.PathStats {
		if stats.Operations > 5000 && stats.Operations < 100000 {
			highFreqOps += stats.Operations
			highFreqCount++
		}
	}

	if highFreqOps > 10000 {
		opportunities = append(opportunities, opportunity{
			name:               fmt.Sprintf("Cache High-Frequency Paths (%d paths)", highFreqCount),
			currentOps:         highFreqOps,
			potentialReduction: int(float64(highFreqOps) * 0.70),
			effort:             "Low-Medium",
			priority:           3,
		})
	}

	sort.Slice(opportunities, func(i, j int) bool {
		return opportunities[i].priority < opportunities[j].priority
	})

	fmt.Printf("\n%-10s %-50s %-15s %-15s %-15s\n", "Priority", "Opportunity", "Current Ops", "Savings", "Effort")
	fmt.Println(stringRepeat("-", 120))

	totalCurrentOps := 0
	totalSavings := 0

	for _, opp := range opportunities {
		fmt.Printf("%-10d %-50s %-15s %-15s %-15s\n", opp.priority, opp.name,
			utils.FormatNumber(opp.currentOps), utils.FormatNumber(opp.potentialReduction), opp.effort)
		totalCurrentOps += opp.currentOps
		totalSavings += opp.potentialReduction
	}

	fmt.Println(stringRepeat("-", 120))
	fmt.Printf("%-10s %-50s %-15s %-15s\n", "TOTAL POTENTIAL SAVINGS", "", "",
		utils.FormatNumber(totalSavings))

	projectedReduction := float64(totalSavings) / float64(result.TotalOperations) * 100.0
	fmt.Printf("\nProjected reduction: %.1f%% of all Vault operations\n", projectedReduction)
	fmt.Println(stringRepeat("=", 120))

	return nil
}

// contains checks if string contains substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// containsLower checks if string contains substring (case-insensitive)
func containsLower(s, substr string) bool {
	s = toLower(s)
	substr = toLower(substr)
	return contains(s, substr)
}

// toLower converts string to lowercase
func toLower(s string) string {
	result := ""
	for _, ch := range s {
		if ch >= 'A' && ch <= 'Z' {
			result += string(ch + 32)
		} else {
			result += string(ch)
		}
	}
	return result
}
