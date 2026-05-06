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

// AirflowPathData tracks statistics for airflow paths.
type AirflowPathData struct {
	Operations         int
	Entities           map[string]bool
	OperationsByEntity map[string]int
	Timestamps         []time.Time
}

// AirflowPollingState accumulates airflow polling statistics.
type AirflowPollingState struct {
	AirflowOperations int
	AirflowPaths      map[string]*AirflowPathData
}

// AirflowPollingRun processes audit logs and outputs airflow polling analysis.
func AirflowPollingRun(logFiles []string, outputFile *string) error {
	newState := func() AirflowPollingState {
		return AirflowPollingState{
			AirflowOperations: 0,
			AirflowPaths:      make(map[string]*AirflowPathData),
		}
	}

	process := func(entry *audit.AuditEntry, state *AirflowPollingState) {
		path := entry.Path()

		if path == "" {
			return
		}

		// Filter for Airflow-related paths (case-insensitive)
		if !containsLower(path, "airflow") {
			return
		}

		state.AirflowOperations++

		entityID := entry.EntityID()
		if entityID == "" {
			entityID = "no-entity"
		}

		// Track path statistics
		if _, ok := state.AirflowPaths[path]; !ok {
			state.AirflowPaths[path] = &AirflowPathData{
				Operations:         0,
				Entities:           make(map[string]bool),
				OperationsByEntity: make(map[string]int),
				Timestamps:         []time.Time{},
			}
		}

		pathData := state.AirflowPaths[path]
		pathData.Operations++
		pathData.Entities[entityID] = true
		pathData.OperationsByEntity[entityID]++

		// Track timestamp if available
		if ts, err := utils.ParseTimestamp(entry.Time); err == nil {
			pathData.Timestamps = append(pathData.Timestamps, ts)
		}
	}

	merge := func(a, b AirflowPollingState) AirflowPollingState {
		a.AirflowOperations += b.AirflowOperations
		for path, bData := range b.AirflowPaths {
			if aData, ok := a.AirflowPaths[path]; ok {
				aData.Operations += bData.Operations
				for entity := range bData.Entities {
					aData.Entities[entity] = true
				}
				for entity, count := range bData.OperationsByEntity {
					aData.OperationsByEntity[entity] += count
				}
				aData.Timestamps = append(aData.Timestamps, bData.Timestamps...)
			} else {
				a.AirflowPaths[path] = bData
			}
		}
		return a
	}

	result, stats, err := processor.RunFiles(processor.DefaultConfig(), logFiles, newState, process, merge)
	if err != nil {
		return fmt.Errorf("process files: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nTotal: Processed %s lines, found %s Airflow operations\n",
		utils.FormatNumber(stats.TotalLines), utils.FormatNumber(result.AirflowOperations))

	fmt.Println("\nSummary:")
	fmt.Printf("  Total lines processed: %s\n", utils.FormatNumber(stats.TotalLines))
	fmt.Printf("  Airflow operations: %s\n", utils.FormatNumber(result.AirflowOperations))
	fmt.Printf("  Unique paths: %s\n", utils.FormatNumber(len(result.AirflowPaths)))

	totalEntities := make(map[string]bool)
	for _, data := range result.AirflowPaths {
		for entity := range data.Entities {
			totalEntities[entity] = true
		}
	}
	fmt.Printf("  Entities involved: %s\n", utils.FormatNumber(len(totalEntities)))

	// 1. Top Airflow paths by operations
	fmt.Println("\n1. TOP AIRFLOW PATHS BY OPERATIONS")
	fmt.Println(stringRepeat("-", 100))
	fmt.Printf("%-80s %-12s %-10s\n", "Path", "Operations", "Entities")
	fmt.Println(stringRepeat("-", 100))

	type pathPair struct {
		path string
		data *AirflowPathData
	}
	var sortedPaths []pathPair
	for path, data := range result.AirflowPaths {
		sortedPaths = append(sortedPaths, pathPair{path, data})
	}
	sort.Slice(sortedPaths, func(i, j int) bool {
		return sortedPaths[i].data.Operations > sortedPaths[j].data.Operations
	})

	for i, p := range sortedPaths {
		if i >= 30 {
			break
		}
		displayPath := p.path
		if len(displayPath) > 78 {
			displayPath = displayPath[:75]
		}
		fmt.Printf("%-80s %-12s %-10s\n", displayPath,
			utils.FormatNumber(p.data.Operations), utils.FormatNumber(len(p.data.Entities)))
	}

	// 2. Entity access patterns
	fmt.Println("\n2. ENTITIES ACCESSING AIRFLOW SECRETS")
	fmt.Println(stringRepeat("-", 100))
	fmt.Printf("%-50s %-12s %-15s\n", "Entity ID", "Operations", "Unique Paths")
	fmt.Println(stringRepeat("-", 100))

	entityPatterns := make(map[string]struct {
		ops   int
		paths map[string]bool
	})
	for path, data := range result.AirflowPaths {
		for entity := range data.Entities {
			ep := entityPatterns[entity]
			if ep.paths == nil {
				ep.paths = make(map[string]bool)
			}
			ep.ops += data.OperationsByEntity[entity]
			ep.paths[path] = true
			entityPatterns[entity] = ep
		}
	}

	type entityPair struct {
		id    string
		ops   int
		paths int
	}
	var sortedEntities []entityPair
	for entity, ep := range entityPatterns {
		sortedEntities = append(sortedEntities, entityPair{entity, ep.ops, len(ep.paths)})
	}
	sort.Slice(sortedEntities, func(i, j int) bool {
		return sortedEntities[i].ops > sortedEntities[j].ops
	})

	for i, e := range sortedEntities {
		if i >= 20 {
			break
		}
		displayEntity := e.id
		if len(displayEntity) > 48 {
			displayEntity = displayEntity[:45]
		}
		fmt.Printf("%-50s %-12s %-15s\n", displayEntity,
			utils.FormatNumber(e.ops), utils.FormatNumber(e.paths))
	}

	// 3. Polling pattern analysis with BURST RATES
	fmt.Println("\n3. BURST RATE ANALYSIS (Paths with Time Data)")
	fmt.Println("   NOTE: Rates calculated over actual time span - high rates indicate bursty access")
	fmt.Println(stringRepeat("-", 100))
	fmt.Printf("%-60s %-12s %-12s %-15s\n", "Path", "Operations", "Time Span", "Avg Interval")
	fmt.Println(stringRepeat("-", 100))

	type pollingPattern struct {
		path            string
		operations      int
		timeSpanHours   float64
		opsPerHour      float64
		avgIntervalSecs float64
	}

	var pollingPatterns []pollingPattern

	for path, data := range result.AirflowPaths {
		if len(data.Timestamps) < 2 {
			continue
		}

		timestamps := make([]time.Time, len(data.Timestamps))
		copy(timestamps, data.Timestamps)
		sort.Slice(timestamps, func(i, j int) bool {
			return timestamps[i].Before(timestamps[j])
		})

		timeSpanSecs := float64(timestamps[len(timestamps)-1].Sub(timestamps[0]).Seconds())
		timeSpanHours := timeSpanSecs / 3600.0

		if timeSpanHours > 0.0 {
			opsPerHour := float64(data.Operations) / timeSpanHours
			avgIntervalSecs := timeSpanSecs / float64(data.Operations)

			pollingPatterns = append(pollingPatterns, pollingPattern{
				path:            path,
				operations:      data.Operations,
				timeSpanHours:   timeSpanHours,
				opsPerHour:      opsPerHour,
				avgIntervalSecs: avgIntervalSecs,
			})
		}
	}

	// Sort by operations per hour
	sort.Slice(pollingPatterns, func(i, j int) bool {
		return pollingPatterns[i].opsPerHour > pollingPatterns[j].opsPerHour
	})

	for i, p := range pollingPatterns {
		if i >= 25 {
			break
		}
		displayPath := p.path
		if len(displayPath) > 58 {
			displayPath = displayPath[:55]
		}
		timeSpan := fmt.Sprintf("%.1fh", p.timeSpanHours)
		interval := fmt.Sprintf("%.1fs", p.avgIntervalSecs)

		fmt.Printf("%-60s %-12s %-12s %-15s\n", displayPath,
			utils.FormatNumber(p.operations), timeSpan, interval)
	}

	// 4. Entity-path combinations
	fmt.Println("\n4. ENTITY-PATH POLLING BEHAVIOR (Top 30)")
	fmt.Println(stringRepeat("-", 100))
	fmt.Printf("%-40s %-45s %-15s\n", "Entity", "Path", "Operations")
	fmt.Println(stringRepeat("-", 100))

	type entityPathCombo struct {
		entity     string
		path       string
		operations int
	}

	var combos []entityPathCombo
	for path, data := range result.AirflowPaths {
		for entity, ops := range data.OperationsByEntity {
			combos = append(combos, entityPathCombo{entity, path, ops})
		}
	}

	sort.Slice(combos, func(i, j int) bool {
		return combos[i].operations > combos[j].operations
	})

	for i, c := range combos {
		if i >= 30 {
			break
		}
		displayEntity := c.entity
		if len(displayEntity) > 38 {
			displayEntity = displayEntity[:35]
		}
		displayPath := c.path
		if len(displayPath) > 43 {
			displayPath = displayPath[:40]
		}

		fmt.Printf("%-40s %-45s %-15s\n", displayEntity, displayPath,
			utils.FormatNumber(c.operations))
	}

	// 5. Recommendations
	fmt.Println("\n5. OPTIMIZATION RECOMMENDATIONS")
	fmt.Println(stringRepeat("-", 100))

	highFreqPaths := make([]pollingPattern, 0)
	for _, p := range pollingPatterns {
		if p.opsPerHour > 100.0 {
			highFreqPaths = append(highFreqPaths, p)
		}
	}

	totalHighFreqOps := 0
	for _, p := range highFreqPaths {
		totalHighFreqOps += p.operations
	}

	fmt.Printf("Total Airflow operations: %s\n", utils.FormatNumber(result.AirflowOperations))
	fmt.Printf("Paths with >100 ops/hour burst rate: %s\n", utils.FormatNumber(len(highFreqPaths)))
	fmt.Printf("Operations from high-frequency paths: %s (%.1f%%)\n", utils.FormatNumber(totalHighFreqOps),
		float64(totalHighFreqOps)/float64(result.AirflowOperations)*100.0)
	fmt.Println()
	fmt.Println("Recommended Actions:")
	fmt.Println()
	fmt.Println("1. IMPLEMENT AIRFLOW CONNECTION CACHING")
	fmt.Println("   - Configure Airflow to cache connection objects")
	fmt.Println("   - Expected reduction: 80-90% of reads")
	fmt.Printf("   - Potential savings: %s operations/day\n",
		utils.FormatNumber(int(float64(result.AirflowOperations)*0.85)))
	fmt.Println()
	fmt.Println("2. DEPLOY VAULT AGENT WITH AIRFLOW")
	fmt.Println("   - Run Vault agent as sidecar/daemon")
	fmt.Println("   - Configure template rendering for connections")
	fmt.Println("   - Expected reduction: 95% of reads")
	fmt.Printf("   - Potential savings: %s operations/day\n",
		utils.FormatNumber(int(float64(result.AirflowOperations)*0.95)))
	fmt.Println()
	fmt.Println("3. USE AIRFLOW SECRETS BACKEND EFFICIENTLY")
	fmt.Println("   - Review connection lookup patterns in DAGs")
	fmt.Println("   - Implement connection object reuse within tasks")
	fmt.Println("   - Cache connections at DAG level where appropriate")
	fmt.Println()

	if len(pollingPatterns) > 0 {
		fmt.Println("4. PRIORITY PATHS FOR IMMEDIATE OPTIMIZATION (by burst rate):")
		for i, p := range pollingPatterns {
			if i >= 10 {
				break
			}
			pathName := p.path
			slashIdx := -1
			for j := len(pathName) - 1; j >= 0; j-- {
				if pathName[j] == '/' {
					slashIdx = j
					break
				}
			}
			if slashIdx >= 0 && slashIdx < len(pathName)-1 {
				pathName = pathName[slashIdx+1:]
			}

			fmt.Printf("   %d. %s: %s operations (%.0f/hour burst rate)\n", i+1, pathName,
				utils.FormatNumber(p.operations), p.opsPerHour)
		}
	}

	fmt.Println("\n" + stringRepeat("=", 100))

	if outputFile != nil && *outputFile != "" {
		csvFile, err := os.Create(*outputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer csvFile.Close()

		fmt.Fprintf(csvFile, "entity_id,path,operation_count\n")
		for path, data := range result.AirflowPaths {
			for entity, count := range data.OperationsByEntity {
				fmt.Fprintf(csvFile, "%s,%s,%d\n", entity, path, count)
			}
		}
		fmt.Printf("\nOutput written to: %s\n", *outputFile)
	}

	return nil
}
