// Package commands provides subcommands for vault audit analysis.
package commands

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/audit"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/processor"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/utils"
)

// Operation represents a single operation in an entity's timeline.
type Operation struct {
	timestamp time.Time
	path      string
	op        string
}

// TimelineState tracks operations for a specific entity.
type TimelineState struct {
	operations      []Operation
	operationsByType map[string]int
	pathsAccessed    map[string]int
	operationsByHour map[string]map[string]int
	hourOfDayStats   map[int]int
	windowCounts     map[time.Time]int
	entityOpCount    int
}

// RunEntityTimeline shows chronological activity for a specific entity.
func RunEntityTimeline(logFiles []string, entityID string, displayName *string) error {
	fmt.Printf("Analyzing timeline for entity: %s\n", entityID)
	if displayName != nil && *displayName != "" {
		fmt.Printf("Display name: %s\n", *displayName)
	}
	fmt.Printf("\n")

	result, _, err := processor.RunFiles(
		processor.DefaultConfig(),
		logFiles,
		func() TimelineState {
			return TimelineState{
				operations:       make([]Operation, 0),
				operationsByType: make(map[string]int),
				pathsAccessed:    make(map[string]int),
				operationsByHour: make(map[string]map[string]int),
				hourOfDayStats:   make(map[int]int),
				windowCounts:     make(map[time.Time]int),
			}
		},
		func(entry *audit.AuditEntry, s *TimelineState) {
			// Check if this is our entity
			if entry.EntityID() != entityID {
				return
			}

			s.entityOpCount++

			path := entry.Path()
			op := entry.Operation()

			ts := parseTime(entry.Time)

			// Track by hour
			hourKey := ts.Format("2006-01-02 15:00")
			if _, ok := s.operationsByHour[hourKey]; !ok {
				s.operationsByHour[hourKey] = make(map[string]int)
			}
			s.operationsByHour[hourKey]["total"]++
			s.operationsByHour[hourKey][op]++

			// Store operation for timeline
			s.operations = append(s.operations, Operation{
				timestamp: ts,
				path:      path,
				op:        op,
			})

			// Track operation types
			s.operationsByType[op]++

			// Track paths
			s.pathsAccessed[path]++

			// Track by hour of day
			s.hourOfDayStats[int(ts.Hour())]++

			// Track 5-minute windows
			minute := (ts.Minute() / 5) * 5
			windowStart := ts.Truncate(time.Hour)
			windowStart = windowStart.Add(time.Duration(minute) * time.Minute)
			s.windowCounts[windowStart]++
		},
		func(a, b TimelineState) TimelineState {
			// Merge states
			a.operations = append(a.operations, b.operations...)
			for op, count := range b.operationsByType {
				a.operationsByType[op] += count
			}
			for path, count := range b.pathsAccessed {
				a.pathsAccessed[path] += count
			}
			for hour, ops := range b.operationsByHour {
				if _, ok := a.operationsByHour[hour]; !ok {
					a.operationsByHour[hour] = make(map[string]int)
				}
				for op, count := range ops {
					a.operationsByHour[hour][op] += count
				}
			}
			for hour, count := range b.hourOfDayStats {
				a.hourOfDayStats[hour] += count
			}
			for window, count := range b.windowCounts {
				a.windowCounts[window] += count
			}
			a.entityOpCount += b.entityOpCount
			return a
		},
	)

	if err != nil {
		return err
	}

	entityOps := result.entityOpCount

	fmt.Fprintf(os.Stderr, "\nTotal: found %s operations for entity: %s\n",
		utils.FormatNumber(entityOps), entityID)

	if entityOps == 0 {
		fmt.Printf("\nNo operations found for this entity!\n")
		return nil
	}

	// Sort timeline
	sort.Slice(result.operations, func(i, j int) bool {
		return result.operations[i].timestamp.Before(result.operations[j].timestamp)
	})

	// Calculate time span
	if len(result.operations) == 0 {
		return nil
	}
	firstOp := result.operations[0].timestamp
	lastOp := result.operations[len(result.operations)-1].timestamp
	timeSpanHours := lastOp.Sub(firstOp).Hours()

	// Analysis and reporting
	fmt.Printf("\n%s\n", strings.Repeat("=", 100))
	fmt.Printf("TIMELINE ANALYSIS FOR: %s\n", entityID)
	fmt.Printf("%s\n", strings.Repeat("=", 100))

	// 1. Summary statistics
	fmt.Printf("\n1. SUMMARY STATISTICS\n")
	fmt.Printf("%s\n", strings.Repeat("-", 100))
	fmt.Printf("Total operations: %s\n", utils.FormatNumber(entityOps))
	fmt.Printf("Time span: %.2f hours (%.2f days)\n", timeSpanHours, timeSpanHours/24.0)

	if timeSpanHours > 0 {
		fmt.Printf("Average rate: %.1f operations/hour (%.2f/minute)\n",
			float64(entityOps)/timeSpanHours,
			float64(entityOps)/timeSpanHours/60.0)
	}
	fmt.Printf("First operation: %s\n", firstOp.Format("2006-01-02 15:04:05"))
	fmt.Printf("Last operation: %s\n", lastOp.Format("2006-01-02 15:04:05"))

	// 2. Operation type distribution
	fmt.Printf("\n2. OPERATION TYPE DISTRIBUTION\n")
	fmt.Printf("%s\n", strings.Repeat("-", 100))
	fmt.Printf("%-30s %-15s %-15s\n", "Operation", "Count", "Percentage")
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	type opEntry struct {
		op    string
		count int
	}
	var sortedOps []opEntry
	for op, count := range result.operationsByType {
		sortedOps = append(sortedOps, opEntry{op, count})
	}
	sort.Slice(sortedOps, func(i, j int) bool {
		return sortedOps[i].count > sortedOps[j].count
	})

	for _, entry := range sortedOps {
		percentage := (float64(entry.count) / float64(entityOps)) * 100.0
		fmt.Printf("%-30s %-15s %-15.2f%%\n", entry.op, utils.FormatNumber(entry.count), percentage)
	}

	// 3. Top paths accessed
	fmt.Printf("\n3. TOP 30 PATHS ACCESSED\n")
	fmt.Printf("%s\n", strings.Repeat("-", 100))
	fmt.Printf("%-70s %-15s %-15s\n", "Path", "Count", "Percentage")
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	type pathEntry struct {
		path  string
		count int
	}
	var sortedPaths []pathEntry
	for path, count := range result.pathsAccessed {
		sortedPaths = append(sortedPaths, pathEntry{path, count})
	}
	sort.Slice(sortedPaths, func(i, j int) bool {
		return sortedPaths[i].count > sortedPaths[j].count
	})

	for i, entry := range sortedPaths {
		if i >= 30 {
			break
		}
		percentage := (float64(entry.count) / float64(entityOps)) * 100.0
		displayPath := entry.path
		if len(displayPath) > 68 {
			displayPath = displayPath[:65] + "..."
		}
		fmt.Printf("%-70s %-15s %-15.2f%%\n", displayPath, utils.FormatNumber(entry.count), percentage)
	}

	// 4. Hourly activity pattern
	fmt.Printf("\n4. HOURLY ACTIVITY PATTERN (Top 30 Hours)\n")
	fmt.Printf("%s\n", strings.Repeat("-", 100))
	fmt.Printf("%-20s %-12s %-10s %-10s %-10s %-10s\n", "Hour", "Total Ops", "read", "update", "list", "Other")
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	type hourEntry struct {
		hour string
		ops  map[string]int
	}
	var sortedHours []hourEntry
	for hour, ops := range result.operationsByHour {
		sortedHours = append(sortedHours, hourEntry{hour, ops})
	}
	sort.Slice(sortedHours, func(i, j int) bool {
		return sortedHours[i].ops["total"] > sortedHours[j].ops["total"]
	})

	for i, entry := range sortedHours {
		if i >= 30 {
			break
		}
		total := entry.ops["total"]
		read := entry.ops["read"]
		update := entry.ops["update"]
		listOps := entry.ops["list"]
		other := total - read - update - listOps

		fmt.Printf("%-20s %-12s %-10s %-10s %-10s %-10s\n",
			entry.hour, utils.FormatNumber(total),
			utils.FormatNumber(read), utils.FormatNumber(update),
			utils.FormatNumber(listOps), utils.FormatNumber(other))
	}

	// 5. Activity distribution by hour of day
	fmt.Printf("\n5. ACTIVITY DISTRIBUTION BY HOUR OF DAY\n")
	fmt.Printf("%s\n", strings.Repeat("-", 100))
	fmt.Printf("%-10s %-15s %-50s\n", "Hour", "Operations", "Bar Chart")
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	maxOpsInHour := 0
	for _, count := range result.hourOfDayStats {
		if count > maxOpsInHour {
			maxOpsInHour = count
		}
	}

	for hour := 0; hour < 24; hour++ {
		ops := result.hourOfDayStats[hour]
		barLength := 0
		if maxOpsInHour > 0 {
			barLength = (ops * 50) / maxOpsInHour
		}
		bar := strings.Repeat("█", barLength)
		fmt.Printf("%02d:00     %-15s %s\n", hour, utils.FormatNumber(ops), bar)
	}

	// 6. Peak activity analysis
	fmt.Printf("\n6. PEAK ACTIVITY WINDOWS\n")
	fmt.Printf("%s\n", strings.Repeat("-", 100))
	fmt.Printf("%-25s %-15s %-20s\n", "5-Minute Window", "Operations", "Rate (ops/sec)")
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	type windowEntry struct {
		window time.Time
		count  int
	}
	var sortedWindows []windowEntry
	for window, count := range result.windowCounts {
		sortedWindows = append(sortedWindows, windowEntry{window, count})
	}
	sort.Slice(sortedWindows, func(i, j int) bool {
		return sortedWindows[i].count > sortedWindows[j].count
	})

	for i, entry := range sortedWindows {
		if i >= 20 {
			break
		}
		rate := float64(entry.count) / 300.0
		fmt.Printf("%-25s %-15s %-20.3f\n",
			entry.window.Format("2006-01-02 15:04"),
			utils.FormatNumber(entry.count), rate)
	}

	// 7. Behavioral patterns
	fmt.Printf("\n7. BEHAVIORAL PATTERNS\n")
	fmt.Printf("%s\n", strings.Repeat("-", 100))

	if timeSpanHours > 1.0 {
		opsPerHour := float64(entityOps) / timeSpanHours
		if opsPerHour > 100.0 {
			fmt.Printf("WARNING: HIGH FREQUENCY: %.0f operations/hour suggests automated polling\n", opsPerHour)
			fmt.Printf("   Recommended action: Implement caching or increase polling interval\n")
		}

		// Check for token lookup abuse
		tokenLookupCount := 0
		for path, count := range result.pathsAccessed {
			if strings.Contains(path, "token/lookup") {
				tokenLookupCount += count
			}
		}

		if tokenLookupCount > 1000 {
			fmt.Printf("WARNING: TOKEN LOOKUP ABUSE: %s token lookups detected\n", utils.FormatNumber(tokenLookupCount))
			fmt.Printf("   Rate: %.1f lookups/hour = %.2f lookups/second\n",
				float64(tokenLookupCount)/timeSpanHours,
				float64(tokenLookupCount)/timeSpanHours/3600.0)
			fmt.Printf("   Recommended action: Implement client-side token TTL tracking\n")
		}

		// Check for path concentration
		if len(sortedPaths) > 0 {
			topPathPct := (float64(sortedPaths[0].count) / float64(entityOps)) * 100.0
			if topPathPct > 30.0 {
				fmt.Printf("WARNING: PATH CONCENTRATION: %.1f%% of operations on single path\n", topPathPct)
				fmt.Printf("   Path: %s\n", sortedPaths[0].path)
				fmt.Printf("   Recommended action: Review why this path is accessed %s times\n", utils.FormatNumber(sortedPaths[0].count))
			}
		}

		// Check for 24/7 activity
		hoursWithActivity := 0
		for h := 0; h < 24; h++ {
			if _, ok := result.hourOfDayStats[h]; ok {
				hoursWithActivity++
			}
		}
		if hoursWithActivity >= 20 {
			fmt.Printf("WARNING: 24/7 ACTIVITY: Active in %d/24 hours\n", hoursWithActivity)
			fmt.Printf("   Suggests automated system or background process\n")
		}
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 100))

	return nil
}
