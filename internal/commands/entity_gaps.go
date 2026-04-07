// Package commands provides subcommands for vault audit analysis.
package commands

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/audit"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/processor"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/utils"
)

// GapsState tracks operations without entity IDs.
type GapsState struct {
	operationsByType map[string]int
	pathsAccessed    map[string]int
	noEntityOps      int
}

// RunEntityGaps detects operations without entity IDs.
func RunEntityGaps(logFiles []string, windowSeconds uint64) error {
	_ = windowSeconds // Parameter for future use

	result, stats, err := processor.RunFiles(
		processor.DefaultConfig(),
		logFiles,
		func() GapsState {
			return GapsState{
				operationsByType: make(map[string]int),
				pathsAccessed:    make(map[string]int),
			}
		},
		func(entry *audit.AuditEntry, s *GapsState) {
			// Check for no entity
			if entry.EntityID() != "" {
				return
			}

			s.noEntityOps++

			// Track data
			op := entry.Operation()
			if op != "" {
				s.operationsByType[op]++
			}

			path := entry.Path()
			if path != "" {
				s.pathsAccessed[path]++
			}
		},
		func(a, b GapsState) GapsState {
			// Merge states
			for op, count := range b.operationsByType {
				a.operationsByType[op] += count
			}
			for path, count := range b.pathsAccessed {
				a.pathsAccessed[path] += count
			}
			a.noEntityOps += b.noEntityOps
			return a
		},
	)

	if err != nil {
		return err
	}

	totalLines := stats.TotalLines
	noEntityOps := result.noEntityOps

	fmt.Fprintf(os.Stderr, "\nTotal: Processed %s lines\n", utils.FormatNumber(totalLines))
	fmt.Fprintf(os.Stderr, "Found %s operations with no entity ID\n", utils.FormatNumber(noEntityOps))

	if noEntityOps == 0 {
		fmt.Println("\nNo operations without entity ID found!")
		return nil
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 100))
	fmt.Printf("NO-ENTITY OPERATIONS ANALYSIS\n")
	fmt.Printf("%s\n", strings.Repeat("=", 100))

	fmt.Printf("\n1. SUMMARY\n")
	fmt.Printf("%s\n", strings.Repeat("-", 100))
	fmt.Printf("Total no-entity operations: %s\n", utils.FormatNumber(noEntityOps))
	fmt.Printf("Percentage of all operations: %.2f%%\n", (float64(noEntityOps)/float64(totalLines))*100.0)

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

	for i, entry := range sortedOps {
		if i >= 20 {
			break
		}
		percentage := (float64(entry.count) / float64(noEntityOps)) * 100.0
		fmt.Printf("%-30s %-15s %-15.2f%%\n", entry.op, utils.FormatNumber(entry.count), percentage)
	}

	fmt.Printf("\n3. TOP 30 PATHS ACCESSED\n")
	fmt.Printf("%s\n", strings.Repeat("-", 100))
	fmt.Printf("%-70s %15s %15s\n", "Path", "Count", "% of No-Entity")
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
		percentage := (float64(entry.count) / float64(noEntityOps)) * 100.0
		displayPath := entry.path
		if len(displayPath) > 68 {
			displayPath = displayPath[:65] + "..."
		}
		fmt.Printf("%-70s %15s %14.2f%%\n", displayPath, utils.FormatNumber(entry.count), percentage)
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 100))

	return nil
}
