// Package commands provides CLI command implementations for audit analysis.
package commands

import (
	"fmt"
	"sort"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/audit"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/processor"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/utils"
)

// PathData holds statistics for a single path.
type PathData struct {
	Count       int
	Operations  map[string]int
	Entities    map[string]bool
}

// SystemOverviewState accumulates statistics across audit entries.
type SystemOverviewState struct {
	PathOperations map[string]*PathData
	OperationTypes map[string]int
	PathPrefixes   map[string]int
	EntityPaths    map[string]map[string]int
	EntityNames    map[string]string
}

// SystemOverviewRun processes audit logs and outputs system overview statistics.
// namespaceFilter, when non-empty, restricts analysis to entries with that namespace ID.
// sequential forces one-file-at-a-time processing even when multiple files are given.
func SystemOverviewRun(logFiles []string, top int, minOps int, namespaceFilter string, sequential bool) error {
	newState := func() SystemOverviewState {
		return SystemOverviewState{
			PathOperations: make(map[string]*PathData),
			OperationTypes: make(map[string]int),
			PathPrefixes:   make(map[string]int),
			EntityPaths:    make(map[string]map[string]int),
			EntityNames:    make(map[string]string),
		}
	}

	cfg := processor.DefaultConfig()
	if sequential {
		cfg.Mode = processor.ModeSequential
	}

	process := func(entry *audit.AuditEntry, state *SystemOverviewState) {
		// Apply namespace filter.
		if namespaceFilter != "" && entry.NamespaceID() != namespaceFilter {
			return
		}

		path := entry.Path()
		operation := entry.Operation()
		entityID := entry.EntityID()
		if entityID == "" {
			entityID = "no-entity"
		}

		if path == "" || operation == "" {
			return
		}

		// Track by full path
		if _, ok := state.PathOperations[path]; !ok {
			state.PathOperations[path] = &PathData{
				Count:      0,
				Operations: make(map[string]int),
				Entities:   make(map[string]bool),
			}
		}
		pathData := state.PathOperations[path]
		pathData.Count++
		pathData.Operations[operation]++
		pathData.Entities[entityID] = true

		// Track by operation type
		state.OperationTypes[operation]++

		// Track by path prefix
		parts := splitPath(path)
		prefix := ""
		if len(parts) >= 2 {
			prefix = parts[0] + "/" + parts[1]
		} else if len(parts) > 0 {
			prefix = parts[0]
		} else {
			prefix = "root"
		}
		state.PathPrefixes[prefix]++

		// Track entity usage
		if _, ok := state.EntityPaths[entityID]; !ok {
			state.EntityPaths[entityID] = make(map[string]int)
		}
		state.EntityPaths[entityID][path]++

		// Store entity display name
		displayName := entry.DisplayName()
		if displayName == "" {
			displayName = "N/A"
		}
		if _, exists := state.EntityNames[entityID]; !exists {
			state.EntityNames[entityID] = displayName
		}
	}

	merge := func(a, b SystemOverviewState) SystemOverviewState {
		// Merge PathOperations
		for path, bData := range b.PathOperations {
			if aData, ok := a.PathOperations[path]; ok {
				aData.Count += bData.Count
				for op, count := range bData.Operations {
					aData.Operations[op] += count
				}
				for entity := range bData.Entities {
					aData.Entities[entity] = true
				}
			} else {
				a.PathOperations[path] = bData
			}
		}

		// Merge OperationTypes
		for op, count := range b.OperationTypes {
			a.OperationTypes[op] += count
		}

		// Merge PathPrefixes
		for prefix, count := range b.PathPrefixes {
			a.PathPrefixes[prefix] += count
		}

		// Merge EntityPaths
		for entity, paths := range b.EntityPaths {
			if _, ok := a.EntityPaths[entity]; !ok {
				a.EntityPaths[entity] = make(map[string]int)
			}
			for path, count := range paths {
				a.EntityPaths[entity][path] += count
			}
		}

		// Merge EntityNames (first one wins)
		for entity, name := range b.EntityNames {
			if _, ok := a.EntityNames[entity]; !ok {
				a.EntityNames[entity] = name
			}
		}

		return a
	}

	result, stats, err := processor.RunFiles(cfg, logFiles, newState, process, merge)
	if err != nil {
		return fmt.Errorf("process files: %w", err)
	}

	stats.Report()

	// Compute total operations
	totalOps := 0
	for _, count := range result.OperationTypes {
		totalOps += count
	}

	// Print results
	fmt.Println("\n" + stringRepeat("=", 100))
	fmt.Println("High-Volume Vault Operations Analysis")
	fmt.Println(stringRepeat("=", 100))

	// 1. Operation Types Summary
	fmt.Println("\n1. Operation Types (Overall)")
	fmt.Println(stringRepeat("-", 100))
	fmt.Printf("%-20s %15s %12s\n", "Operation", "Count", "Percentage")
	fmt.Println(stringRepeat("-", 100))

	type opPair struct {
		name  string
		count int
	}
	var sortedOps []opPair
	for op, count := range result.OperationTypes {
		sortedOps = append(sortedOps, opPair{op, count})
	}
	sort.Slice(sortedOps, func(i, j int) bool {
		return sortedOps[i].count > sortedOps[j].count
	})

	for _, op := range sortedOps {
		pct := float64(0.0)
		if totalOps > 0 {
			pct = float64(op.count) / float64(totalOps) * 100.0
		}
		fmt.Printf("%-20s %15s %11.2f%%\n", op.name, utils.FormatNumber(op.count), pct)
	}

	fmt.Println(stringRepeat("-", 100))
	fmt.Printf("%-20s %15s %11.2f%%\n", "TOTAL", utils.FormatNumber(totalOps), 100.0)

	// 2. Top Path Prefixes
	fmt.Println("\n2. Top Path Prefixes (First 2 components)")
	fmt.Println(stringRepeat("-", 100))
	fmt.Printf("%-40s %15s %12s\n", "Path Prefix", "Operations", "Percentage")
	fmt.Println(stringRepeat("-", 100))

	type prefixPair struct {
		prefix string
		count  int
	}
	var sortedPrefixes []prefixPair
	for prefix, count := range result.PathPrefixes {
		sortedPrefixes = append(sortedPrefixes, prefixPair{prefix, count})
	}
	sort.Slice(sortedPrefixes, func(i, j int) bool {
		return sortedPrefixes[i].count > sortedPrefixes[j].count
	})

	for i, p := range sortedPrefixes {
		if i >= top {
			break
		}
		pct := float64(0.0)
		if totalOps > 0 {
			pct = float64(p.count) / float64(totalOps) * 100.0
		}
		fmt.Printf("%-40s %15s %11.2f%%\n", p.prefix, utils.FormatNumber(p.count), pct)
	}

	// 3. Top Individual Paths
	fmt.Printf("\n3. Top %d Individual Paths (Highest Volume)\n", top)
	fmt.Println(stringRepeat("-", 100))
	fmt.Printf("%-60s %10s %10s %15s\n", "Path", "Ops", "Entities", "Top Op")
	fmt.Println(stringRepeat("-", 100))

	type pathPair struct {
		path string
		data *PathData
	}
	var sortedPaths []pathPair
	for path, data := range result.PathOperations {
		sortedPaths = append(sortedPaths, pathPair{path, data})
	}
	sort.Slice(sortedPaths, func(i, j int) bool {
		return sortedPaths[i].data.Count > sortedPaths[j].data.Count
	})

	for i, p := range sortedPaths {
		if i >= top || p.data.Count < minOps {
			break
		}
		topOp := "N/A"
		maxCount := 0
		for op, count := range p.data.Operations {
			if count > maxCount {
				maxCount = count
				topOp = op
			}
		}
		pathDisplay := p.path
		if len(pathDisplay) > 60 {
			pathDisplay = pathDisplay[:58] + ".."
		}
		fmt.Printf("%-60s %10s %10s %15s\n", pathDisplay, utils.FormatNumber(p.data.Count),
			utils.FormatNumber(len(p.data.Entities)), topOp)
	}

	// 4. Top Entities by Total Operations
	fmt.Printf("\n4. Top %d Entities by Total Operations\n", top)
	fmt.Println(stringRepeat("-", 100))
	fmt.Printf("%-50s %-38s %10s\n", "Display Name", "Entity ID", "Total Ops")
	fmt.Println(stringRepeat("-", 100))

	entityTotals := make(map[string]int)
	for entity, paths := range result.EntityPaths {
		total := 0
		for _, count := range paths {
			total += count
		}
		entityTotals[entity] = total
	}

	type entityPair struct {
		id    string
		total int
	}
	var sortedEntities []entityPair
	for id, total := range entityTotals {
		sortedEntities = append(sortedEntities, entityPair{id, total})
	}
	sort.Slice(sortedEntities, func(i, j int) bool {
		return sortedEntities[i].total > sortedEntities[j].total
	})

	for i, e := range sortedEntities {
		if i >= top {
			break
		}
		name := result.EntityNames[e.id]
		if name == "" {
			name = "N/A"
		}
		nameDisplay := name
		if len(nameDisplay) > 48 {
			nameDisplay = nameDisplay[:48]
		}
		entityShort := e.id
		if len(entityShort) > 36 {
			entityShort = entityShort[:36]
		}
		fmt.Printf("%-50s %-38s %10s\n", nameDisplay, entityShort, utils.FormatNumber(e.total))
	}

	// 5. Potential Stress Points
	fmt.Println("\n5. Potential System Stress Points")
	fmt.Println(stringRepeat("-", 100))

	type stressPoint struct {
		path       string
		entityName string
		operations int
	}
	var stressPoints []stressPoint

	for path, data := range result.PathOperations {
		if data.Count >= minOps {
			for entity := range data.Entities {
				if entityPaths, ok := result.EntityPaths[entity]; ok {
					if entityOps, ok := entityPaths[path]; ok && entityOps >= minOps {
						entityName := result.EntityNames[entity]
						if entityName == "" {
							entityName = "N/A"
						}
						stressPoints = append(stressPoints, stressPoint{path, entityName, entityOps})
					}
				}
			}
		}
	}

	sort.Slice(stressPoints, func(i, j int) bool {
		return stressPoints[i].operations > stressPoints[j].operations
	})

	fmt.Printf("%-40s %-40s %10s\n", "Entity", "Path", "Ops")
	fmt.Println(stringRepeat("-", 100))

	for i, sp := range stressPoints {
		if i >= top {
			break
		}
		entityDisplay := sp.entityName
		if len(entityDisplay) > 38 {
			entityDisplay = entityDisplay[:38]
		}
		pathDisplay := sp.path
		if len(pathDisplay) > 38 {
			pathDisplay = pathDisplay[:38]
		}
		fmt.Printf("%-40s %-40s %10s\n", entityDisplay, pathDisplay, utils.FormatNumber(sp.operations))
	}

	fmt.Println(stringRepeat("=", 100))
	fmt.Printf("\nTotal Lines Processed: %s\n", utils.FormatNumber(stats.TotalLines))
	fmt.Printf("Total Operations: %s\n", utils.FormatNumber(totalOps))
	fmt.Println(stringRepeat("=", 100))

	return nil
}

// splitPath splits a path by "/" and returns components
func splitPath(path string) []string {
	// Trim leading/trailing slashes
	for len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	for len(path) > 0 && path[len(path)-1] == '/' {
		path = path[:len(path)-1]
	}

	if path == "" {
		return []string{}
	}

	var result []string
	var current string
	for _, ch := range path {
		if ch == '/' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// stringRepeat repeats a string n times
func stringRepeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
