// Package commands provides CLI command implementations.
package commands

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/audit"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/processor"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/utils"
)

// errorInstance links entity, error type, and path.
type errorInstance struct {
	EntityID    string
	DisplayName string
	ErrorType   string
	Path        string
	Timestamp   string
}

// clientStats tracks statistics for a single client IP.
type clientStats struct {
	requestCount       int
	operations         map[string]int    // operation type -> count
	paths              map[string]int    // path -> count
	mountPoints        map[string]int    // mount point -> count
	entities           map[string]string // entity_id -> display_name
	firstSeen          *string
	lastSeen           *string
	errorCount         int
	errorTypes         map[string]int // error type -> count
	errorPaths         map[string]int // error path -> count
	errorInstances     []errorInstance
	hourlyDistribution map[uint32]int // hour -> count
}

// clientExport is the export format for client metrics.
type clientExport struct {
	ClientIP               string  `csv:"client_ip"`
	TotalRequests          int     `csv:"total_requests"`
	UniqueEntities         int     `csv:"unique_entities"`
	UniquePaths            int     `csv:"unique_paths"`
	UniqueMountPoints      int     `csv:"unique_mount_points"`
	ErrorCount             int     `csv:"error_count"`
	ErrorRate              float64 `csv:"error_rate"`
	FirstSeen              string  `csv:"first_seen"`
	LastSeen               string  `csv:"last_seen"`
	TopOperation           string  `csv:"top_operation"`
	TopOperationCount      int     `csv:"top_operation_count"`
	TopPath                string  `csv:"top_path"`
	TopPathCount           int     `csv:"top_path_count"`
	TopErrorType           string  `csv:"top_error_type"`
	TopErrorTypeCount      int     `csv:"top_error_type_count"`
	TopErrorTypePercentage float64 `csv:"top_error_type_percentage"`
	SecondErrorType        string  `csv:"second_error_type"`
	SecondErrorTypeCount   int     `csv:"second_error_type_count"`
	ThirdErrorType         string  `csv:"third_error_type"`
	ThirdErrorTypeCount    int     `csv:"third_error_type_count"`
	TopErrorPath           string  `csv:"top_error_path"`
	TopErrorPathCount      int     `csv:"top_error_path_count"`
	Classification         string  `csv:"classification"`
}

// detailedErrorExport represents a detailed error export record.
type detailedErrorExport struct {
	ClientIP    string `csv:"client_ip"`
	EntityID    string `csv:"entity_id"`
	DisplayName string `csv:"display_name"`
	ErrorType   string `csv:"error_type"`
	Path        string `csv:"path"`
	Timestamp   string `csv:"timestamp"`
}

// trafficStats aggregates statistics across all clients.
type trafficStats struct {
	clients       map[string]*clientStats
	totalRequests int
}

// newClientStats creates a new client stats object.
func newClientStats() *clientStats {
	return &clientStats{
		operations:         make(map[string]int),
		paths:              make(map[string]int),
		mountPoints:        make(map[string]int),
		entities:           make(map[string]string),
		errorTypes:         make(map[string]int),
		errorPaths:         make(map[string]int),
		hourlyDistribution: make(map[uint32]int),
	}
}

// update updates stats with a new audit entry.
func (cs *clientStats) update(entry *audit.AuditEntry) {
	cs.requestCount++

	// Track operation type
	if op := entry.Operation(); op != "" {
		cs.operations[op]++
	}

	// Track path
	if path := entry.Path(); path != "" {
		cs.paths[path]++
	}

	// Track mount point
	if mp := entry.MountPoint(); mp != "" {
		cs.mountPoints[mp]++
	}

	// Track entity
	if entityID := entry.EntityID(); entityID != "" {
		if displayName := entry.DisplayName(); displayName != "" {
			cs.entities[entityID] = displayName
		}
	}

	// Track timestamps
	if cs.firstSeen == nil {
		cs.firstSeen = &entry.Time
	}
	cs.lastSeen = &entry.Time

	// Track errors
	if entry.HasError() {
		cs.errorCount++

		cleanedError := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(entry.ErrorString(), "\n", " "), "\t", " "))

		// Categorize error
		errorType := categorizeError(cleanedError)
		cs.errorTypes[errorType]++

		// Track which path generated the error
		path := entry.Path()
		if path == "" {
			path = "unknown"
		}
		cs.errorPaths[path]++

		// Create detailed error instance
		entityID := entry.EntityID()
		if entityID == "" {
			entityID = "unknown"
		}
		displayName := entry.DisplayName()
		if displayName == "" {
			displayName = "unknown"
		}

		cs.errorInstances = append(cs.errorInstances, errorInstance{
			EntityID:    entityID,
			DisplayName: displayName,
			ErrorType:   errorType,
			Path:        path,
			Timestamp:   entry.Time,
		})
	}

	// Track hourly distribution
	if t, err := time.Parse(time.RFC3339Nano, entry.Time); err == nil {
		hour := uint32(t.Hour())
		cs.hourlyDistribution[hour]++
	}
}

// categorizeError categorizes an error message.
func categorizeError(msg string) string {
	switch {
	case strings.Contains(msg, "permission denied"):
		return "permission denied"
	case strings.Contains(msg, "service account name not authorized"):
		return "service account not authorized"
	case strings.Contains(msg, "namespace not authorized"):
		return "namespace not authorized"
	case strings.Contains(msg, "invalid credentials"):
		return "invalid credentials"
	case strings.Contains(msg, "wrapping token"):
		return "invalid wrapping token"
	case strings.Contains(msg, "internal error"):
		return "internal error"
	case strings.Contains(msg, "unsupported operation"):
		return "unsupported operation"
	case strings.Contains(msg, "max TTL"):
		return "max TTL exceeded"
	case msg == "" || msg == "null":
		return "unknown error"
	default:
		if len(msg) > 50 {
			return msg[:50]
		}
		return msg
	}
}

// classifyBehavior classifies client behavior as automated or interactive.
func (cs *clientStats) classifyBehavior() string {
	if cs.requestCount == 0 {
		return "unknown"
	}
	pathsPerRequest := float64(len(cs.paths)) / float64(cs.requestCount)
	if cs.requestCount > 1000 || pathsPerRequest < 0.1 {
		return "automated"
	}
	return "interactive"
}

// toExport converts client stats to export format.
func (cs *clientStats) toExport(clientIP string) clientExport {
	errorRate := 0.0
	if cs.requestCount > 0 {
		errorRate = float64(cs.errorCount) / float64(cs.requestCount) * 100.0
	}

	// Get top operation
	topOp := "none"
	topOpCount := 0
	for op, count := range cs.operations {
		if count > topOpCount {
			topOp = op
			topOpCount = count
		}
	}

	// Get top path
	topPath := "none"
	topPathCount := 0
	for path, count := range cs.paths {
		if count > topPathCount {
			topPath = path
			topPathCount = count
		}
	}

	// Get top 3 error types
	type errTypeCount struct {
		eType string
		count int
	}
	var errorTypes []errTypeCount
	for eType, count := range cs.errorTypes {
		errorTypes = append(errorTypes, errTypeCount{eType, count})
	}
	sort.Slice(errorTypes, func(i, j int) bool {
		return errorTypes[i].count > errorTypes[j].count
	})

	topErrType := "none"
	topErrTypeCount := 0
	if len(errorTypes) > 0 {
		topErrType = errorTypes[0].eType
		topErrTypeCount = errorTypes[0].count
	}

	secondErrType := "none"
	secondErrTypeCount := 0
	if len(errorTypes) > 1 {
		secondErrType = errorTypes[1].eType
		secondErrTypeCount = errorTypes[1].count
	}

	thirdErrType := "none"
	thirdErrTypeCount := 0
	if len(errorTypes) > 2 {
		thirdErrType = errorTypes[2].eType
		thirdErrTypeCount = errorTypes[2].count
	}

	topErrTypePerc := 0.0
	if cs.errorCount > 0 {
		topErrTypePerc = float64(topErrTypeCount) / float64(cs.errorCount) * 100.0
	}

	// Get top error path
	topErrPath := "none"
	topErrPathCount := 0
	for path, count := range cs.errorPaths {
		if count > topErrPathCount {
			topErrPath = path
			topErrPathCount = count
		}
	}

	firstSeen := "unknown"
	if cs.firstSeen != nil {
		firstSeen = *cs.firstSeen
	}

	lastSeen := "unknown"
	if cs.lastSeen != nil {
		lastSeen = *cs.lastSeen
	}

	return clientExport{
		ClientIP:               clientIP,
		TotalRequests:          cs.requestCount,
		UniqueEntities:         len(cs.entities),
		UniquePaths:            len(cs.paths),
		UniqueMountPoints:      len(cs.mountPoints),
		ErrorCount:             cs.errorCount,
		ErrorRate:              errorRate,
		FirstSeen:              firstSeen,
		LastSeen:               lastSeen,
		TopOperation:           topOp,
		TopOperationCount:      topOpCount,
		TopPath:                topPath,
		TopPathCount:           topPathCount,
		TopErrorType:           topErrType,
		TopErrorTypeCount:      topErrTypeCount,
		TopErrorTypePercentage: topErrTypePerc,
		SecondErrorType:        secondErrType,
		SecondErrorTypeCount:   secondErrTypeCount,
		ThirdErrorType:         thirdErrType,
		ThirdErrorTypeCount:    thirdErrTypeCount,
		TopErrorPath:           topErrPath,
		TopErrorPathCount:      topErrPathCount,
		Classification:         cs.classifyBehavior(),
	}
}

// trafficStats methods

func newTrafficStats() trafficStats {
	return trafficStats{
		clients: make(map[string]*clientStats),
	}
}

func (ts *trafficStats) merge(other trafficStats) {
	ts.totalRequests += other.totalRequests
	for ip, stats := range other.clients {
		if ts.clients[ip] == nil {
			ts.clients[ip] = stats
		} else {
			// Merge into existing
			cs := ts.clients[ip]
			cs.requestCount += stats.requestCount
			cs.errorCount += stats.errorCount

			for op, count := range stats.operations {
				cs.operations[op] += count
			}
			for path, count := range stats.paths {
				cs.paths[path] += count
			}
			for mp, count := range stats.mountPoints {
				cs.mountPoints[mp] += count
			}
			for eid, dname := range stats.entities {
				cs.entities[eid] = dname
			}
			for et, count := range stats.errorTypes {
				cs.errorTypes[et] += count
			}
			for path, count := range stats.errorPaths {
				cs.errorPaths[path] += count
			}
			cs.errorInstances = append(cs.errorInstances, stats.errorInstances...)
			for hour, count := range stats.hourlyDistribution {
				cs.hourlyDistribution[hour] += count
			}

			// Merge timestamps
			if cs.firstSeen == nil || (stats.firstSeen != nil && *stats.firstSeen < *cs.firstSeen) {
				cs.firstSeen = stats.firstSeen
			}
			if cs.lastSeen == nil || (stats.lastSeen != nil && *stats.lastSeen > *cs.lastSeen) {
				cs.lastSeen = stats.lastSeen
			}
		}
	}
}

// RunClientTrafficAnalysis analyzes client traffic patterns from audit logs.
func RunClientTrafficAnalysis(logFiles []string, output *string, format *string, errorDetailsOutput *string, top int, temporal bool, minRequests int, showOperations, showErrors, showDetails bool) error {
	if len(logFiles) == 1 {
		fmt.Fprintf(os.Stderr, "Analyzing client traffic patterns from 1 file...\n")
	} else {
		fmt.Fprintf(os.Stderr, "Analyzing client traffic patterns from %d files...\n", len(logFiles))
	}

	// Create processor state
	newState := func() trafficStats {
		return newTrafficStats()
	}

	// Process entries
	processEntry := func(entry *audit.AuditEntry, state *trafficStats) {
		// Only process request entries
		if entry.EntryType != "request" {
			return
		}

		// Get client IP
		clientIP := entry.RemoteAddress()
		if clientIP == "" {
			return
		}

		// Update client stats
		if state.clients[clientIP] == nil {
			state.clients[clientIP] = newClientStats()
		}
		state.clients[clientIP].update(entry)
		state.totalRequests++
	}

	// Merge function
	merge := func(a, b trafficStats) trafficStats {
		a.merge(b)
		return a
	}

	result, _, err := processor.RunFiles(
		processor.DefaultConfig(),
		logFiles,
		newState,
		processEntry,
		merge,
	)
	if err != nil {
		return err
	}

	// Filter by minimum requests
	if minRequests > 1 {
		filtered := newTrafficStats()
		filtered.totalRequests = result.totalRequests
		for ip, stats := range result.clients {
			if stats.requestCount >= minRequests {
				filtered.clients[ip] = stats
			}
		}
		result = filtered
	}

	// Export summary data
	if output != nil && *output != "" {
		if err := exportData(&result, *output, format); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Exported summary data to %s\n", *output)
	}

	// Export detailed error analysis
	if errorDetailsOutput != nil && *errorDetailsOutput != "" {
		if err := exportErrorDetails(&result, *errorDetailsOutput); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Exported detailed error analysis (with entities) to %s\n", *errorDetailsOutput)
	}

	// Generate report
	printSummary(&result)
	printTopClients(&result, top)
	printClientBehaviorAnalysis(&result)

	if showOperations {
		if top > 10 {
			top = 10
		}
		printOperationBreakdown(&result, top)
	}

	if showErrors {
		if top > 10 {
			top = 10
		}
		printErrorAnalysis(&result, top)
	}

	if showDetails {
		if top > 10 {
			top = 10
		}
		printDetailedClientAnalysis(&result, top)
	}

	if temporal {
		if top > 10 {
			top = 10
		}
		printTemporalAnalysis(&result, top)
	}

	return nil
}

// Print functions

func printSummary(stats *trafficStats) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("Client Traffic Analysis Summary")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Printf("Total Requests: %s\n", utils.FormatNumber(stats.totalRequests))
	fmt.Printf("Unique Clients: %s\n", utils.FormatNumber(len(stats.clients)))
	if len(stats.clients) > 0 {
		fmt.Printf("Avg Requests per Client: %.2f\n", float64(stats.totalRequests)/float64(len(stats.clients)))
	}
}

func printTopClients(stats *trafficStats, topN int) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 100))
	fmt.Printf("Top %d Clients by Request Volume\n", topN)
	fmt.Println(strings.Repeat("=", 100))
	fmt.Printf("%-20s %15s %15s %15s %15s\n", "Client IP", "Requests", "Entities", "Errors", "Error %")
	fmt.Println(strings.Repeat("-", 100))

	type clientPair struct {
		ip    string
		stats *clientStats
	}
	var clients []clientPair
	for ip, stats := range stats.clients {
		clients = append(clients, clientPair{ip, stats})
	}
	sort.Slice(clients, func(i, j int) bool {
		return clients[i].stats.requestCount > clients[j].stats.requestCount
	})

	for i := 0; i < topN && i < len(clients); i++ {
		cs := clients[i].stats
		errorPct := 0.0
		if cs.requestCount > 0 {
			errorPct = float64(cs.errorCount) / float64(cs.requestCount) * 100.0
		}
		fmt.Printf("%-20s %15s %15s %15s %14.2f%%\n",
			clients[i].ip,
			utils.FormatNumber(cs.requestCount),
			utils.FormatNumber(len(cs.entities)),
			utils.FormatNumber(cs.errorCount),
			errorPct)
	}
}

func printClientBehaviorAnalysis(stats *trafficStats) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("Client Behavior Analysis")
	fmt.Println(strings.Repeat("=", 100))

	var automatedClients, interactiveClients []struct {
		ip    string
		stats *clientStats
	}

	for ip, cs := range stats.clients {
		pathsPerRequest := float64(len(cs.paths)) / float64(cs.requestCount)
		if cs.requestCount > 1000 || pathsPerRequest < 0.1 {
			automatedClients = append(automatedClients, struct {
				ip    string
				stats *clientStats
			}{ip, cs})
		} else {
			interactiveClients = append(interactiveClients, struct {
				ip    string
				stats *clientStats
			}{ip, cs})
		}
	}

	fmt.Printf("Automated Clients (likely services): %d\n", len(automatedClients))
	fmt.Printf("Interactive Clients (likely users): %d\n", len(interactiveClients))

	if len(automatedClients) > 0 {
		fmt.Println("\nTop Automated Clients:")
		fmt.Printf("%-20s %15s %15s\n", "Client IP", "Requests", "Unique Paths")
		fmt.Println(strings.Repeat("-", 60))

		sort.Slice(automatedClients, func(i, j int) bool {
			return automatedClients[i].stats.requestCount > automatedClients[j].stats.requestCount
		})

		for i := 0; i < 10 && i < len(automatedClients); i++ {
			fmt.Printf("%-20s %15s %15s\n",
				automatedClients[i].ip,
				utils.FormatNumber(automatedClients[i].stats.requestCount),
				utils.FormatNumber(len(automatedClients[i].stats.paths)))
		}
	}
}

func printOperationBreakdown(stats *trafficStats, topN int) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 100))
	fmt.Printf("Operation Type Breakdown - Top %d Clients\n", topN)
	fmt.Println(strings.Repeat("=", 100))

	type clientPair struct {
		ip    string
		stats *clientStats
	}
	var clients []clientPair
	for ip, cs := range stats.clients {
		clients = append(clients, clientPair{ip, cs})
	}
	sort.Slice(clients, func(i, j int) bool {
		return clients[i].stats.requestCount > clients[j].stats.requestCount
	})

	for i := 0; i < topN && i < len(clients); i++ {
		ip := clients[i].ip
		cs := clients[i].stats

		fmt.Printf("\nClient: %s (Total: %s)\n", ip, utils.FormatNumber(cs.requestCount))
		fmt.Println(strings.Repeat("-", 80))

		type opCount struct {
			op    string
			count int
		}
		var ops []opCount
		for op, count := range cs.operations {
			ops = append(ops, opCount{op, count})
		}
		sort.Slice(ops, func(i, j int) bool {
			return ops[i].count > ops[j].count
		})

		fmt.Printf("%-30s %15s %15s\n", "Operation", "Count", "Percentage")
		fmt.Println(strings.Repeat("-", 60))

		for _, oc := range ops {
			pct := float64(oc.count) / float64(cs.requestCount) * 100.0
			fmt.Printf("%-30s %15s %14.2f%%\n",
				oc.op,
				utils.FormatNumber(oc.count),
				pct)
		}
	}
}

func printErrorAnalysis(stats *trafficStats, topN int) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("Error Analysis - Clients with Errors")
	fmt.Println(strings.Repeat("=", 100))

	type clientPair struct {
		ip    string
		stats *clientStats
	}
	var clientsWithErrors []clientPair
	for ip, cs := range stats.clients {
		if cs.errorCount > 0 {
			clientsWithErrors = append(clientsWithErrors, clientPair{ip, cs})
		}
	}

	if len(clientsWithErrors) == 0 {
		fmt.Println("No errors detected in the analyzed logs.")
		return
	}

	sort.Slice(clientsWithErrors, func(i, j int) bool {
		return clientsWithErrors[i].stats.errorCount > clientsWithErrors[j].stats.errorCount
	})

	fmt.Printf("%-20s %15s %15s %15s\n", "Client IP", "Total Requests", "Errors", "Error Rate")
	fmt.Println(strings.Repeat("-", 80))

	for i := 0; i < topN && i < len(clientsWithErrors); i++ {
		cs := clientsWithErrors[i].stats
		errorRate := float64(cs.errorCount) / float64(cs.requestCount) * 100.0
		fmt.Printf("%-20s %15s %15s %14.2f%%\n",
			clientsWithErrors[i].ip,
			utils.FormatNumber(cs.requestCount),
			utils.FormatNumber(cs.errorCount),
			errorRate)
	}

	// Print error type breakdown
	fmt.Println()
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("Error Type Breakdown by Client")
	fmt.Println(strings.Repeat("=", 100))

	for i := 0; i < topN && i < len(clientsWithErrors); i++ {
		ip := clientsWithErrors[i].ip
		cs := clientsWithErrors[i].stats

		if len(cs.errorTypes) == 0 {
			continue
		}

		fmt.Printf("\nClient: %s (Total Errors: %s)\n", ip, utils.FormatNumber(cs.errorCount))
		fmt.Println(strings.Repeat("-", 80))

		type errCount struct {
			et    string
			count int
		}
		var errs []errCount
		for et, count := range cs.errorTypes {
			errs = append(errs, errCount{et, count})
		}
		sort.Slice(errs, func(i, j int) bool {
			return errs[i].count > errs[j].count
		})

		fmt.Printf("%-50s %15s %15s\n", "Error Type", "Count", "Percentage")
		fmt.Println(strings.Repeat("-", 80))

		for j := 0; j < 10 && j < len(errs); j++ {
			pct := float64(errs[j].count) / float64(cs.errorCount) * 100.0
			truncated := errs[j].et
			if len(truncated) > 50 {
				truncated = truncated[:47] + "..."
			}
			fmt.Printf("%-50s %15s %14.2f%%\n",
				truncated,
				utils.FormatNumber(errs[j].count),
				pct)
		}

		// Print top error paths
		if len(cs.errorPaths) > 0 {
			fmt.Println("\nTop Paths Generating Errors:")
			fmt.Printf("%-60s %15s\n", "Path", "Error Count")
			fmt.Println(strings.Repeat("-", 80))

			type pathCount struct {
				path  string
				count int
			}
			var paths []pathCount
			for p, c := range cs.errorPaths {
				paths = append(paths, pathCount{p, c})
			}
			sort.Slice(paths, func(i, j int) bool {
				return paths[i].count > paths[j].count
			})

			for j := 0; j < 5 && j < len(paths); j++ {
				truncated := paths[j].path
				if len(truncated) > 60 {
					truncated = truncated[:57] + "..."
				}
				fmt.Printf("%-60s %15s\n", truncated, utils.FormatNumber(paths[j].count))
			}
		}
	}

	// Overall error distribution
	fmt.Println()
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("Overall Error Type Distribution")
	fmt.Println(strings.Repeat("=", 100))

	overallErrors := make(map[string]int)
	totalErrors := 0
	for _, pair := range clientsWithErrors {
		for et, count := range pair.stats.errorTypes {
			overallErrors[et] += count
			totalErrors += count
		}
	}

	type errCount struct {
		et    string
		count int
	}
	var errs []errCount
	for et, count := range overallErrors {
		errs = append(errs, errCount{et, count})
	}
	sort.Slice(errs, func(i, j int) bool {
		return errs[i].count > errs[j].count
	})

	fmt.Printf("%-50s %15s %15s\n", "Error Type", "Count", "Percentage")
	fmt.Println(strings.Repeat("-", 80))

	for i := 0; i < 15 && i < len(errs); i++ {
		pct := float64(errs[i].count) / float64(totalErrors) * 100.0
		truncated := errs[i].et
		if len(truncated) > 50 {
			truncated = truncated[:47] + "..."
		}
		fmt.Printf("%-50s %15s %14.2f%%\n",
			truncated,
			utils.FormatNumber(errs[i].count),
			pct)
	}
}

func printDetailedClientAnalysis(stats *trafficStats, topN int) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 100))
	fmt.Printf("Detailed Client Analysis - Top %d Clients\n", topN)
	fmt.Println(strings.Repeat("=", 100))

	type clientPair struct {
		ip    string
		stats *clientStats
	}
	var clients []clientPair
	for ip, cs := range stats.clients {
		clients = append(clients, clientPair{ip, cs})
	}
	sort.Slice(clients, func(i, j int) bool {
		return clients[i].stats.requestCount > clients[j].stats.requestCount
	})

	for i := 0; i < topN && i < len(clients); i++ {
		ip := clients[i].ip
		cs := clients[i].stats

		fmt.Println()
		fmt.Println(strings.Repeat("=", 100))
		fmt.Printf("Client: %s\n", ip)
		fmt.Println(strings.Repeat("=", 100))
		fmt.Printf("Total Requests: %s\n", utils.FormatNumber(cs.requestCount))
		fmt.Printf("Unique Entities: %s\n", utils.FormatNumber(len(cs.entities)))
		fmt.Printf("Unique Paths: %s\n", utils.FormatNumber(len(cs.paths)))
		fmt.Printf("Unique Mount Points: %s\n", utils.FormatNumber(len(cs.mountPoints)))
		fmt.Printf("Error Count: %s\n", utils.FormatNumber(cs.errorCount))
		fmt.Printf("Classification: %s\n", cs.classifyBehavior())
		firstSeen := "unknown"
		if cs.firstSeen != nil {
			firstSeen = *cs.firstSeen
		}
		lastSeen := "unknown"
		if cs.lastSeen != nil {
			lastSeen = *cs.lastSeen
		}
		fmt.Printf("First Seen: %s\n", firstSeen)
		fmt.Printf("Last Seen: %s\n", lastSeen)

		// Top paths
		fmt.Println("\nTop Paths Accessed:")
		fmt.Printf("%-60s %15s\n", "Path", "Count")
		fmt.Println(strings.Repeat("-", 80))

		type pathCount struct {
			p string
			c int
		}
		var paths []pathCount
		for p, c := range cs.paths {
			paths = append(paths, pathCount{p, c})
		}
		sort.Slice(paths, func(i, j int) bool {
			return paths[i].c > paths[j].c
		})

		for j := 0; j < 10 && j < len(paths); j++ {
			truncated := paths[j].p
			if len(truncated) > 60 {
				truncated = truncated[:57] + "..."
			}
			fmt.Printf("%-60s %15s\n", truncated, utils.FormatNumber(paths[j].c))
		}

		// Top mount points
		fmt.Println("\nTop Mount Points:")
		fmt.Printf("%-60s %15s\n", "Mount Point", "Count")
		fmt.Println(strings.Repeat("-", 80))

		type mpCount struct {
			mp string
			c  int
		}
		var mps []mpCount
		for mp, c := range cs.mountPoints {
			mps = append(mps, mpCount{mp, c})
		}
		sort.Slice(mps, func(i, j int) bool {
			return mps[i].c > mps[j].c
		})

		for j := 0; j < 10 && j < len(mps); j++ {
			fmt.Printf("%-60s %15s\n", mps[j].mp, utils.FormatNumber(mps[j].c))
		}

		// Entities
		if len(cs.entities) > 0 {
			fmt.Println("\nAssociated Entities:")
			fmt.Printf("%-40s %s\n", "Entity ID", "Display Name")
			fmt.Println(strings.Repeat("-", 80))

			type ent struct {
				id   string
				name string
			}
			var ents []ent
			for id, name := range cs.entities {
				ents = append(ents, ent{id, name})
			}
			sort.Slice(ents, func(i, j int) bool {
				return ents[i].id < ents[j].id
			})

			for j := 0; j < 10 && j < len(ents); j++ {
				fmt.Printf("%-40s %s\n", ents[j].id, ents[j].name)
			}
		}
	}
}

func printTemporalAnalysis(stats *trafficStats, topN int) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("Temporal Analysis - Hourly Request Distribution")
	fmt.Println(strings.Repeat("=", 100))

	type clientPair struct {
		ip    string
		stats *clientStats
	}
	var clients []clientPair
	for ip, cs := range stats.clients {
		clients = append(clients, clientPair{ip, cs})
	}
	sort.Slice(clients, func(i, j int) bool {
		return clients[i].stats.requestCount > clients[j].stats.requestCount
	})

	for i := 0; i < topN && i < len(clients); i++ {
		ip := clients[i].ip
		cs := clients[i].stats

		fmt.Printf("\nClient: %s (Total: %s)\n", ip, utils.FormatNumber(cs.requestCount))
		fmt.Println(strings.Repeat("-", 80))

		type hourCount struct {
			hour  uint32
			count int
		}
		var hourly []hourCount
		for hour, count := range cs.hourlyDistribution {
			hourly = append(hourly, hourCount{hour, count})
		}
		sort.Slice(hourly, func(i, j int) bool {
			return hourly[i].hour < hourly[j].hour
		})

		for _, hc := range hourly {
			pct := float64(hc.count) / float64(cs.requestCount) * 100.0
			barLen := int(pct / 2)
			bar := strings.Repeat("#", barLen)
			fmt.Printf("%02d:00 %8s %6.2f%% %s\n",
				hc.hour,
				utils.FormatNumber(hc.count),
				pct,
				bar)
		}
	}
}

// Export functions

func exportData(stats *trafficStats, outputFile string, format *string) error {
	formatStr := "csv"
	if format != nil {
		formatStr = *format
	}

	// Convert to export format
	var exports []clientExport
	for ip, cs := range stats.clients {
		exports = append(exports, cs.toExport(ip))
	}

	// Sort by request count
	sort.Slice(exports, func(i, j int) bool {
		return exports[i].TotalRequests > exports[j].TotalRequests
	})

	switch formatStr {
	case "csv":
		return exportClientCSV(exports, outputFile)
	case "json":
		return exportJSON(exports, outputFile)
	default:
		return fmt.Errorf("unsupported format: %s", formatStr)
	}
}

func exportClientCSV(data []clientExport, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"client_ip", "total_requests", "unique_entities", "unique_paths", "unique_mount_points",
		"error_count", "error_rate", "first_seen", "last_seen",
		"top_operation", "top_operation_count", "top_path", "top_path_count",
		"top_error_type", "top_error_type_count", "top_error_type_percentage",
		"second_error_type", "second_error_type_count",
		"third_error_type", "third_error_type_count",
		"top_error_path", "top_error_path_count", "classification",
	}
	writer.Write(header) //nolint:errcheck

	// Write records
	for _, export := range data {
		writer.Write([]string{
			export.ClientIP,
			fmt.Sprintf("%d", export.TotalRequests),
			fmt.Sprintf("%d", export.UniqueEntities),
			fmt.Sprintf("%d", export.UniquePaths),
			fmt.Sprintf("%d", export.UniqueMountPoints),
			fmt.Sprintf("%d", export.ErrorCount),
			fmt.Sprintf("%.2f", export.ErrorRate),
			export.FirstSeen,
			export.LastSeen,
			export.TopOperation,
			fmt.Sprintf("%d", export.TopOperationCount),
			export.TopPath,
			fmt.Sprintf("%d", export.TopPathCount),
			export.TopErrorType,
			fmt.Sprintf("%d", export.TopErrorTypeCount),
			fmt.Sprintf("%.2f", export.TopErrorTypePercentage),
			export.SecondErrorType,
			fmt.Sprintf("%d", export.SecondErrorTypeCount),
			export.ThirdErrorType,
			fmt.Sprintf("%d", export.ThirdErrorTypeCount),
			export.TopErrorPath,
			fmt.Sprintf("%d", export.TopErrorPathCount),
			export.Classification,
		}) //nolint:errcheck
	}

	return nil
}

func exportJSON(data []clientExport, outputFile string) error {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(outputFile, jsonBytes, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

func exportErrorDetails(stats *trafficStats, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	writer.Write([]string{
		"client_ip", "entity_id", "display_name", "error_type", "path", "timestamp",
	}) //nolint:errcheck

	// Collect all error instances
	var allErrors []detailedErrorExport
	for clientIP, cs := range stats.clients {
		for _, ei := range cs.errorInstances {
			allErrors = append(allErrors, detailedErrorExport{
				ClientIP:    clientIP,
				EntityID:    ei.EntityID,
				DisplayName: ei.DisplayName,
				ErrorType:   ei.ErrorType,
				Path:        ei.Path,
				Timestamp:   ei.Timestamp,
			})
		}
	}

	// Sort by timestamp (most recent first)
	sort.Slice(allErrors, func(i, j int) bool {
		return allErrors[i].Timestamp > allErrors[j].Timestamp
	})

	// Write records
	for _, export := range allErrors {
		writer.Write([]string{
			export.ClientIP,
			export.EntityID,
			export.DisplayName,
			export.ErrorType,
			export.Path,
			export.Timestamp,
		}) //nolint:errcheck
	}

	return nil
}
