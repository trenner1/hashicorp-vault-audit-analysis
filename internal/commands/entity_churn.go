// Package commands provides subcommands for vault audit analysis.
package commands

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/audit"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/processor"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/utils"
)

// EntityChurnRecord represents a single entity's churn status.
type EntityChurnRecord struct {
	EntityID              string    `json:"entity_id"`
	DisplayName           string    `json:"display_name"`
	MountPath             string    `json:"mount_path"`
	MountType             string    `json:"mount_type"`
	TokenType             string    `json:"token_type"`
	FirstSeenFile         string    `json:"first_seen_file"`
	FirstSeenTime         time.Time `json:"first_seen_time"`
	LastSeenFile          string    `json:"last_seen_file"`
	LastSeenTime          time.Time `json:"last_seen_time"`
	FilesAppeared         []string  `json:"files_appeared"`
	TotalLogins           int       `json:"total_logins"`
	Lifecycle             string    `json:"lifecycle"`
	ActivityPattern       string    `json:"activity_pattern"`
	IsEphemeralPattern    bool      `json:"is_ephemeral_pattern"`
	EphemeralConfidence   float32   `json:"ephemeral_confidence"`
	EphemeralReasons      []string  `json:"ephemeral_reasons"`
	BaselineEntityName    *string   `json:"baseline_entity_name,omitempty"`
	BaselineCreated       *string   `json:"baseline_created,omitempty"`
	BaselineAliasName     *string   `json:"baseline_alias_name,omitempty"`
	BaselineMount         *string   `json:"baseline_mount_path,omitempty"`
	HistoricalDisplayName *string   `json:"historical_display_name,omitempty"`
	HistoricalFirstSeen   *string   `json:"historical_first_seen,omitempty"`
	HistoricalLastSeen    *string   `json:"historical_last_seen,omitempty"`
	HistoricalLoginCount  *int      `json:"historical_login_count,omitempty"`
}

// DailyStats records statistics for a single log file.
type DailyStats struct {
	FileName          string
	NewEntities       int
	ReturningEntities int
	TotalLogins       int
}

// EphemeralPatternAnalyzer detects ephemeral entities.
type EphemeralPatternAnalyzer struct {
	totalFiles         int
	shortLivedPatterns []ShortLivedPattern
}

// ShortLivedPattern tracks patterns seen in entities that appeared 1-2 days.
type ShortLivedPattern struct {
	daysActive  int
	displayName string
	mountPath   string
}

// NewEphemeralPatternAnalyzer creates a new analyzer.
func NewEphemeralPatternAnalyzer(totalFiles int) *EphemeralPatternAnalyzer {
	return &EphemeralPatternAnalyzer{
		totalFiles:         totalFiles,
		shortLivedPatterns: make([]ShortLivedPattern, 0),
	}
}

// learnFromEntities learns patterns from short-lived entities.
func (e *EphemeralPatternAnalyzer) learnFromEntities(entities map[string]*EntityChurnRecord) {
	for _, entity := range entities {
		daysActive := len(entity.FilesAppeared)
		if daysActive <= 2 {
			e.shortLivedPatterns = append(e.shortLivedPatterns, ShortLivedPattern{
				daysActive:  daysActive,
				displayName: entity.DisplayName,
				mountPath:   entity.MountPath,
			})
		}
	}
}

// analyzeEntity determines ephemeral status for an entity.
func (e *EphemeralPatternAnalyzer) analyzeEntity(entity *EntityChurnRecord) (bool, float32, []string) {
	daysActive := len(entity.FilesAppeared)
	confidence := float32(0.0)
	reasons := make([]string, 0)

	// Strong indicators (high confidence)
	if daysActive == 1 {
		confidence += 0.5
		reasons = append(reasons, fmt.Sprintf("Appeared only 1 day (%s)", entity.FirstSeenFile))
	} else if daysActive == 2 {
		confidence += 0.3
		reasons = append(reasons, fmt.Sprintf("Appeared only 2 days: %s, %s",
			entity.FilesAppeared[0], entity.FilesAppeared[len(entity.FilesAppeared)-1]))
	}

	// Pattern matching
	if daysActive <= 2 {
		similarCount := 0
		for _, p := range e.shortLivedPatterns {
			if p.mountPath == entity.MountPath && p.daysActive <= 2 {
				similarCount++
				continue
			}
			// Check for similar naming pattern (e.g., "github-repo:*")
			if strings.Contains(entity.DisplayName, ":") && strings.Contains(p.displayName, ":") {
				entityPrefix := strings.Split(entity.DisplayName, ":")[0]
				patternPrefix := strings.Split(p.displayName, ":")[0]
				if entityPrefix == patternPrefix && entityPrefix != "" {
					similarCount++
				}
			}
		}

		if similarCount > 5 {
			confidence += 0.2
			reasons = append(reasons, fmt.Sprintf("Matches pattern seen in %d other short-lived entities", similarCount))
		} else if similarCount > 0 {
			confidence += 0.1
			reasons = append(reasons, fmt.Sprintf("Similar to %d other short-lived entities", similarCount))
		}
	}

	// Low activity indicator
	if entity.TotalLogins <= 5 && daysActive <= 2 {
		confidence += 0.1
		reasons = append(reasons, fmt.Sprintf("Low activity: only %d login(s)", entity.TotalLogins))
	}

	// Check for gaps in activity
	if daysActive >= 2 {
		firstDayIdx := extractDayIndex(entity.FilesAppeared[0])
		lastDayIdx := extractDayIndex(entity.FilesAppeared[len(entity.FilesAppeared)-1])

		if firstDayIdx >= 0 && lastDayIdx >= 0 {
			span := lastDayIdx - firstDayIdx + 1
			if span > daysActive {
				confidence *= 0.7
				reasons = append(reasons, "Has gaps in activity (possibly sporadic access, not churned)")
			}
		}
	}

	// Cap confidence
	if confidence > 1.0 {
		confidence = 1.0
	}

	isEphemeral := confidence >= 0.4

	// Add absence indicator
	if isEphemeral && daysActive < e.totalFiles {
		reasons = append(reasons, fmt.Sprintf("Not seen in most recent %d file(s)", e.totalFiles-daysActive))
	}

	return isEphemeral, confidence, reasons
}

// classifyActivityPattern determines the activity pattern for an entity.
func (e *EphemeralPatternAnalyzer) classifyActivityPattern(entity *EntityChurnRecord) string {
	daysActive := len(entity.FilesAppeared)

	if daysActive == 1 {
		return "single_burst"
	}

	if daysActive == e.totalFiles {
		return "consistent"
	}

	if daysActive >= (e.totalFiles*2)/3 {
		return "consistent"
	}

	// Check if activity is declining
	if len(entity.FilesAppeared) > 0 {
		lastFile := entity.FilesAppeared[len(entity.FilesAppeared)-1]
		lastFileNum := extractDayIndex(lastFile)

		if lastFileNum >= 0 && lastFileNum < e.totalFiles/2 {
			return "declining"
		}
	}

	if daysActive <= 2 {
		return "single_burst"
	}

	return "sporadic"
}

// extractDayIndex extracts the day number from a filename like "vault_audit_day_1.log"
func extractDayIndex(filename string) int {
	parts := strings.Split(filename, "_")
	if len(parts) > 0 {
		lastPart := parts[len(parts)-1]
		lastPart = strings.TrimSuffix(lastPart, ".log")
		lastPart = strings.TrimSuffix(lastPart, ".gz")
		lastPart = strings.TrimSuffix(lastPart, ".zst")
		var dayNum int
		_, err := fmt.Sscanf(lastPart, "%d", &dayNum)
		if err == nil {
			return dayNum
		}
	}
	return -1
}

// RunEntityChurn performs entity churn analysis.
func RunEntityChurn(logFiles []string, entityMap, baseline, output, format *string) error {
	// Filter out empty file paths
	var validFiles []string
	for _, f := range logFiles {
		if f != "" {
			validFiles = append(validFiles, f)
		}
	}
	logFiles = validFiles

	if len(logFiles) == 0 {
		return fmt.Errorf("no valid log files provided")
	}

	fmt.Printf("\n=== Multi-Day Entity Churn Analysis ===\n\n")
	fmt.Printf("Analyzing %d log files:\n", len(logFiles))
	for i, file := range logFiles {
		info, err := os.Stat(file)
		var size float64
		if err != nil {
			size = 0
		} else {
			size = float64(info.Size()) / 1_000_000_000.0
		}
		fmt.Printf("  Day %d: %s (%.2f GB)\n", i+1, file, size)
	}
	fmt.Printf("\n")

	// Load baseline entities if provided
	var baselineSet map[string]baselineEntity
	if baseline != nil && *baseline != "" {
		fmt.Printf("Loading baseline entity list from %s...\n", *baseline)
		var err error
		baselineSet, err = loadBaselineEntities(*baseline)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load baseline: %v\n", err)
		} else {
			fmt.Printf("Loaded %s pre-existing entities from baseline\n\n", utils.FormatNumber(len(baselineSet)))
		}
	} else {
		fmt.Printf("No baseline entity list provided. Cannot distinguish truly NEW entities from pre-existing.\n")
		fmt.Printf("   All Day 1 entities will be marked as 'pre_existing_or_new_day_1'.\n\n")
	}

	// Load entity mappings if provided
	var entityMappings map[string]EntityMapping
	if entityMap != nil && *entityMap != "" {
		fmt.Printf("Loading historical entity mappings from %s...\n", *entityMap)
		var err error
		entityMappings, err = loadEntityMappingsFromFile(*entityMap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load entity mappings: %v\n", err)
		} else {
			fmt.Printf("Loaded %s entity mappings with historical data\n\n", utils.FormatNumber(len(entityMappings)))
		}
	}

	// Track all entities across all files
	entities := make(map[string]*EntityChurnRecord)
	var dailyStats []DailyStats

	// Process each log file
	for fileIdx, logFile := range logFiles {
		fileName := filepath.Base(logFile)
		fmt.Fprintf(os.Stderr, "\nProcessing Day %s (%d/%d)...\n", fileName, fileIdx+1, len(logFiles))

		// Check if this is a JSON entity mapping file
		var fileEntities map[string]*EntityChurnRecord
		if strings.HasSuffix(strings.ToLower(logFile), ".json") {
			// Load entity mappings from JSON file
			fmt.Fprintf(os.Stderr, "Detected JSON entity mapping file, loading directly...\n")
			mappings, err := loadEntityMappingsFromFile(logFile)
			if err != nil {
				return fmt.Errorf("failed to load entity mappings from %s: %w", logFile, err)
			}

			// Convert EntityMapping to EntityChurnRecord
			fileEntities = make(map[string]*EntityChurnRecord)
			for entityID, mapping := range mappings {
				firstSeen := parseTime(mapping.FirstSeen)
				lastSeen := parseTime(mapping.LastSeen)

				fileEntities[entityID] = &EntityChurnRecord{
					EntityID:        entityID,
					DisplayName:     mapping.DisplayName,
					MountPath:       mapping.MountPath,
					MountType:       "", // Not available in entity mappings
					TokenType:       "", // Not available in entity mappings
					FirstSeenFile:   fileName,
					FirstSeenTime:   firstSeen,
					LastSeenFile:    fileName,
					LastSeenTime:    lastSeen,
					FilesAppeared:   []string{fileName},
					TotalLogins:     mapping.LoginCount,
					Lifecycle:       "unknown",
					ActivityPattern: "unknown",
				}
			}
			fmt.Fprintf(os.Stderr, "Loaded %s entities from JSON file\n", utils.FormatNumber(len(fileEntities)))
		} else {
			// Process as audit log file
			type churnState struct {
				entities map[string]*EntityChurnRecord
			}

			result, _, err := processor.RunFiles(
				processor.DefaultConfig(),
				[]string{logFile},
				func() churnState {
					return churnState{entities: make(map[string]*EntityChurnRecord)}
				},
				func(entry *audit.AuditEntry, s *churnState) {
					// Only process login operations
					if !entry.PathStartsWith("auth/") || !strings.HasSuffix(entry.Path(), "/login") {
						return
					}

					if entry.Auth == nil || entry.Auth.EntityID == nil {
						return
					}

					entityID := *entry.Auth.EntityID

					displayName := entityID
					if entry.Auth.DisplayName != nil {
						displayName = *entry.Auth.DisplayName
					}

					mountPath := entry.Path()
					mountType := entry.MountType()
					if mountType == "" {
						mountType = "unknown"
					}

					tokenType := ""
					if entry.Auth.TokenType != nil {
						tokenType = *entry.Auth.TokenType
					}

					firstSeenTime := parseTime(entry.Time)

					// Check if entity already seen in this file
					if existing, ok := s.entities[entityID]; ok {
						// Increment login count and update last seen
						existing.TotalLogins++
						existing.LastSeenTime = firstSeenTime
					} else {
						// First time seeing this entity in this file
						s.entities[entityID] = &EntityChurnRecord{
							EntityID:        entityID,
							DisplayName:     displayName,
							MountPath:       mountPath,
							MountType:       mountType,
							TokenType:       tokenType,
							FirstSeenFile:   fileName,
							FirstSeenTime:   firstSeenTime,
							LastSeenFile:    fileName,
							LastSeenTime:    firstSeenTime,
							FilesAppeared:   []string{fileName},
							TotalLogins:     1,
							Lifecycle:       "unknown",
							ActivityPattern: "unknown",
						}
					}
				},
				func(a, b churnState) churnState {
					// Merge state - not used in single-file processing
					return a
				},
			)

			if err != nil {
				return err
			}

			fileEntities = result.entities
		}

		// Update global entities and track daily stats
		newEntitiesThisFile := 0
		returningEntitiesThisFile := 0
		loginsThisFile := 0

		for entityID, record := range fileEntities {
			loginsThisFile += record.TotalLogins

			if existingRecord, ok := entities[entityID]; ok {
				// Returning entity
				existingRecord.TotalLogins += record.TotalLogins
				existingRecord.LastSeenFile = fileName
				existingRecord.LastSeenTime = record.LastSeenTime

				// Add file to list if not already there
				found := false
				for _, f := range existingRecord.FilesAppeared {
					if f == fileName {
						found = true
						break
					}
				}
				if !found {
					existingRecord.FilesAppeared = append(existingRecord.FilesAppeared, fileName)
				}
				returningEntitiesThisFile++
			} else {
				// New entity
				newEntitiesThisFile++

				// Determine lifecycle
				var lifecycle string
				if baselineSet != nil && len(baselineSet) > 0 {
					if _, inBaseline := baselineSet[entityID]; inBaseline {
						lifecycle = "pre_existing_baseline"
					} else {
						lifecycle = fmt.Sprintf("new_day_%d", fileIdx+1)
					}
				} else {
					if fileIdx == 0 {
						lifecycle = "pre_existing_or_new_day_1"
					} else {
						lifecycle = fmt.Sprintf("new_day_%d", fileIdx+1)
					}
				}

				record.Lifecycle = lifecycle

				// Get baseline metadata
				if baselineSet != nil && len(baselineSet) > 0 {
					if baselineEntity, ok := baselineSet[entityID]; ok {
						name := baselineEntity.getName()
						if name != "" {
							record.BaselineEntityName = &name
						}
						if baselineEntity.EntityCreated != "" {
							record.BaselineCreated = &baselineEntity.EntityCreated
						}
						if baselineEntity.AliasName != "" {
							record.BaselineAliasName = &baselineEntity.AliasName
						}
						if baselineEntity.MountPath != "" {
							record.BaselineMount = &baselineEntity.MountPath
						}
					}
				}

				// Get historical data from entity mappings
				if len(entityMappings) > 0 {
					if mapping, ok := entityMappings[entityID]; ok {
						record.HistoricalDisplayName = &mapping.DisplayName
						record.HistoricalFirstSeen = &mapping.FirstSeen
						record.HistoricalLastSeen = &mapping.LastSeen
						record.HistoricalLoginCount = &mapping.LoginCount
					}
				}

				entities[entityID] = record
			}
		}

		dailyStats = append(dailyStats, DailyStats{
			FileName:          fileName,
			NewEntities:       newEntitiesThisFile,
			ReturningEntities: returningEntitiesThisFile,
			TotalLogins:       loginsThisFile,
		})

		fmt.Fprintf(os.Stderr, "Day %d Summary: %s new entities, %s returning, %s logins\n",
			fileIdx+1, utils.FormatNumber(newEntitiesThisFile),
			utils.FormatNumber(returningEntitiesThisFile), utils.FormatNumber(loginsThisFile))
	}

	// SECOND PASS: Analyze patterns and classify entities
	fmt.Printf("\nAnalyzing entity behavior patterns...\n")

	analyzer := NewEphemeralPatternAnalyzer(len(logFiles))
	analyzer.learnFromEntities(entities)
	fmt.Printf("Learned from %s short-lived entity patterns\n", utils.FormatNumber(len(analyzer.shortLivedPatterns)))

	// Classify all entities
	for _, entity := range entities {
		entity.ActivityPattern = analyzer.classifyActivityPattern(entity)
		isEphemeral, confidence, reasons := analyzer.analyzeEntity(entity)
		entity.IsEphemeralPattern = isEphemeral
		entity.EphemeralConfidence = confidence
		entity.EphemeralReasons = reasons
	}

	// Generate report
	fmt.Printf("\n=== Entity Churn Analysis ===\n\n")

	fmt.Printf("Daily Breakdown:\n")
	for idx, stats := range dailyStats {
		fmt.Printf("  Day %d: %s new, %s returning, %s total logins\n",
			idx+1, utils.FormatNumber(stats.NewEntities),
			utils.FormatNumber(stats.ReturningEntities),
			utils.FormatNumber(stats.TotalLogins))
	}

	// Lifecycle classification
	lifecycleCounts := make(map[string]int)
	entitiesByFileCount := make(map[int]int)

	for _, entity := range entities {
		lifecycleCounts[entity.Lifecycle]++
		entitiesByFileCount[len(entity.FilesAppeared)]++
	}

	fmt.Printf("\nEntity Lifecycle Classification:\n")
	var lifecycles []string
	for lc := range lifecycleCounts {
		lifecycles = append(lifecycles, lc)
	}
	sort.Strings(lifecycles)
	for _, lc := range lifecycles {
		fmt.Printf("  %s: %s\n", lc, utils.FormatNumber(lifecycleCounts[lc]))
	}

	fmt.Printf("\nEntity Persistence:\n")
	for dayCount := 1; dayCount <= len(logFiles); dayCount++ {
		if count, ok := entitiesByFileCount[dayCount]; ok {
			label := "Appeared some days"
			if dayCount == 1 {
				label = "Appeared 1 day only"
			} else if dayCount == len(logFiles) {
				label = "Appeared all days (persistent)"
			}
			fmt.Printf("  %d day(s): %s entities (%s)\n", dayCount, utils.FormatNumber(count), label)
		}
	}

	// Activity pattern analysis
	activityPatternCounts := make(map[string]int)
	var ephemeralEntities []*EntityChurnRecord

	for _, entity := range entities {
		activityPatternCounts[entity.ActivityPattern]++
		if entity.IsEphemeralPattern {
			ephemeralEntities = append(ephemeralEntities, entity)
		}
	}

	fmt.Printf("\nActivity Pattern Distribution:\n")
	var patterns []string
	for p := range activityPatternCounts {
		patterns = append(patterns, p)
	}
	sort.Slice(patterns, func(i, j int) bool {
		return activityPatternCounts[patterns[i]] > activityPatternCounts[patterns[j]]
	})
	for _, p := range patterns {
		fmt.Printf("  %s: %s\n", p, utils.FormatNumber(activityPatternCounts[p]))
	}

	fmt.Printf("\nEphemeral Entity Detection:\n")
	fmt.Printf("  Detected %s likely ephemeral entities (confidence >= 0.4)\n", utils.FormatNumber(len(ephemeralEntities)))

	if len(ephemeralEntities) > 0 {
		// Sort by confidence
		sort.Slice(ephemeralEntities, func(i, j int) bool {
			return ephemeralEntities[i].EphemeralConfidence > ephemeralEntities[j].EphemeralConfidence
		})

		fmt.Printf("  Top 10 by confidence:\n")
		for idx, entity := range ephemeralEntities {
			if idx >= 10 {
				break
			}
			fmt.Printf("    %d. %s (confidence: %.1f%%)\n", idx+1, entity.DisplayName, float64(entity.EphemeralConfidence)*100.0)
			for _, reason := range entity.EphemeralReasons {
				fmt.Printf("       - %s\n", reason)
			}
		}

		// Confidence distribution
		highConf := 0
		medConf := 0
		lowConf := 0
		for _, e := range ephemeralEntities {
			if e.EphemeralConfidence >= 0.7 {
				highConf++
			} else if e.EphemeralConfidence >= 0.5 {
				medConf++
			} else if e.EphemeralConfidence >= 0.4 {
				lowConf++
			}
		}

		fmt.Printf("\n  Confidence distribution:\n")
		fmt.Printf("    High (>=70%%): %s\n", utils.FormatNumber(highConf))
		fmt.Printf("    Medium (50-69%%): %s\n", utils.FormatNumber(medConf))
		fmt.Printf("    Low (40-49%%): %s\n", utils.FormatNumber(lowConf))
	}

	// Mount path breakdown
	mountStats := make(map[string]int)
	for _, entity := range entities {
		mountStats[entity.MountPath]++
	}

	fmt.Printf("\nTop Authentication Methods (Total Entities):\n")
	type mountInfo struct {
		path  string
		count int
	}
	var mounts []mountInfo
	for path, count := range mountStats {
		mounts = append(mounts, mountInfo{path, count})
	}
	sort.Slice(mounts, func(i, j int) bool {
		return mounts[i].count > mounts[j].count
	})

	for idx, m := range mounts {
		if idx >= 20 {
			break
		}
		fmt.Printf("  %d. %s: %s\n", idx+1, m.path, utils.FormatNumber(m.count))
	}

	// Export to file if requested
	if output != nil && *output != "" {
		var entityVec []*EntityChurnRecord
		for _, entity := range entities {
			entityVec = append(entityVec, entity)
		}
		sort.Slice(entityVec, func(i, j int) bool {
			return entityVec[i].FirstSeenTime.Before(entityVec[j].FirstSeenTime)
		})

		outputFormat := "json"
		if format != nil && *format != "" {
			outputFormat = *format
		} else if strings.HasSuffix(*output, ".csv") {
			outputFormat = "csv"
		}

		fmt.Printf("\nExporting detailed entity records to %s (format: %s)...\n", *output, outputFormat)

		switch outputFormat {
		case "csv":
			file, err := os.Create(*output)
			if err != nil {
				return err
			}
			defer file.Close()

			writer := csv.NewWriter(file)
			defer writer.Flush()

			// Write header
			header := []string{
				"entity_id", "display_name", "mount_path", "mount_type", "token_type",
				"first_seen_file", "first_seen_time", "last_seen_file", "last_seen_time",
				"files_appeared", "days_active", "total_logins", "lifecycle", "activity_pattern",
				"is_ephemeral_pattern", "ephemeral_confidence", "ephemeral_reasons",
				"baseline_entity_name", "baseline_created", "baseline_alias_name", "baseline_mount_path",
				"historical_display_name", "historical_first_seen", "historical_last_seen", "historical_login_count",
			}
			writer.Write(header)

			for _, entity := range entityVec {
				record := []string{
					entity.EntityID,
					entity.DisplayName,
					entity.MountPath,
					entity.MountType,
					entity.TokenType,
					entity.FirstSeenFile,
					entity.FirstSeenTime.Format(time.RFC3339),
					entity.LastSeenFile,
					entity.LastSeenTime.Format(time.RFC3339),
					strings.Join(entity.FilesAppeared, ", "),
					fmt.Sprintf("%d", len(entity.FilesAppeared)),
					fmt.Sprintf("%d", entity.TotalLogins),
					entity.Lifecycle,
					entity.ActivityPattern,
					fmt.Sprintf("%v", entity.IsEphemeralPattern),
					fmt.Sprintf("%f", entity.EphemeralConfidence),
					strings.Join(entity.EphemeralReasons, "; "),
					stringOrEmpty(entity.BaselineEntityName),
					stringOrEmpty(entity.BaselineCreated),
					stringOrEmpty(entity.BaselineAliasName),
					stringOrEmpty(entity.BaselineMount),
					stringOrEmpty(entity.HistoricalDisplayName),
					stringOrEmpty(entity.HistoricalFirstSeen),
					stringOrEmpty(entity.HistoricalLastSeen),
					intOrEmpty(entity.HistoricalLoginCount),
				}
				writer.Write(record)
			}

		default:
			// JSON
			file, err := os.Create(*output)
			if err != nil {
				return err
			}
			defer file.Close()

			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(entityVec); err != nil {
				return err
			}
		}

		fmt.Printf("Exported %s entity records\n", utils.FormatNumber(len(entityVec)))
	}

	fmt.Printf("\n=== Analysis Complete ===\n\n")
	return nil
}

// Helper functions

func stringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func intOrEmpty(i *int) string {
	if i == nil {
		return ""
	}
	return fmt.Sprintf("%d", *i)
}
