// Package commands provides subcommands for vault audit analysis.
package commands

import (
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

// EntityCreation represents a single entity creation event.
type EntityCreation struct {
	EntityID    string    `json:"entity_id"`
	DisplayName string    `json:"display_name"`
	MountPath   string    `json:"mount_path"`
	MountType   string    `json:"mount_type"`
	FirstSeen   time.Time `json:"first_seen"`
	LoginCount  int       `json:"login_count"`
}

// MountStats tracks statistics per authentication mount.
type MountStats struct {
	MountPath       string
	MountType       string
	EntitiesCreated int
	TotalLogins     int
	SampleEntities  []string
}

// RunEntityCreation analyzes entity creation by authentication path.
func RunEntityCreation(logFiles []string, entityMap, output *string) error {
	fmt.Fprintln(os.Stderr, "Analyzing entity creation by authentication path...")

	// Load entity mappings if provided
	var entityMappings map[string]EntityMapping
	if entityMap != nil && *entityMap != "" {
		fmt.Fprintf(os.Stderr, "Loading entity mappings from: %s\n", *entityMap)
		var err error
		entityMappings, err = loadEntityMappingsFromFile(*entityMap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load entity mappings: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Loaded %s entity mappings for display name enrichment\n\n", utils.FormatNumber(len(entityMappings)))
		}
	}

	type creationState struct {
		entityCreations map[string]*EntityCreation
		seenEntities    map[string]bool
	}

	result, _, err := processor.RunFiles(
		processor.DefaultConfig(),
		logFiles,
		func() creationState {
			return creationState{
				entityCreations: make(map[string]*EntityCreation),
				seenEntities:    make(map[string]bool),
			}
		},
		func(entry *audit.AuditEntry, s *creationState) {
			// Look for login events in auth paths
			path := entry.Path()
			if !entry.PathStartsWith("auth/") || !strings.HasSuffix(path, "/login") {
				return
			}

			if entry.Auth == nil || entry.Auth.EntityID == nil {
				return
			}

			entityID := *entry.Auth.EntityID
			if entityID == "" {
				return
			}

			// Check if this is the first time we've seen this entity
			if _, alreadySeen := s.seenEntities[entityID]; alreadySeen {
				// Increment login count for existing entity
				if creation, ok := s.entityCreations[entityID]; ok {
					creation.LoginCount++
				}
				return
			}

			// First time seeing this entity
			s.seenEntities[entityID] = true

			displayName := entityID
			if entry.Auth.DisplayName != nil && *entry.Auth.DisplayName != "" {
				displayName = *entry.Auth.DisplayName
			} else if mapping, ok := entityMappings[entityID]; ok {
				displayName = mapping.DisplayName
			}

			mountPath := trimSuffixes(path, "/login", "/"+displayName)
			mountType := entry.MountType()
			if mountType == "" {
				mountType = "unknown"
			}

			firstSeen := parseTime(entry.Time)

			s.entityCreations[entityID] = &EntityCreation{
				EntityID:    entityID,
				DisplayName: displayName,
				MountPath:   mountPath,
				MountType:   mountType,
				FirstSeen:   firstSeen,
				LoginCount:  1,
			}
		},
		func(a, b creationState) creationState {
			// Merge creations from multiple files
			for id, creation := range b.entityCreations {
				if existing, ok := a.entityCreations[id]; ok {
					existing.LoginCount += creation.LoginCount
					a.entityCreations[id] = existing
				} else {
					a.entityCreations[id] = creation
					a.seenEntities[id] = true
				}
			}
			return a
		},
	)

	if err != nil {
		return err
	}

	entityCreations := result.entityCreations
	seenCount := len(result.seenEntities)
	loginCount := 0
	for _, creation := range entityCreations {
		loginCount += creation.LoginCount
	}

	fmt.Fprintf(os.Stderr, "\nTotal: %s login events, %s new entities created\n",
		utils.FormatNumber(loginCount), utils.FormatNumber(seenCount))

	// Aggregate by mount path
	mountStats := make(map[string]*MountStats)

	for _, creation := range entityCreations {
		key := creation.MountPath
		if stats, ok := mountStats[key]; ok {
			stats.EntitiesCreated++
			stats.TotalLogins += creation.LoginCount
			if len(stats.SampleEntities) < 5 {
				stats.SampleEntities = append(stats.SampleEntities, creation.DisplayName)
			}
		} else {
			mountStats[key] = &MountStats{
				MountPath:       creation.MountPath,
				MountType:       creation.MountType,
				EntitiesCreated: 1,
				TotalLogins:     creation.LoginCount,
				SampleEntities:  []string{creation.DisplayName},
			}
		}
	}

	// Sort by entities created
	var sortedMounts []*MountStats
	for _, stats := range mountStats {
		sortedMounts = append(sortedMounts, stats)
	}
	sort.Slice(sortedMounts, func(i, j int) bool {
		return sortedMounts[i].EntitiesCreated > sortedMounts[j].EntitiesCreated
	})

	// Print report
	fmt.Fprintf(os.Stderr, "\n%s\n", strings.Repeat("=", 100))
	fmt.Fprintf(os.Stderr, "ENTITY CREATION ANALYSIS BY AUTHENTICATION PATH\n")
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("=", 100))
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Summary:\n")
	fmt.Fprintf(os.Stderr, "  Total login events: %s\n", utils.FormatNumber(loginCount))
	fmt.Fprintf(os.Stderr, "  Unique entities discovered: %s\n", utils.FormatNumber(seenCount))
	fmt.Fprintf(os.Stderr, "  Authentication methods: %s\n", utils.FormatNumber(len(mountStats)))
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 100))
	fmt.Fprintf(os.Stderr, "%-50s %-15s %15s %15s\n", "Authentication Path", "Mount Type", "Entities", "Total Logins")
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 100))

	for _, stats := range sortedMounts {
		displayPath := stats.MountPath
		if len(displayPath) > 49 {
			displayPath = displayPath[:46] + "..."
		}
		displayType := stats.MountType
		if len(displayType) > 14 {
			displayType = displayType[:11] + "..."
		}
		fmt.Fprintf(os.Stderr, "%-50s %-15s %15s %15s\n",
			displayPath, displayType,
			utils.FormatNumber(stats.EntitiesCreated),
			utils.FormatNumber(stats.TotalLogins))
	}

	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 100))
	fmt.Fprintf(os.Stderr, "\n")

	// Show top 10 with sample entities
	fmt.Fprintf(os.Stderr, "Top 10 Authentication Paths with Sample Entities:\n")
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("=", 100))
	for idx, stats := range sortedMounts {
		if idx >= 10 {
			break
		}
		fmt.Fprintf(os.Stderr, "\n%d. %s (%s)\n", idx+1, stats.MountPath, stats.MountType)
		fmt.Fprintf(os.Stderr, "   Entities created: %s | Total logins: %s\n",
			utils.FormatNumber(stats.EntitiesCreated),
			utils.FormatNumber(stats.TotalLogins))
		fmt.Fprintf(os.Stderr, "   Sample entities:\n")
		for j, name := range stats.SampleEntities {
			fmt.Fprintf(os.Stderr, "      %d. %s\n", j+1, name)
		}
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", strings.Repeat("=", 100))

	// Write detailed output if requested
	if output != nil && *output != "" {
		fmt.Fprintf(os.Stderr, "\nWriting detailed entity creation data to: %s\n", *output)

		var entities []*EntityCreation
		for _, creation := range entityCreations {
			entities = append(entities, creation)
		}
		sort.Slice(entities, func(i, j int) bool {
			return entities[i].FirstSeen.Before(entities[j].FirstSeen)
		})

		file, err := os.Create(*output)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(entities); err != nil {
			return fmt.Errorf("failed to write JSON output: %w", err)
		}

		fmt.Fprintf(os.Stderr, "✓ Wrote %s entity records to %s\n",
			utils.FormatNumber(len(entities)), *output)
	}

	return nil
}
