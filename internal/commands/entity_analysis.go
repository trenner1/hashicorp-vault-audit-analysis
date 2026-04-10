// Package commands provides subcommands for vault audit analysis.
package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/audit"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/processor"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/utils"
)

// EntityMapping represents entity-to-display-name mappings extracted from audit logs.
type EntityMapping struct {
	DisplayName   string `json:"display_name"`
	MountPath     string `json:"mount_path"`
	MountAccessor string `json:"mount_accessor"`
	Username      string `json:"username,omitempty"`
	LoginCount    int    `json:"login_count"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
}

// buildEntityMap extracts entity mappings from audit log files.
func buildEntityMap(logFiles []string) (map[string]EntityMapping, error) {
	type state struct {
		entityMap map[string]EntityMapping
	}

	result, _, err := processor.RunFiles(
		processor.DefaultConfig(),
		logFiles,
		func() state {
			return state{entityMap: make(map[string]EntityMapping)}
		},
		func(entry *audit.AuditEntry, s *state) {
			// Look for login events in auth paths
			path := entry.Path()
			if !entry.PathStartsWith("auth/") || !pathContains(path, "/login") {
				return
			}

			if entry.Auth == nil || entry.Auth.EntityID == nil {
				return
			}

			entityID := *entry.Auth.EntityID
			if entityID == "" {
				return
			}

			displayName := ""
			if entry.Auth.DisplayName != nil {
				displayName = *entry.Auth.DisplayName
			}
			if displayName == "" {
				return
			}

			// Extract mount path (e.g., "auth/github/login" -> "auth/github")
			mountPath := trimSuffixes(path, "/login", "/"+displayName)

			mountAccessor := ""
			if entry.Auth.Accessor != nil {
				mountAccessor = *entry.Auth.Accessor
			}

			username := ""
			if entry.MetadataString("username") != "" {
				username = entry.MetadataString("username")
			}

			if mapping, exists := s.entityMap[entityID]; exists {
				mapping.LoginCount++
				mapping.LastSeen = entry.Time
				s.entityMap[entityID] = mapping
			} else {
				s.entityMap[entityID] = EntityMapping{
					DisplayName:   displayName,
					MountPath:     mountPath,
					MountAccessor: mountAccessor,
					Username:      username,
					LoginCount:    1,
					FirstSeen:     entry.Time,
					LastSeen:      entry.Time,
				}
			}
		},
		func(a, b state) state {
			// Merge entity maps
			for id, mapping := range b.entityMap {
				if existing, ok := a.entityMap[id]; ok {
					existing.LoginCount += mapping.LoginCount
					existing.LastSeen = mapping.LastSeen
					a.entityMap[id] = existing
				} else {
					a.entityMap[id] = mapping
				}
			}
			return a
		},
	)

	if err != nil {
		return nil, err
	}

	return result.entityMap, nil
}

// writeTempEntityMap writes entity mappings to a temporary JSON file.
func writeTempEntityMap(entityMap map[string]EntityMapping) (string, error) {
	tempPath := fmt.Sprintf(".vault-audit-autopreprocess-%d.json", os.Getpid())

	data, err := json.MarshalIndent(entityMap, "", "  ")
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return "", err
	}

	return tempPath, nil
}

// RunChurn performs entity churn analysis with auto-preprocessing.
func RunChurn(logFiles []string, entityMap, baseline, output, format *string, autoPreprocess bool) error {
	var tempMapFile string

	// Auto-preprocessing: build entity map in-memory and write to temp file
	if autoPreprocess && (entityMap == nil || *entityMap == "") {
		fmt.Fprintln(os.Stderr, "Auto-preprocessing: Building entity mappings in-memory...")
		entityMapData, err := buildEntityMap(logFiles)
		if err != nil {
			return err
		}
		tempPath, err := writeTempEntityMap(entityMapData)
		if err != nil {
			return err
		}
		tempMapFile = tempPath
		fmt.Fprintln(os.Stderr, "Entity mappings ready")
	}

	// Use provided map or auto-generated temp map
	var mapToUse *string
	if entityMap != nil && *entityMap != "" {
		mapToUse = entityMap
	} else if tempMapFile != "" {
		mapToUse = &tempMapFile
	}

	// Delegate to entity_churn implementation
	err := RunEntityChurn(logFiles, mapToUse, baseline, output, format)

	// Cleanup temp file
	if tempMapFile != "" {
		_ = os.Remove(tempMapFile)
	}

	return err
}

// RunCreation performs entity creation analysis with auto-preprocessing.
func RunCreation(logFiles []string, entityMap, output *string, autoPreprocess bool) error {
	var tempMapFile string

	// Auto-preprocessing: build entity map in-memory and write to temp file
	if autoPreprocess && (entityMap == nil || *entityMap == "") {
		fmt.Fprintln(os.Stderr, "Auto-preprocessing: Building entity mappings in-memory...")
		entityMapData, err := buildEntityMap(logFiles)
		if err != nil {
			return err
		}
		tempPath, err := writeTempEntityMap(entityMapData)
		if err != nil {
			return err
		}
		tempMapFile = tempPath
		fmt.Fprintln(os.Stderr, "Entity mappings ready")
	}

	// Use provided map or auto-generated temp map
	var mapToUse *string
	if entityMap != nil && *entityMap != "" {
		mapToUse = entityMap
	} else if tempMapFile != "" {
		mapToUse = &tempMapFile
	}

	// Delegate to entity_creation implementation
	err := RunEntityCreation(logFiles, mapToUse, output)

	// Cleanup temp file
	if tempMapFile != "" {
		_ = os.Remove(tempMapFile)
	}

	return err
}

// RunPreprocess extracts and exports entity mappings.
func RunPreprocess(logFiles []string, output, format string) error {
	return RunEntityPreprocess(logFiles, output, format)
}

// RunGaps detects activity gaps for entities.
func RunGaps(logFiles []string, windowSeconds uint64) error {
	return RunEntityGaps(logFiles, windowSeconds)
}

// RunTimeline shows chronological activity for a specific entity.
func RunTimeline(logFiles []string, entityID string, displayName *string) error {
	return RunEntityTimeline(logFiles, entityID, displayName)
}

// Helper functions

func pathContains(path, substr string) bool {
	for i := 0; i <= len(path)-len(substr); i++ {
		if path[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func trimSuffixes(s string, suffixes ...string) string {
	for _, suffix := range suffixes {
		if len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix {
			return s[:len(s)-len(suffix)]
		}
	}
	return s
}

// loadEntityMappingsFromFile loads entity mappings from JSON or CSV file.
func loadEntityMappingsFromFile(path string) (map[string]EntityMapping, error) {
	// Try JSON first
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var mappings map[string]EntityMapping
	if err := json.Unmarshal(data, &mappings); err == nil {
		return mappings, nil
	}

	// If JSON fails, could also try CSV, but for now just fail
	return nil, fmt.Errorf("failed to parse entity mappings from %s", path)
}

// loadBaselineEntities loads entity baseline from JSON file.
type baselineEntity struct {
	EntityID      string `json:"entity_id"`
	EntityName    string `json:"entity_name"`
	EntityCreated string `json:"entity_created"`
	AliasName     string `json:"alias_name"`
	MountPath     string `json:"mount_path"`
	MountType     string `json:"mount_type"`
	MountAccessor string `json:"mount_accessor"`
}

func (b *baselineEntity) getName() string {
	if b.EntityName != "" {
		return b.EntityName
	}
	return b.AliasName
}

func loadBaselineEntities(path string) (map[string]baselineEntity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entities []baselineEntity
	if err := json.Unmarshal(data, &entities); err != nil {
		return nil, err
	}

	result := make(map[string]baselineEntity)
	for _, e := range entities {
		if _, exists := result[e.EntityID]; !exists {
			result[e.EntityID] = e
		}
	}
	return result, nil
}

// parseTime parses RFC3339 timestamp strings.
func parseTime(ts string) time.Time {
	t, err := utils.ParseTimestamp(ts)
	if err != nil {
		return time.Time{}
	}
	return t
}
