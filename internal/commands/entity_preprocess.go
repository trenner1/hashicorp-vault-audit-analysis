// Package commands provides subcommands for vault audit analysis.
package commands

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/audit"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/output"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/processor"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/utils"
)

// RunEntityPreprocess extracts entity mappings from audit logs and exports them.
func RunEntityPreprocess(logFiles []string, outputFlag, format string) error {
	fmt.Fprintln(os.Stderr, "Preprocessing audit logs...")
	fmt.Fprintln(os.Stderr, "Extracting entity → display_name mappings from login events...")

	// Generate timestamped filename if relative path
	var outputFile string
	if filepath.IsAbs(outputFlag) {
		outputFile = outputFlag
	} else {
		base := strings.TrimSuffix(outputFlag, filepath.Ext(outputFlag))
		ext := filepath.Ext(outputFlag)
		if ext == "" {
			ext = ".json" // default extension
		}
		outputFile = output.GenerateTimestampedFilename(base, ext)
	}

	type preprocessState struct {
		entityMap map[string]EntityMapping
	}

	result, _, err := processor.RunFiles(
		processor.DefaultConfig(),
		logFiles,
		func() preprocessState {
			return preprocessState{
				entityMap: make(map[string]EntityMapping),
			}
		},
		func(entry *audit.AuditEntry, s *preprocessState) {
			// Look for login events in auth paths
			path := entry.Path()
			if !entry.PathStartsWith("auth/") || !strings.HasSuffix(path, "/login") {
				return
			}

			if entry.Request == nil || entry.Request.Path == nil {
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

			// Extract mount path from auth path
			mountPath := trimSuffixes(path, "/login", "/"+displayName)

			mountAccessor := ""
			if entry.Auth.Accessor != nil {
				mountAccessor = *entry.Auth.Accessor
			}

			username := entry.MetadataString("username")

			// Update or insert entity mapping
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
		func(a, b preprocessState) preprocessState {
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
		return err
	}

	entityMap := result.entityMap

	fmt.Fprintf(os.Stderr, "\nTotal: Processed %s entities\n\n", utils.FormatNumber(len(entityMap)))

	// Ensure output directory exists
	if err := output.EnsureOutputDir(outputFile); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write output based on format
	fmt.Fprintf(os.Stderr, "Writing entity mappings to: %s\n", outputFile)

	switch strings.ToLower(format) {
	case "json":
		file, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(entityMap); err != nil {
			return fmt.Errorf("failed to write JSON output: %w", err)
		}

		fmt.Fprintln(os.Stderr, "JSON entity mapping file created successfully!")

	case "csv":
		file, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()

		writer := csv.NewWriter(file)
		defer writer.Flush()

		// Write header
		header := []string{
			"entity_id", "display_name", "mount_path", "mount_accessor",
			"username", "login_count", "first_seen", "last_seen",
		}
		if err := writer.Write(header); err != nil {
			return fmt.Errorf("failed to write CSV header: %w", err)
		}

		// Write entity data
		for entityID, mapping := range entityMap {
			record := []string{
				entityID,
				mapping.DisplayName,
				mapping.MountPath,
				mapping.MountAccessor,
				mapping.Username,
				fmt.Sprintf("%d", mapping.LoginCount),
				mapping.FirstSeen,
				mapping.LastSeen,
			}
			if err := writer.Write(record); err != nil {
				return fmt.Errorf("failed to write CSV record: %w", err)
			}
		}

		fmt.Fprintln(os.Stderr, "CSV entity mapping file created successfully!")

	default:
		return fmt.Errorf("invalid format '%s'. Use 'csv' or 'json'", format)
	}

	// Write metadata file
	meta := output.FileMetadata{
		Command:     "entity-analysis",
		Subcommand:  "preprocess",
		Description: fmt.Sprintf("Entity mappings extracted from audit logs (%s entities)", utils.FormatNumber(len(entityMap))),
		InputFiles:  logFiles,
	}
	if err := output.WriteMetadata(outputFile, meta); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Failed to write metadata: %v\n", err)
	}

	fmt.Fprintf(os.Stderr, "Usage with client-activity command:\n")
	fmt.Fprintf(os.Stderr, "  vault-audit client-activity --start <START> --end <END> --entity-map %s\n", outputFile)

	return nil
}
