package commands

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/utils"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/vault"
)

// EntityListResponse is returned by the /v1/identity/entity/id endpoint.
type EntityListResponse struct {
	Keys []string `json:"keys"`
}

// AliasData represents an alias within an entity.
type AliasData struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	MountAccessor   string            `json:"mount_accessor"`
	CreationTime    string            `json:"creation_time"`
	LastUpdateTime  string            `json:"last_update_time"`
	Metadata        map[string]string `json:"metadata"`
}

// EntityData represents a complete entity with its aliases.
type EntityData struct {
	ID              string       `json:"id"`
	Name            string       `json:"name"`
	Disabled        bool         `json:"disabled"`
	CreationTime    string       `json:"creation_time"`
	LastUpdateTime  string       `json:"last_update_time"`
	Aliases         []AliasData  `json:"aliases"`
}

// EntityOutput is the flattened output record.
type EntityOutput struct {
	EntityID        string `json:"entity_id"`
	EntityName      string `json:"entity_name"`
	EntityDisabled  bool   `json:"entity_disabled"`
	EntityCreated   string `json:"entity_created"`
	EntityUpdated   string `json:"entity_updated"`
	AliasID         string `json:"alias_id"`
	AliasName       string `json:"alias_name"`
	MountPath       string `json:"mount_path"`
	MountType       string `json:"mount_type"`
	MountAccessor   string `json:"mount_accessor"`
	AliasCreated    string `json:"alias_created"`
	AliasUpdated    string `json:"alias_updated"`
	AliasMetadata   string `json:"alias_metadata"`
}

// RunEntityList queries Vault for entities and their aliases.
//
// Lists all entities from /v1/identity/entity/id, fetches detailed information
// for each, and outputs CSV or JSON with flattened entity/alias records.
func RunEntityList(
	vaultAddr, vaultToken, vaultNamespace *string,
	insecure bool,
	output *string,
	format string,
	mount *string,
) error {
	// Build Vault client options
	opts := vault.Options{SkipVerify: insecure}
	if vaultAddr != nil {
		opts.Addr = *vaultAddr
	}
	if vaultToken != nil {
		opts.Token = *vaultToken
	}
	if vaultNamespace != nil {
		opts.Namespace = *vaultNamespace
	}

	client, err := vault.NewFromOptions(opts)
	if err != nil {
		return fmt.Errorf("create vault client: %w", err)
	}

	fmt.Fprintf(os.Stderr, "=== Vault Entity Analysis ===\n")
	fmt.Fprintf(os.Stderr, "Vault Address: %s\n", client.Addr())
	if mount != nil && *mount != "" {
		fmt.Fprintf(os.Stderr, "Filtering by mount: %s\n", *mount)
	}
	if insecure {
		fmt.Fprintf(os.Stderr, "⚠️  TLS certificate verification is DISABLED\n")
	}
	fmt.Fprintf(os.Stderr, "\n")

	// Build mount lookup map
	fmt.Fprintf(os.Stderr, "Building mount map...\n")
	mountMap, err := fetchAuthMountMap(client)
	if err != nil {
		return fmt.Errorf("fetch auth mount map: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Found %d auth mounts\n", len(mountMap))

	// List all entity IDs
	fmt.Fprintf(os.Stderr, "Fetching entity list...\n")
	var listResp map[string]interface{}
	if err := client.Get("/v1/identity/entity/id?list=true", &listResp); err != nil {
		return fmt.Errorf("list entities: %w", err)
	}

	var entityList EntityListResponse
	if dataRaw, ok := listResp["data"]; ok {
		data, _ := json.Marshal(dataRaw)
		json.Unmarshal(data, &entityList)
	}

	entityCount := len(entityList.Keys)
	fmt.Fprintf(os.Stderr, "Found %d entities\n", utils.FormatNumber(entityCount))
	fmt.Fprintf(os.Stderr, "\n")

	// Fetch each entity's details
	fmt.Fprintf(os.Stderr, "Fetching entity details...\n")
	var entitiesData []EntityData
	processed := 0

	for _, entityID := range entityList.Keys {
		processed++
		if processed%100 == 0 || processed == entityCount {
			fmt.Fprintf(os.Stderr, "\rProcessing entity %d/%d...", processed, entityCount)
		}

		entityPath := fmt.Sprintf("/v1/identity/entity/id/%s", entityID)
		var entityResp map[string]interface{}
		if err := client.Get(entityPath, &entityResp); err != nil {
			continue
		}

		var entity EntityData
		if dataRaw, ok := entityResp["data"]; ok {
			data, _ := json.Marshal(dataRaw)
			json.Unmarshal(data, &entity)
			entitiesData = append(entitiesData, entity)
		}
	}
	fmt.Fprintf(os.Stderr, "\n\n")

	// Convert to output format
	var outputRows []EntityOutput

	for _, entity := range entitiesData {
		entityName := entity.Name
		entityCreated := entity.CreationTime
		entityUpdated := entity.LastUpdateTime

		if len(entity.Aliases) > 0 {
			var filteredAliases []AliasData
			for _, alias := range entity.Aliases {
				filteredAliases = append(filteredAliases, alias)
			}

			// Apply mount filter if specified
			if mount != nil && *mount != "" {
				var filtered []AliasData
				for _, alias := range filteredAliases {
					if info, ok := mountMap[alias.MountAccessor]; ok {
						if info[0] == *mount {
							filtered = append(filtered, alias)
						}
					}
				}
				filteredAliases = filtered
			}

			// Skip if filtered and no matching aliases
			if len(filteredAliases) == 0 && mount != nil && *mount != "" {
				continue
			}

			for _, alias := range filteredAliases {
				mountPath := "unknown"
				mountType := "unknown"
				if info, ok := mountMap[alias.MountAccessor]; ok {
					mountPath = info[0]
					mountType = info[1]
				}

				// Format metadata
				var metadataStr string
				if len(alias.Metadata) > 0 {
					var pairs []string
					for k, v := range alias.Metadata {
						pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
					}
					sort.Strings(pairs)
					metadataStr = strings.Join(pairs, "; ")
				}

				outputRows = append(outputRows, EntityOutput{
					EntityID:       entity.ID,
					EntityName:     entityName,
					EntityDisabled: entity.Disabled,
					EntityCreated:  entityCreated,
					EntityUpdated:  entityUpdated,
					AliasID:        alias.ID,
					AliasName:      alias.Name,
					MountPath:      mountPath,
					MountType:      mountType,
					MountAccessor:  alias.MountAccessor,
					AliasCreated:   alias.CreationTime,
					AliasUpdated:   alias.LastUpdateTime,
					AliasMetadata:  metadataStr,
				})
			}
		} else if mount == nil || *mount == "" {
			// Include entities with no aliases only if not filtering
			outputRows = append(outputRows, EntityOutput{
				EntityID:       entity.ID,
				EntityName:     entityName,
				EntityDisabled: entity.Disabled,
				EntityCreated:  entityCreated,
				EntityUpdated:  entityUpdated,
			})
		}
	}

	// Print summary
	fmt.Fprintf(os.Stderr, "=== Summary ===\n")
	fmt.Fprintf(os.Stderr, "Total entities: %s\n", utils.FormatNumber(len(entitiesData)))
	fmt.Fprintf(os.Stderr, "Total aliases: %s\n", utils.FormatNumber(len(outputRows)))
	fmt.Fprintf(os.Stderr, "\n")

	// Count aliases by mount
	mountCounts := make(map[string]int)
	for _, row := range outputRows {
		if row.MountPath != "" {
			mountCounts[row.MountPath]++
		}
	}

	if len(mountCounts) > 0 {
		fmt.Fprintf(os.Stderr, "Aliases by mount:\n")
		type kv struct {
			Key   string
			Value int
		}
		var counts []kv
		for k, v := range mountCounts {
			counts = append(counts, kv{k, v})
		}
		sort.Slice(counts, func(i, j int) bool {
			return counts[i].Value > counts[j].Value
		})
		for _, pair := range counts {
			fmt.Fprintf(os.Stderr, "  %s: %s\n", pair.Key, utils.FormatNumber(pair.Value))
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	// Output results
	if output != nil && *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()

		switch strings.ToLower(format) {
		case "json":
			encoder := json.NewEncoder(f)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(outputRows); err != nil {
				return fmt.Errorf("write json: %w", err)
			}
			fmt.Fprintf(os.Stderr, "JSON written to: %s\n", *output)

		case "csv":
			w := csv.NewWriter(f)
			w.Write([]string{
				"entity_id", "entity_name", "entity_disabled", "entity_created", "entity_updated",
				"alias_id", "alias_name", "mount_path", "mount_type", "mount_accessor",
				"alias_created", "alias_updated", "alias_metadata",
			})
			for _, row := range outputRows {
				w.Write([]string{
					row.EntityID,
					row.EntityName,
					fmt.Sprintf("%v", row.EntityDisabled),
					row.EntityCreated,
					row.EntityUpdated,
					row.AliasID,
					row.AliasName,
					row.MountPath,
					row.MountType,
					row.MountAccessor,
					row.AliasCreated,
					row.AliasUpdated,
					row.AliasMetadata,
				})
			}
			w.Flush()
			if err := w.Error(); err != nil {
				return fmt.Errorf("write csv: %w", err)
			}
			fmt.Fprintf(os.Stderr, "CSV written to: %s\n", *output)

		default:
			return fmt.Errorf("invalid format %q; use 'csv' or 'json'", format)
		}
	} else {
		// No output file - print to stdout based on format
		switch strings.ToLower(format) {
		case "json":
			data, err := json.MarshalIndent(outputRows, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal json: %w", err)
			}
			fmt.Println(string(data))

		case "csv":
			w := csv.NewWriter(os.Stdout)
			w.Write([]string{
				"entity_id", "entity_name", "entity_disabled", "entity_created", "entity_updated",
				"alias_id", "alias_name", "mount_path", "mount_type", "mount_accessor",
				"alias_created", "alias_updated", "alias_metadata",
			})
			for _, row := range outputRows {
				w.Write([]string{
					row.EntityID,
					row.EntityName,
					fmt.Sprintf("%v", row.EntityDisabled),
					row.EntityCreated,
					row.EntityUpdated,
					row.AliasID,
					row.AliasName,
					row.MountPath,
					row.MountType,
					row.MountAccessor,
					row.AliasCreated,
					row.AliasUpdated,
					row.AliasMetadata,
				})
			}
			w.Flush()
			if err := w.Error(); err != nil {
				return fmt.Errorf("write csv: %w", err)
			}

		default:
			return fmt.Errorf("invalid format %q; use 'csv' or 'json'", format)
		}
	}

	return nil
}

// fetchAuthMountMap builds a map of mount accessor to (path, type).
func fetchAuthMountMap(client *vault.Client) (map[string][2]string, error) {
	mountMap := make(map[string][2]string)

	var authResp map[string]interface{}
	if err := client.Get("/v1/sys/auth", &authResp); err != nil {
		return mountMap, nil // Tolerate error, just return empty map
	}

	if dataRaw, ok := authResp["data"]; ok {
		if data, ok := dataRaw.(map[string]interface{}); ok {
			for path, infoRaw := range data {
				if info, ok := infoRaw.(map[string]interface{}); ok {
					if accessor, ok := info["accessor"].(string); ok {
						mountType := "unknown"
						if t, ok := info["type"].(string); ok {
							mountType = t
						}
						mountMap[accessor] = [2]string{path, mountType}
					}
				}
			}
		}
	}

	return mountMap, nil
}
