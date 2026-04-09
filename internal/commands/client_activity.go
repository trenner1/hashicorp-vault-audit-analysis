// Package commands contains executable command implementations.
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

// ActivityRecord represents a single activity record from Vault API.
type ActivityRecord struct {
	ClientID         string `json:"client_id"`
	ClientType       string `json:"client_type"`
	MountAccessor    string `json:"mount_accessor"`
	MountPath        string `json:"mount_path"`
	MountType        string `json:"mount_type"`
	EntityAliasName  string `json:"entity_alias_name"`
}

// EntityMapping represents entity metadata from the entity map.
// MountActivity represents aggregated activity for a mount.
type MountActivity struct {
	Mount    string `json:"mount"`
	Type     string `json:"type"`
	Accessor string `json:"accessor"`
	Total    int    `json:"total"`
	Entity   int    `json:"entity"`
	NonEntity int   `json:"non_entity"`
}

// mountActivityData tracks clients for a mount during aggregation.
type mountActivityData struct {
	mount          string
	mountType      string
	accessor       string
	role           string
	totalClients   map[string]bool
	entityClients  map[string]bool
	nonEntityClients map[string]bool
}

// RunClientActivity queries Vault API for client activity and outputs results.
//
// Queries /v1/sys/internal/counters/activity/export to fetch client usage metrics,
// then outputs CSV or JSON with client counts grouped by mount.
func RunClientActivity(
	start, end string,
	vaultAddr, vaultToken, vaultNamespace *string,
	insecure bool,
	groupByRole bool,
	entityMap *string,
	output *string,
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

	fmt.Fprintf(os.Stderr, "=== Vault Client Activity Analysis ===\n")
	fmt.Fprintf(os.Stderr, "Vault Address: %s\n", client.Addr())
	fmt.Fprintf(os.Stderr, "Time Window: %s to %s\n", start, end)
	if insecure {
		fmt.Fprintf(os.Stderr, "⚠️  TLS certificate verification is DISABLED\n")
	}
	fmt.Fprintf(os.Stderr, "\n")

	// Load entity mappings if provided
	var entityMapData map[string]EntityMapping
	if entityMap != nil && *entityMap != "" {
		fmt.Fprintf(os.Stderr, "Loading entity mappings from: %s\n", *entityMap)
		data, err := loadEntityMapJSON(*entityMap)
		if err != nil {
			return fmt.Errorf("load entity map: %w", err)
		}
		entityMapData = data
		fmt.Fprintf(os.Stderr, "Loaded %d entity mappings\n", len(entityMapData))
	}

	// Build mount lookup map
	fmt.Fprintf(os.Stderr, "Fetching mount information...\n")
	mountMap, err := fetchMountMap(client)
	if err != nil {
		return fmt.Errorf("fetch mount map: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Found %d mounts\n", len(mountMap))

	// Fetch activity export
	fmt.Fprintf(os.Stderr, "Fetching client activity data...\n")
	exportPath := fmt.Sprintf("/v1/sys/internal/counters/activity/export?start_time=%s&end_time=%s", start, end)

	exportText, err := client.GetRaw(exportPath)
	if err != nil {
		return fmt.Errorf("get activity export: %w", err)
	}

	// Parse NDJSON (newline-delimited JSON)
	var records []ActivityRecord
	for _, line := range strings.Split(exportText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var record ActivityRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		records = append(records, record)
	}

	if len(records) == 0 {
		fmt.Fprintf(os.Stderr, "No activity data found for the specified time range.\n")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Processing %s activity records...\n", utils.FormatNumber(len(records)))

	// Group by mount and count unique clients
	mountActivities := make(map[string]*mountActivityData)

	for _, record := range records {
		accessor := record.MountAccessor
		if accessor == "" {
			accessor = "unknown"
		}

		// Look up mount info
		var mountPath, mountType string
		if info, ok := mountMap[accessor]; ok {
			mountPath = info[0]
			mountType = info[1]
		} else {
			mountPath = record.MountPath
			if mountPath == "" {
				mountPath = "unknown"
			}
			mountType = record.MountType
			if mountType == "" {
				mountType = "unknown"
			}
		}

		// Extract role/appcode if grouping by role
		var role string
		if groupByRole {
			if record.EntityAliasName != "" {
				role = record.EntityAliasName
			} else if len(entityMapData) > 0 {
				if mapping, ok := entityMapData[record.ClientID]; ok {
					role = mapping.DisplayName
				}
			}
		}

		// Create unique key based on grouping mode
		var key string
		if groupByRole {
			if role == "" {
				role = "unknown"
			}
			key = fmt.Sprintf("%s|%s|%s|%s", mountPath, mountType, accessor, role)
		} else {
			key = fmt.Sprintf("%s|%s|%s", mountPath, mountType, accessor)
		}

		// Get or create activity entry
		if _, ok := mountActivities[key]; !ok {
			mountActivities[key] = &mountActivityData{
				mount:             mountPath,
				mountType:         mountType,
				accessor:          accessor,
				role:              role,
				totalClients:      make(map[string]bool),
				entityClients:     make(map[string]bool),
				nonEntityClients:  make(map[string]bool),
			}
		}

		activity := mountActivities[key]
		activity.totalClients[record.ClientID] = true

		if record.ClientType == "entity" {
			activity.entityClients[record.ClientID] = true
		} else {
			activity.nonEntityClients[record.ClientID] = true
		}
	}

	// Convert to output format
	var results []MountActivity
	for _, data := range mountActivities {
		// Concatenate mount + role if grouping by role
		mountDisplay := data.mount
		if groupByRole && data.role != "" {
			mountDisplay = data.mount + " / " + data.role
		}

		results = append(results, MountActivity{
			Mount:     mountDisplay,
			Type:      data.mountType,
			Accessor:  data.accessor,
			Total:     len(data.totalClients),
			Entity:    len(data.entityClients),
			NonEntity: len(data.nonEntityClients),
		})
	}

	// Sort by mount path
	sort.Slice(results, func(i, j int) bool {
		return results[i].Mount < results[j].Mount
	})

	// Calculate totals
	totalClients := 0
	totalEntity := 0
	totalNonEntity := 0
	for _, r := range results {
		totalClients += r.Total
		totalEntity += r.Entity
		totalNonEntity += r.NonEntity
	}

	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "=== Summary ===\n")
	fmt.Fprintf(os.Stderr, "Total Clients: %s\n", utils.FormatNumber(totalClients))
	fmt.Fprintf(os.Stderr, "  Entity Clients: %s\n", utils.FormatNumber(totalEntity))
	fmt.Fprintf(os.Stderr, "  Non-Entity Clients: %s\n", utils.FormatNumber(totalNonEntity))
	fmt.Fprintf(os.Stderr, "Mounts Analyzed: %d\n", len(results))
	fmt.Fprintf(os.Stderr, "\n")

	// Output results
	if output != nil && *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()

		w := csv.NewWriter(f)
		w.Write([]string{"mount", "type", "accessor", "total", "entity", "non_entity"})
		for _, r := range results {
			w.Write([]string{
				r.Mount,
				r.Type,
				r.Accessor,
				fmt.Sprintf("%d", r.Total),
				fmt.Sprintf("%d", r.Entity),
				fmt.Sprintf("%d", r.NonEntity),
			})
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return fmt.Errorf("write csv: %w", err)
		}
		fmt.Fprintf(os.Stderr, "CSV written to: %s\n", *output)
	} else {
		// JSON output to stdout
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal json: %w", err)
		}
		fmt.Println(string(data))
	}

	return nil
}

// fetchMountMap builds a map of mount accessor to (path, type).
func fetchMountMap(client *vault.Client) (map[string][2]string, error) {
	mountMap := make(map[string][2]string)

	// Try /sys/mounts (secret engines)
	var mountsResp map[string]interface{}
	if err := client.Get("/v1/sys/mounts", &mountsResp); err == nil {
		if dataRaw, ok := mountsResp["data"]; ok {
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
	}

	// Try /sys/auth (auth methods)
	var authResp map[string]interface{}
	if err := client.Get("/v1/sys/auth", &authResp); err == nil {
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
	}

	return mountMap, nil
}

// loadEntityMapJSON loads entity mappings from a JSON file.
func loadEntityMapJSON(path string) (map[string]EntityMapping, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var result map[string]EntityMapping
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result, nil
}
