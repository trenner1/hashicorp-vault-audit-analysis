// Package commands provides CLI command implementations.
package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/vault"
)

// pathEntry represents a single entry in the KV mount hierarchy.
type pathEntry struct {
	Path        string      `json:"path"`
	Type        string      `json:"type"` // "folder" or "secret"
	Children    []pathEntry `json:"children,omitempty"`
	CreatedTime *string     `json:"created_time,omitempty"`
	UpdatedTime *string     `json:"updated_time,omitempty"`
}

// kvMountOutput represents a single KV mount with optional children.
type kvMountOutput struct {
	Path        string      `json:"path"`
	MountType   string      `json:"mount_type"`
	Description string      `json:"description"`
	Version     string      `json:"version"`
	Accessor    string      `json:"accessor"`
	Children    []pathEntry `json:"children,omitempty"`
}

// mountInfo represents the response structure for a mount from /sys/mounts.
type mountInfo struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Accessor    string                 `json:"accessor"`
	Config      map[string]interface{} `json:"config"`
	Options     map[string]interface{} `json:"options"`
}

// fetchSecretMetadata fetches created_time and updated_time for a secret.
func fetchSecretMetadata(client *vault.Client, metadataPath string) (*string, *string) {
	fullPath := "/v1/" + metadataPath
	var resp map[string]interface{}

	if err := client.Get(fullPath, &resp); err != nil {
		// Silently ignore errors
		return nil, nil
	}

	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	var created, updated *string

	if c, ok := data["created_time"].(string); ok {
		created = &c
	}

	if u, ok := data["updated_time"].(string); ok {
		updated = &u
	}

	return created, updated
}

// listKVV2Paths recursively lists paths within a KV v2 mount up to a specified depth.
func listKVV2Paths(client *vault.Client, mountPath string, currentDepth, maxDepth int) ([]pathEntry, error) {
	visited := make(map[string]bool)
	return listKVV2PathsWithVisited(client, mountPath, currentDepth, maxDepth, visited)
}

// listKVV2PathsWithVisited recursively lists paths with cycle detection.
func listKVV2PathsWithVisited(client *vault.Client, mountPath string, currentDepth, maxDepth int, visited map[string]bool) ([]pathEntry, error) {
	if currentDepth > maxDepth {
		return []pathEntry{}, nil
	}

	var entries []pathEntry
	mountTrimmed := strings.TrimRight(mountPath, "/")

	// List the root of the mount using LIST method on metadata endpoint
	listPath := fmt.Sprintf("/v1/%s/metadata", mountTrimmed)

	var resp map[string]interface{}
	if err := client.List(listPath, &resp); err != nil {
		// OK if we can't list (might be empty or no permissions)
		return entries, nil
	}

	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		return entries, nil
	}

	keys, ok := data["keys"].([]interface{})
	if !ok {
		return entries, nil
	}

	for _, k := range keys {
		keyStr, ok := k.(string)
		if !ok {
			continue
		}

		isFolder := strings.HasSuffix(keyStr, "/")
		entryType := "secret"
		if isFolder {
			entryType = "folder"
		}

		var createdTime, updatedTime *string

		// For secrets (not folders), fetch metadata
		if !isFolder {
			metadataPath := fmt.Sprintf("%s/metadata/%s", mountTrimmed, keyStr)
			createdTime, updatedTime = fetchSecretMetadata(client, metadataPath)
		}

		var children []pathEntry
		if isFolder && currentDepth < maxDepth {
			relPath := strings.TrimRight(keyStr, "/")
			fullPath := fmt.Sprintf("%s/%s", mountTrimmed, relPath)

			if visited[fullPath] {
				fmt.Fprintf(os.Stderr, "Warning: Detected circular reference at path: %s\n", fullPath)
			} else {
				visited[fullPath] = true
				subChildren, err := listKVV2SubpathWithVisited(client, mountTrimmed, relPath, currentDepth+1, maxDepth, visited)
				if err != nil {
					return nil, err
				}
				children = subChildren
			}
		}

		entries = append(entries, pathEntry{
			Path:        keyStr,
			Type:        entryType,
			Children:    children,
			CreatedTime: createdTime,
			UpdatedTime: updatedTime,
		})
	}

	return entries, nil
}

// listKVV2SubpathWithVisited lists paths within a KV v2 subpath (folder).
func listKVV2SubpathWithVisited(client *vault.Client, mountPath, relPath string, currentDepth, maxDepth int, visited map[string]bool) ([]pathEntry, error) {
	if currentDepth > maxDepth {
		return []pathEntry{}, nil
	}

	var entries []pathEntry
	mountTrimmed := strings.TrimRight(mountPath, "/")

	// For KV v2, the metadata endpoint is /v1/{mount}/metadata/{path}
	listPath := fmt.Sprintf("/v1/%s/metadata/%s", mountTrimmed, relPath)

	var resp map[string]interface{}
	if err := client.List(listPath, &resp); err != nil {
		// Silently ignore list errors for subpaths
		return entries, nil
	}

	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		return entries, nil
	}

	keys, ok := data["keys"].([]interface{})
	if !ok {
		return entries, nil
	}

	for _, k := range keys {
		keyStr, ok := k.(string)
		if !ok {
			continue
		}

		isFolder := strings.HasSuffix(keyStr, "/")
		entryType := "secret"
		if isFolder {
			entryType = "folder"
		}

		var createdTime, updatedTime *string

		// For secrets (not folders), fetch metadata
		if !isFolder {
			metadataPath := fmt.Sprintf("%s/metadata/%s/%s", mountTrimmed, relPath, keyStr)
			createdTime, updatedTime = fetchSecretMetadata(client, metadataPath)
		}

		var children []pathEntry
		if isFolder && currentDepth < maxDepth {
			newRelPath := fmt.Sprintf("%s/%s", relPath, strings.TrimRight(keyStr, "/"))
			fullPath := fmt.Sprintf("%s/%s", mountTrimmed, newRelPath)

			if visited[fullPath] {
				fmt.Fprintf(os.Stderr, "Warning: Detected circular reference at path: %s\n", fullPath)
			} else {
				visited[fullPath] = true
				subChildren, err := listKVV2SubpathWithVisited(client, mountPath, newRelPath, currentDepth+1, maxDepth, visited)
				if err != nil {
					return nil, err
				}
				children = subChildren
			}
		}

		entries = append(entries, pathEntry{
			Path:        keyStr,
			Type:        entryType,
			Children:    children,
			CreatedTime: createdTime,
			UpdatedTime: updatedTime,
		})
	}

	return entries, nil
}

// listKVV1Paths recursively lists paths within a KV v1 mount.
func listKVV1Paths(client *vault.Client, mountPath, subpath string, currentDepth, maxDepth int) ([]pathEntry, error) {
	visited := make(map[string]bool)
	return listKVV1PathsWithVisited(client, mountPath, subpath, currentDepth, maxDepth, visited)
}

// listKVV1PathsWithVisited recursively lists KV v1 paths with cycle detection.
func listKVV1PathsWithVisited(client *vault.Client, mountPath, subpath string, currentDepth, maxDepth int, visited map[string]bool) ([]pathEntry, error) {
	if currentDepth > maxDepth {
		return []pathEntry{}, nil
	}

	var entries []pathEntry
	mountTrimmed := strings.TrimRight(mountPath, "/")

	// For KV v1, use LIST on the mount path directly
	var listPath string
	if subpath == "" {
		listPath = fmt.Sprintf("/v1/%s", mountTrimmed)
	} else {
		listPath = fmt.Sprintf("/v1/%s/%s", mountTrimmed, strings.TrimRight(subpath, "/"))
	}

	var resp map[string]interface{}
	if err := client.List(listPath, &resp); err != nil {
		// If we can't list, that's OK - might be empty or no permissions
		return entries, nil
	}

	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		return entries, nil
	}

	keys, ok := data["keys"].([]interface{})
	if !ok {
		return entries, nil
	}

	for _, k := range keys {
		keyStr, ok := k.(string)
		if !ok {
			continue
		}

		isFolder := strings.HasSuffix(keyStr, "/")
		entryType := "secret"
		if isFolder {
			entryType = "folder"
		}

		var children []pathEntry
		if isFolder && currentDepth < maxDepth {
			var newSubpath string
			if subpath == "" {
				newSubpath = strings.TrimRight(keyStr, "/")
			} else {
				newSubpath = fmt.Sprintf("%s/%s", strings.TrimRight(subpath, "/"), strings.TrimRight(keyStr, "/"))
			}

			fullPath := fmt.Sprintf("%s/%s", mountTrimmed, newSubpath)

			if visited[fullPath] {
				fmt.Fprintf(os.Stderr, "Warning: Detected circular reference at path: %s\n", fullPath)
			} else {
				visited[fullPath] = true
				subChildren, err := listKVV1PathsWithVisited(client, mountPath, newSubpath, currentDepth+1, maxDepth, visited)
				if err != nil {
					return nil, err
				}
				children = subChildren
			}
		}

		// KV v1 doesn't support metadata endpoint, so no timestamps
		entries = append(entries, pathEntry{
			Path:     keyStr,
			Type:     entryType,
			Children: children,
		})
	}

	return entries, nil
}

// flattenPathsToCSV recursively flattens nested path entries to CSV format.
func flattenPathsToCSV(w *strings.Builder, basePath string, entries []pathEntry, depth int) {
	for _, entry := range entries {
		fullPath := basePath + entry.Path
		created := ""
		updated := ""
		if entry.CreatedTime != nil {
			created = *entry.CreatedTime
		}
		if entry.UpdatedTime != nil {
			updated = *entry.UpdatedTime
		}

		fmt.Fprintf(w, "\"%s\",\"%s\",\"%s\",%d,\"%s\",\"%s\"\n",
			strings.ReplaceAll(fullPath, "\"", "\"\""),
			entry.Type,
			strings.ReplaceAll(basePath, "\"", "\"\""),
			depth,
			strings.ReplaceAll(created, "\"", "\"\""),
			strings.ReplaceAll(updated, "\"", "\"\""))

		if len(entry.Children) > 0 {
			newBase := basePath + entry.Path
			flattenPathsToCSV(w, newBase, entry.Children, depth+1)
		}
	}
}

// printTree recursively prints paths in tree format.
func printTree(basePath string, entries []pathEntry, prefix string) {
	for i, entry := range entries {
		isLast := i == len(entries)-1
		connector := "├──"
		if isLast {
			connector = "└──"
		}

		output := fmt.Sprintf("%s%s %s (%s)", prefix, connector, entry.Path, entry.Type)

		// Add timestamps for secrets (if available)
		if entry.Type == "secret" {
			if entry.CreatedTime != nil && entry.UpdatedTime != nil {
				output = fmt.Sprintf("%s [created: %s, updated: %s]", output, *entry.CreatedTime, *entry.UpdatedTime)
			}
		}

		fmt.Println(output)

		if len(entry.Children) > 0 {
			var newPrefix string
			if isLast {
				newPrefix = prefix + "    "
			} else {
				newPrefix = prefix + "│   "
			}
			printTree(basePath, entry.Children, newPrefix)
		}
	}
}

// RunKVMounts discovers and lists all KV mounts and their contents.
func RunKVMounts(vaultAddr, vaultToken, vaultNamespace *string, insecure bool, output *string, format string, maxDepth int) error {
	// Create vault client
	opts := vault.Options{
		SkipVerify: insecure,
	}
	if vaultAddr != nil && *vaultAddr != "" {
		opts.Addr = *vaultAddr
	}
	if vaultToken != nil && *vaultToken != "" {
		opts.Token = *vaultToken
	}
	if vaultNamespace != nil && *vaultNamespace != "" {
		opts.Namespace = *vaultNamespace
	}

	client, err := vault.NewFromOptions(opts)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Querying Vault API for KV mounts...\n")
	fmt.Fprintf(os.Stderr, "   Vault Address: %s\n", client.Addr())

	// Query /sys/mounts to get all secret mounts
	var resp map[string]interface{}
	if err := client.Get("/v1/sys/mounts", &resp); err != nil {
		return fmt.Errorf("failed to query /v1/sys/mounts: %w", err)
	}

	// Extract the data field which contains the actual mounts
	var mountsData map[string]interface{}
	if data, ok := resp["data"].(map[string]interface{}); ok {
		mountsData = data
	} else {
		mountsData = resp
	}

	var kvMounts []kvMountOutput

	for path, mountDataRaw := range mountsData {
		// Skip metadata fields
		if path == "request_id" || path == "lease_id" || path == "renewable" ||
			path == "lease_duration" || path == "data" || path == "wrap_info" ||
			path == "warnings" || path == "auth" {
			continue
		}

		// Parse mount info
		mountBytes, err := json.Marshal(mountDataRaw)
		if err != nil {
			continue
		}

		var mount mountInfo
		if err := json.Unmarshal(mountBytes, &mount); err != nil {
			continue
		}

		// Filter for KV mounts (v1 and v2)
		if mount.Type != "kv" {
			continue
		}

		// Determine version
		version := "1"
		if v, ok := mount.Options["version"].(string); ok {
			version = v
		} else if v, ok := mount.Options["version"].(float64); ok {
			version = fmt.Sprintf("%.0f", v)
		}

		// Traverse paths if depth > 0
		var children []pathEntry
		if maxDepth > 0 {
			if version == "2" {
				var err error
				children, err = listKVV2Paths(client, path, 1, maxDepth)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Failed to traverse KV v2 mount %s: %v\n", path, err)
				}
			} else {
				var err error
				children, err = listKVV1Paths(client, path, "", 1, maxDepth)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Failed to traverse KV v1 mount %s: %v\n", path, err)
				}
			}
		}

		kvMounts = append(kvMounts, kvMountOutput{
			Path:        path,
			MountType:   mount.Type,
			Description: mount.Description,
			Version:     version,
			Accessor:    mount.Accessor,
			Children:    children,
		})
	}

	fmt.Fprintf(os.Stderr, "Found %d KV mounts (v1 and v2)\n", len(kvMounts))

	// Output results based on format
	switch format {
	case "json":
		jsonBytes, err := json.MarshalIndent(kvMounts, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to serialize to JSON: %w", err)
		}

		if output != nil && *output != "" {
			if err := os.WriteFile(*output, jsonBytes, 0644); err != nil {
				return fmt.Errorf("failed to write JSON to file: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Output written to: %s\n", *output)
		} else {
			fmt.Println(string(jsonBytes))
		}

	case "csv":
		var csvOutput strings.Builder

		if maxDepth > 0 {
			csvOutput.WriteString("full_path,type,mount,depth,created_time,updated_time\n")
			for _, mount := range kvMounts {
				// Write mount itself
				fmt.Fprintf(&csvOutput, "\"%s\",\"mount\",\"%s\",0\n",
					strings.ReplaceAll(mount.Path, "\"", "\"\""),
					strings.ReplaceAll(mount.Path, "\"", "\"\""))

				// Write nested paths
				if len(mount.Children) > 0 {
					flattenPathsToCSV(&csvOutput, mount.Path, mount.Children, 1)
				}
			}
		} else {
			csvOutput.WriteString("path,type,description,version,accessor\n")
			for _, mount := range kvMounts {
				fmt.Fprintf(&csvOutput, "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
					strings.ReplaceAll(mount.Path, "\"", "\"\""),
					mount.MountType,
					strings.ReplaceAll(mount.Description, "\"", "\"\""),
					mount.Version,
					mount.Accessor)
			}
		}

		if output != nil && *output != "" {
			if err := os.WriteFile(*output, []byte(csvOutput.String()), 0644); err != nil {
				return fmt.Errorf("failed to write CSV to file: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Output written to: %s\n", *output)
		} else {
			fmt.Print(csvOutput.String())
		}

	case "stdout":
		fmt.Println("\nKV Mounts:")
		fmt.Println(strings.Repeat("=", 80))
		for _, mount := range kvMounts {
			fmt.Printf("Path: %s\n", mount.Path)
			fmt.Printf("  Type: %s\n", mount.MountType)
			fmt.Printf("  Version: %s\n", mount.Version)
			fmt.Printf("  Description: %s\n", mount.Description)
			fmt.Printf("  Accessor: %s\n", mount.Accessor)

			if len(mount.Children) > 0 {
				fmt.Println("  Contents:")
				printTree(mount.Path, mount.Children, "    ")
			}
			fmt.Println()
		}

	default:
		return fmt.Errorf("invalid format: %s. Must be one of: csv, json, stdout", format)
	}

	return nil
}
