package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/vault"
)

// RoleEntry represents a role/user within an auth mount with metadata.
type RoleEntry struct {
	Name                 string                 `json:"name"`
	Policies             []string               `json:"policies,omitempty"`
	TokenTTL             string                 `json:"token_ttl,omitempty"`
	TokenMaxTTL          string                 `json:"token_max_ttl,omitempty"`
	BoundServiceAccounts []string               `json:"bound_service_accounts,omitempty"`
	BoundNamespaces      []string               `json:"bound_namespaces,omitempty"`
	Metadata             map[string]interface{} `json:"metadata,omitempty"`
	Children             []RoleEntry            `json:"children,omitempty"`
}

// AuthMountOutput represents a single auth mount with its configuration.
type AuthMountOutput struct {
	Path            string      `json:"path"`
	AuthType        string      `json:"auth_type"`
	Description     string      `json:"description"`
	Accessor        string      `json:"accessor"`
	Local           bool        `json:"local"`
	SealWrap        bool        `json:"seal_wrap"`
	DefaultLeaseTTL string      `json:"default_lease_ttl"`
	MaxLeaseTTL     string      `json:"max_lease_ttl"`
	Roles           []RoleEntry `json:"roles,omitempty"`
}

// RunAuthMounts queries Vault for auth mounts and optionally enumerates roles.
//
// Lists all auth mounts from /v1/sys/auth and optionally lists roles/users
// within each mount depending on the depth parameter. Outputs CSV, JSON,
// or a visual tree representation.
func RunAuthMounts(
	vaultAddr, vaultToken, vaultNamespace *string,
	insecure bool,
	output *string,
	format string,
	maxDepth int,
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

	fmt.Fprintf(os.Stderr, "Querying Vault API for auth mounts...\n")
	fmt.Fprintf(os.Stderr, "   Vault Address: %s\n", client.Addr())

	// Query /sys/auth
	var response map[string]interface{}
	if err := client.Get("/v1/sys/auth", &response); err != nil {
		return fmt.Errorf("failed to query /v1/sys/auth: %w", err)
	}

	// Extract the data field
	var mountsData map[string]interface{}
	if dataRaw, ok := response["data"]; ok {
		if data, ok := dataRaw.(map[string]interface{}); ok {
			mountsData = data
		}
	}
	if mountsData == nil {
		// Fallback: if no data field, use response directly
		mountsData = response
	}

	var authMounts []AuthMountOutput

	for path, mountRaw := range mountsData {
		// Skip metadata fields
		if path == "request_id" || path == "lease_id" || path == "renewable" ||
			path == "lease_duration" || path == "data" || path == "wrap_info" ||
			path == "warnings" || path == "auth" {
			continue
		}

		// Parse mount info
		mountInfo, ok := mountRaw.(map[string]interface{})
		if !ok {
			continue
		}

		authType := ""
		if t, ok := mountInfo["type"].(string); ok {
			authType = t
		}

		description := ""
		if d, ok := mountInfo["description"].(string); ok {
			description = d
		}

		accessor := ""
		if a, ok := mountInfo["accessor"].(string); ok {
			accessor = a
		}

		local := false
		if l, ok := mountInfo["local"].(bool); ok {
			local = l
		}

		sealWrap := false
		if sw, ok := mountInfo["seal_wrap"].(bool); ok {
			sealWrap = sw
		}

		// Extract lease TTLs from config
		defaultLeaseStr := "0s"
		maxLeaseStr := "0s"

		if configRaw, ok := mountInfo["config"]; ok {
			if config, ok := configRaw.(map[string]interface{}); ok {
				if defTTL, ok := config["default_lease_ttl"].(float64); ok {
					defaultLeaseStr = strconv.FormatInt(int64(defTTL), 10) + "s"
				}
				if maxTTL, ok := config["max_lease_ttl"].(float64); ok {
					maxLeaseStr = strconv.FormatInt(int64(maxTTL), 10) + "s"
				}
			}
		}

		// Enumerate roles/users if depth > 0
		var roles []RoleEntry
		if maxDepth > 0 {
			enumerated, _ := enumerateAuthConfigs(client, path, authType, maxDepth)
			roles = enumerated
		}

		authMounts = append(authMounts, AuthMountOutput{
			Path:            path,
			AuthType:        authType,
			Description:     description,
			Accessor:        accessor,
			Local:           local,
			SealWrap:        sealWrap,
			DefaultLeaseTTL: defaultLeaseStr,
			MaxLeaseTTL:     maxLeaseStr,
			Roles:           roles,
		})
	}

	fmt.Fprintf(os.Stderr, "Found %d auth mounts\n", len(authMounts))

	// Output results based on format
	switch strings.ToLower(format) {
	case "json":
		jsonBytes, err := json.MarshalIndent(authMounts, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal json: %w", err)
		}

		if output != nil && *output != "" {
			if err := os.WriteFile(*output, jsonBytes, 0644); err != nil {
				return fmt.Errorf("write json file: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Output written to: %s\n", *output)
		} else {
			fmt.Println(string(jsonBytes))
		}

	case "csv":
		csvContent := buildCSVOutput(authMounts)

		if output != nil && *output != "" {
			if err := os.WriteFile(*output, []byte(csvContent), 0644); err != nil {
				return fmt.Errorf("write csv file: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Output written to: %s\n", *output)
		} else {
			fmt.Print(csvContent)
		}

	case "stdout":
		fmt.Println("\nAuth Mounts:")
		fmt.Println(strings.Repeat("=", 80))
		for _, mount := range authMounts {
			fmt.Printf("Path: %s\n", mount.Path)
			fmt.Printf("  Type: %s\n", mount.AuthType)
			fmt.Printf("  Description: %s\n", mount.Description)
			fmt.Printf("  Accessor: %s\n", mount.Accessor)
			fmt.Printf("  Local: %v\n", mount.Local)
			fmt.Printf("  Seal Wrap: %v\n", mount.SealWrap)
			fmt.Printf("  Default Lease TTL: %s\n", mount.DefaultLeaseTTL)
			fmt.Printf("  Max Lease TTL: %s\n", mount.MaxLeaseTTL)

			if len(mount.Roles) > 0 {
				fmt.Printf("  Roles/Users (%d):\n", len(mount.Roles))
				for i, role := range mount.Roles {
					prefix := "├──"
					if i == len(mount.Roles)-1 {
						prefix = "└──"
					}
					fmt.Printf("    %s %s\n", prefix, role.Name)

					// Display role metadata if available
					if len(role.Policies) > 0 {
						fmt.Printf("        Policies: %s\n", strings.Join(role.Policies, ", "))
					}
					if role.TokenTTL != "" {
						fmt.Printf("        Token TTL: %s\n", role.TokenTTL)
					}
					if role.TokenMaxTTL != "" {
						fmt.Printf("        Token Max TTL: %s\n", role.TokenMaxTTL)
					}
					if len(role.BoundServiceAccounts) > 0 {
						fmt.Printf("        Bound Service Accounts: %s\n", strings.Join(role.BoundServiceAccounts, ", "))
					}
					if len(role.BoundNamespaces) > 0 {
						fmt.Printf("        Bound Namespaces: %s\n", strings.Join(role.BoundNamespaces, ", "))
					}
				}
			}
			fmt.Println()
		}

	default:
		return fmt.Errorf("invalid format %q; must be one of: csv, json, stdout", format)
	}

	return nil
}

// buildCSVOutput generates CSV with mount info repeated for each role.
func buildCSVOutput(mounts []AuthMountOutput) string {
	var sb strings.Builder
	sb.WriteString("path,type,description,accessor,role_name,depth\n")

	for _, mount := range mounts {
		// Write mount itself
		sb.WriteString(fmt.Sprintf(`"%s","%s","%s","%s","",0`+"\n",
			escapeCSVField(mount.Path),
			mount.AuthType,
			escapeCSVField(mount.Description),
			mount.Accessor,
		))

		// Write each role
		for _, role := range mount.Roles {
			sb.WriteString(fmt.Sprintf(`"%s","%s","%s","%s","%s",1`+"\n",
				escapeCSVField(mount.Path),
				mount.AuthType,
				escapeCSVField(mount.Description),
				mount.Accessor,
				escapeCSVField(role.Name),
			))
		}
	}

	return sb.String()
}

// escapeCSVField escapes special characters in CSV fields.
func escapeCSVField(field string) string {
	return strings.ReplaceAll(field, `"`, `""`)
}

// enumerateAuthConfigs lists roles/users based on auth type.
func enumerateAuthConfigs(
	client *vault.Client,
	mountPath string,
	authType string,
	depth int,
) ([]RoleEntry, error) {
	if depth == 0 {
		return nil, nil
	}

	switch authType {
	case "kubernetes":
		return listK8sRoles(client, mountPath)
	case "approle":
		return listApproleRoles(client, mountPath)
	case "userpass":
		return listUserpassUsers(client, mountPath)
	case "jwt", "oidc":
		return listJWTRoles(client, mountPath)
	case "ldap":
		return listLDAPConfig(client, mountPath)
	default:
		return nil, nil
	}
}

// listK8sRoles lists roles for kubernetes auth mount with metadata.
func listK8sRoles(client *vault.Client, mountPath string) ([]RoleEntry, error) {
	listPath := fmt.Sprintf("/v1/auth/%s/role", strings.TrimRight(mountPath, "/"))

	var resp map[string]interface{}
	if err := client.List(listPath, &resp); err != nil {
		return nil, nil
	}

	var roles []RoleEntry
	if dataRaw, ok := resp["data"]; ok {
		if data, ok := dataRaw.(map[string]interface{}); ok {
			if keysRaw, ok := data["keys"]; ok {
				if keys, ok := keysRaw.([]interface{}); ok {
					for _, k := range keys {
						if name, ok := k.(string); ok {
							role := RoleEntry{Name: name}
							// Fetch role metadata
							fetchK8sRoleMetadata(client, mountPath, name, &role)
							roles = append(roles, role)
						}
					}
				}
			}
		}
	}
	return roles, nil
}

// fetchK8sRoleMetadata fetches detailed metadata for a kubernetes role.
func fetchK8sRoleMetadata(client *vault.Client, mountPath, roleName string, role *RoleEntry) {
	rolePath := fmt.Sprintf("/v1/auth/%s/role/%s", strings.TrimRight(mountPath, "/"), roleName)

	var roleResp map[string]interface{}
	if err := client.Get(rolePath, &roleResp); err != nil {
		return
	}

	if dataRaw, ok := roleResp["data"]; ok {
		if data, ok := dataRaw.(map[string]interface{}); ok {
			// Extract policies
			if policiesRaw, ok := data["policies"]; ok {
				if policies, ok := policiesRaw.([]interface{}); ok {
					for _, p := range policies {
						if policy, ok := p.(string); ok {
							role.Policies = append(role.Policies, policy)
						}
					}
				}
			}

			// Extract token TTLs
			if ttl, ok := data["token_ttl"].(float64); ok {
				role.TokenTTL = fmt.Sprintf("%ds", int64(ttl))
			}
			if maxTTL, ok := data["token_max_ttl"].(float64); ok {
				role.TokenMaxTTL = fmt.Sprintf("%ds", int64(maxTTL))
			}

			// Extract bound service accounts
			if saRaw, ok := data["bound_service_account_names"]; ok {
				if sa, ok := saRaw.([]interface{}); ok {
					for _, s := range sa {
						if account, ok := s.(string); ok {
							role.BoundServiceAccounts = append(role.BoundServiceAccounts, account)
						}
					}
				}
			}

			// Extract bound namespaces
			if nsRaw, ok := data["bound_service_account_namespaces"]; ok {
				if ns, ok := nsRaw.([]interface{}); ok {
					for _, n := range ns {
						if namespace, ok := n.(string); ok {
							role.BoundNamespaces = append(role.BoundNamespaces, namespace)
						}
					}
				}
			}

			// Store remaining metadata
			role.Metadata = make(map[string]interface{})
			for key, value := range data {
				if key != "policies" && key != "token_ttl" && key != "token_max_ttl" &&
					key != "bound_service_account_names" && key != "bound_service_account_namespaces" {
					role.Metadata[key] = value
				}
			}
		}
	}
}

// listApproleRoles lists roles for approle auth mount with metadata.
func listApproleRoles(client *vault.Client, mountPath string) ([]RoleEntry, error) {
	listPath := fmt.Sprintf("/v1/auth/%s/role", strings.TrimRight(mountPath, "/"))

	var resp map[string]interface{}
	if err := client.List(listPath, &resp); err != nil {
		return nil, nil
	}

	var roles []RoleEntry
	if dataRaw, ok := resp["data"]; ok {
		if data, ok := dataRaw.(map[string]interface{}); ok {
			if keysRaw, ok := data["keys"]; ok {
				if keys, ok := keysRaw.([]interface{}); ok {
					for _, k := range keys {
						if name, ok := k.(string); ok {
							role := RoleEntry{Name: name}
							// Fetch role metadata
							fetchApproleMetadata(client, mountPath, name, &role)
							roles = append(roles, role)
						}
					}
				}
			}
		}
	}
	return roles, nil
}

// fetchApproleMetadata fetches detailed metadata for an approle role.
func fetchApproleMetadata(client *vault.Client, mountPath, roleName string, role *RoleEntry) {
	rolePath := fmt.Sprintf("/v1/auth/%s/role/%s", strings.TrimRight(mountPath, "/"), roleName)

	var roleResp map[string]interface{}
	if err := client.Get(rolePath, &roleResp); err != nil {
		return
	}

	if dataRaw, ok := roleResp["data"]; ok {
		if data, ok := dataRaw.(map[string]interface{}); ok {
			// Extract policies
			if policiesRaw, ok := data["policies"]; ok {
				if policies, ok := policiesRaw.([]interface{}); ok {
					for _, p := range policies {
						if policy, ok := p.(string); ok {
							role.Policies = append(role.Policies, policy)
						}
					}
				}
			}

			// Extract token TTLs
			if ttl, ok := data["token_ttl"].(float64); ok {
				role.TokenTTL = fmt.Sprintf("%ds", int64(ttl))
			}
			if maxTTL, ok := data["token_max_ttl"].(float64); ok {
				role.TokenMaxTTL = fmt.Sprintf("%ds", int64(maxTTL))
			}

			// Store remaining metadata
			role.Metadata = make(map[string]interface{})
			for key, value := range data {
				if key != "policies" && key != "token_ttl" && key != "token_max_ttl" {
					role.Metadata[key] = value
				}
			}
		}
	}
}

// listUserpassUsers lists users for userpass auth mount with metadata.
func listUserpassUsers(client *vault.Client, mountPath string) ([]RoleEntry, error) {
	listPath := fmt.Sprintf("/v1/auth/%s/users", strings.TrimRight(mountPath, "/"))

	var resp map[string]interface{}
	if err := client.List(listPath, &resp); err != nil {
		return nil, nil
	}

	var users []RoleEntry
	if dataRaw, ok := resp["data"]; ok {
		if data, ok := dataRaw.(map[string]interface{}); ok {
			if keysRaw, ok := data["keys"]; ok {
				if keys, ok := keysRaw.([]interface{}); ok {
					for _, k := range keys {
						if name, ok := k.(string); ok {
							user := RoleEntry{Name: name}
							// Fetch user metadata
							fetchUserpassMetadata(client, mountPath, name, &user)
							users = append(users, user)
						}
					}
				}
			}
		}
	}
	return users, nil
}

// fetchUserpassMetadata fetches detailed metadata for a userpass user.
func fetchUserpassMetadata(client *vault.Client, mountPath, username string, user *RoleEntry) {
	userPath := fmt.Sprintf("/v1/auth/%s/users/%s", strings.TrimRight(mountPath, "/"), username)

	var userResp map[string]interface{}
	if err := client.Get(userPath, &userResp); err != nil {
		return
	}

	if dataRaw, ok := userResp["data"]; ok {
		if data, ok := dataRaw.(map[string]interface{}); ok {
			// Extract policies
			if policiesRaw, ok := data["policies"]; ok {
				if policies, ok := policiesRaw.([]interface{}); ok {
					for _, p := range policies {
						if policy, ok := p.(string); ok {
							user.Policies = append(user.Policies, policy)
						}
					}
				}
			}

			// Extract token TTLs
			if ttl, ok := data["token_ttl"].(float64); ok {
				user.TokenTTL = fmt.Sprintf("%ds", int64(ttl))
			}
			if maxTTL, ok := data["token_max_ttl"].(float64); ok {
				user.TokenMaxTTL = fmt.Sprintf("%ds", int64(maxTTL))
			}

			// Store remaining metadata
			user.Metadata = make(map[string]interface{})
			for key, value := range data {
				if key != "policies" && key != "token_ttl" && key != "token_max_ttl" && key != "password" {
					user.Metadata[key] = value
				}
			}
		}
	}
}

// listJWTRoles lists roles for JWT/OIDC auth mount with metadata.
func listJWTRoles(client *vault.Client, mountPath string) ([]RoleEntry, error) {
	listPath := fmt.Sprintf("/v1/auth/%s/role", strings.TrimRight(mountPath, "/"))

	var resp map[string]interface{}
	if err := client.List(listPath, &resp); err != nil {
		return nil, nil
	}

	var roles []RoleEntry
	if dataRaw, ok := resp["data"]; ok {
		if data, ok := dataRaw.(map[string]interface{}); ok {
			if keysRaw, ok := data["keys"]; ok {
				if keys, ok := keysRaw.([]interface{}); ok {
					for _, k := range keys {
						if name, ok := k.(string); ok {
							role := RoleEntry{Name: name}
							// Fetch role metadata
							fetchJWTRoleMetadata(client, mountPath, name, &role)
							roles = append(roles, role)
						}
					}
				}
			}
		}
	}
	return roles, nil
}

// fetchJWTRoleMetadata fetches detailed metadata for a JWT/OIDC role.
func fetchJWTRoleMetadata(client *vault.Client, mountPath, roleName string, role *RoleEntry) {
	rolePath := fmt.Sprintf("/v1/auth/%s/role/%s", strings.TrimRight(mountPath, "/"), roleName)

	var roleResp map[string]interface{}
	if err := client.Get(rolePath, &roleResp); err != nil {
		return
	}

	if dataRaw, ok := roleResp["data"]; ok {
		if data, ok := dataRaw.(map[string]interface{}); ok {
			// Extract policies
			if policiesRaw, ok := data["policies"]; ok {
				if policies, ok := policiesRaw.([]interface{}); ok {
					for _, p := range policies {
						if policy, ok := p.(string); ok {
							role.Policies = append(role.Policies, policy)
						}
					}
				}
			}

			// Extract token TTLs
			if ttl, ok := data["token_ttl"].(float64); ok {
				role.TokenTTL = fmt.Sprintf("%ds", int64(ttl))
			}
			if maxTTL, ok := data["token_max_ttl"].(float64); ok {
				role.TokenMaxTTL = fmt.Sprintf("%ds", int64(maxTTL))
			}

			// Store remaining metadata
			role.Metadata = make(map[string]interface{})
			for key, value := range data {
				if key != "policies" && key != "token_ttl" && key != "token_max_ttl" {
					role.Metadata[key] = value
				}
			}
		}
	}
}

// listLDAPConfig lists users and groups for LDAP auth mount.
func listLDAPConfig(client *vault.Client, mountPath string) ([]RoleEntry, error) {
	usersPath := fmt.Sprintf("/v1/auth/%s/users", strings.TrimRight(mountPath, "/"))
	groupsPath := fmt.Sprintf("/v1/auth/%s/groups", strings.TrimRight(mountPath, "/"))

	var entries []RoleEntry

	// Try to list users
	var usersResp map[string]interface{}
	if err := client.List(usersPath, &usersResp); err == nil {
		if dataRaw, ok := usersResp["data"]; ok {
			if data, ok := dataRaw.(map[string]interface{}); ok {
				if keysRaw, ok := data["keys"]; ok {
					if keys, ok := keysRaw.([]interface{}); ok {
						for _, k := range keys {
							if name, ok := k.(string); ok {
								entries = append(entries, RoleEntry{
									Name: "user:" + name,
								})
							}
						}
					}
				}
			}
		}
	}

	// Try to list groups
	var groupsResp map[string]interface{}
	if err := client.List(groupsPath, &groupsResp); err == nil {
		if dataRaw, ok := groupsResp["data"]; ok {
			if data, ok := dataRaw.(map[string]interface{}); ok {
				if keysRaw, ok := data["keys"]; ok {
					if keys, ok := keysRaw.([]interface{}); ok {
						for _, k := range keys {
							if name, ok := k.(string); ok {
								entries = append(entries, RoleEntry{
									Name: "group:" + name,
								})
							}
						}
					}
				}
			}
		}
	}

	// Sort for consistency
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	return entries, nil
}
