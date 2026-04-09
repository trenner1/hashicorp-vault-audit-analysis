// Command server provides a REST API for vault-audit analysis.
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/api"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/jobs"
)

func main() {
	// Read environment variables
	port := getEnv("PORT", "8080")
	binaryPath := getEnv("VAULT_AUDIT_BINARY", "./vault-audit")
	corsOrigins := getEnv("CORS_ORIGINS", "*")
	uploadDir := getEnv("UPLOAD_DIR", "./uploads")
	dataDir := getEnv("DATA_DIR", "./data")

	// Resolve uploadDir and binaryPath to absolute paths immediately so that
	// all downstream consumers (file listing API, job args, child process CWD)
	// see consistent absolute paths regardless of how the server was started.
	if abs, err := filepath.Abs(uploadDir); err == nil {
		uploadDir = abs
	}
	if abs, err := filepath.Abs(binaryPath); err == nil {
		binaryPath = abs
	}
	if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs
	}
	anthropicKey := os.Getenv("ANTHROPIC_API_KEY")
	apiKey := os.Getenv("API_KEY")

	maxConcurrent := 5
	if v := os.Getenv("MAX_CONCURRENT_JOBS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			maxConcurrent = n
		}
	}

	// Validate port is a valid number
	if _, err := strconv.Atoi(port); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid PORT: %v\n", err)
		os.Exit(1)
	}

	// Create job queue and SSE broker
	broker := jobs.NewBroker()
	queue := jobs.NewQueue(broker)
	queue.SetBinaryPath(binaryPath)
	queue.SetMaxConcurrent(maxConcurrent)
	// CWD for child processes = uploads dir so relative output files (e.g.
	// entity_mappings.json) land where the Files API can see them.
	queue.SetWorkDir(uploadDir)

	// Attach persistent store — non-fatal if unavailable
	jobsDir := filepath.Join(dataDir, "jobs")
	if store, err := jobs.NewStore(jobsDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not init job store (%v) — running without persistence\n", err)
	} else {
		queue.SetStore(store)
		fmt.Printf("Job store: %s\n", jobsDir)
	}

	// Create API server
	server := api.New(queue, broker)
	server.SetUploadDir(uploadDir)
	if err := server.SetDataDir(filepath.Join(dataDir, "config")); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not init config store (%v) — clusters won't persist\n", err)
	} else {
		fmt.Printf("Config store: %s\n", filepath.Join(dataDir, "config"))
	}
	if anthropicKey != "" {
		server.SetAnthropicKey(anthropicKey)
		fmt.Println("Anthropic API key: set (agentic queries enabled)")
	} else {
		fmt.Println("Anthropic API key: not set (agentic queries disabled)")
	}
	if apiKey != "" {
		server.SetAPIKey(apiKey)
		fmt.Println("API authentication: enabled")
	} else {
		fmt.Println("API authentication: disabled (set API_KEY to enable)")
	}

	// Log startup
	fmt.Printf("Starting REST API server on port %s\n", port)
	fmt.Printf("Vault audit binary: %s\n", binaryPath)
	fmt.Printf("Upload directory: %s\n", uploadDir)
	fmt.Printf("CORS origins: %s\n", corsOrigins)
	fmt.Printf("Data directory: %s\n", dataDir)
	if maxConcurrent > 0 {
		fmt.Printf("Max concurrent jobs: %d\n", maxConcurrent)
	} else {
		fmt.Println("Max concurrent jobs: unlimited")
	}

	// Start HTTP server
	addr := ":" + port
	if err := http.ListenAndServe(addr, server); err != nil { // nosemgrep: go.lang.security.audit.net.use-tls.use-tls
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// getEnv returns the value of an environment variable, or a default if not set.
func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
