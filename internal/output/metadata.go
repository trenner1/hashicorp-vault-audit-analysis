// Package output provides utilities for managing analysis output files with metadata.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileMetadata contains information about an analysis output file.
type FileMetadata struct {
	Command     string    `json:"command"`
	Subcommand  string    `json:"subcommand,omitempty"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	InputFiles  []string  `json:"input_files,omitempty"`
	Flags       []string  `json:"flags,omitempty"`
}

// GenerateTimestampedFilename creates a unique filename with timestamp.
// Example: "kv_analysis" -> "kv_analysis_20260411_032841.csv"
func GenerateTimestampedFilename(base, ext string) string {
	timestamp := time.Now().Format("20060102_150405")
	return fmt.Sprintf("%s_%s%s", base, timestamp, ext)
}

// WriteMetadata writes a .meta.json file alongside the output file.
func WriteMetadata(outputPath string, meta FileMetadata) error {
	metaPath := outputPath + ".meta.json"

	file, err := os.Create(metaPath)
	if err != nil {
		return fmt.Errorf("failed to create metadata file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(meta); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	return nil
}

// EnsureOutputDir creates the output directory if it doesn't exist.
func EnsureOutputDir(outputPath string) error {
	if outputPath == "" {
		return nil
	}

	dir := filepath.Dir(outputPath)
	if dir == "." || dir == "" {
		return nil
	}

	return os.MkdirAll(dir, 0755)
}

// Made with Bob
