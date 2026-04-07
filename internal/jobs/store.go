package jobs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Store persists jobs as individual JSON files under a directory.
// Each job is written atomically via a temp-file + rename, so a crash
// mid-write never leaves a corrupt record.
//
// Layout:
//
//	<dir>/
//	  <job-id>.json   — one file per completed or in-progress job
//	  <job-id>.tmp    — transient during write, cleaned up on next load
type Store struct {
	dir string
}

// NewStore creates a Store rooted at dir, creating the directory if needed.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("store: create dir %q: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// Save atomically writes job to disk, overwriting any previous version.
func (s *Store) Save(job *Job) error {
	data, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("store: marshal job %s: %w", job.ID, err)
	}
	tmp := filepath.Join(s.dir, job.ID+".tmp")
	dst := filepath.Join(s.dir, job.ID+".json")
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("store: write tmp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp) // best-effort cleanup
		return fmt.Errorf("store: rename %s→%s: %w", tmp, dst, err)
	}
	return nil
}

// LoadAll reads every *.json file in the store directory and returns the
// jobs it can parse, skipping any corrupt files.
// Any leftover *.tmp files from a previous crashed write are removed.
func (s *Store) LoadAll() ([]*Job, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: read dir %q: %w", s.dir, err)
	}

	var loaded []*Job
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(s.dir, name)

		// Clean up any temp files left by a previous crash.
		if strings.HasSuffix(name, ".tmp") {
			os.Remove(path)
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			continue // skip unreadable files
		}
		var j Job
		if err := json.Unmarshal(data, &j); err != nil {
			continue // skip corrupt JSON
		}
		loaded = append(loaded, &j)
	}
	return loaded, nil
}

// Delete removes a job's JSON file from the store.
// Returns nil if the file did not exist.
func (s *Store) Delete(id string) error {
	path := filepath.Join(s.dir, id+".json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("store: delete job %s: %w", id, err)
	}
	return nil
}
