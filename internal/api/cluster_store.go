package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// clusterStore persists clusters as a single JSON file.
// It is safe for concurrent use.
type clusterStore struct {
	mu   sync.Mutex
	path string
}

func newClusterStore(dir string) (*clusterStore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("cluster store: create dir %q: %w", dir, err)
	}
	return &clusterStore{path: filepath.Join(dir, "clusters.json")}, nil
}

// load reads clusters from disk. Returns an empty map if the file doesn't exist.
func (cs *clusterStore) load() (map[string]*Cluster, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	data, err := os.ReadFile(cs.path)
	if os.IsNotExist(err) {
		return make(map[string]*Cluster), nil
	}
	if err != nil {
		return nil, fmt.Errorf("cluster store: read %q: %w", cs.path, err)
	}

	var clusters map[string]*Cluster
	if err := json.Unmarshal(data, &clusters); err != nil {
		return nil, fmt.Errorf("cluster store: parse %q: %w", cs.path, err)
	}
	if clusters == nil {
		clusters = make(map[string]*Cluster)
	}
	return clusters, nil
}

// save atomically writes the full cluster map to disk.
func (cs *clusterStore) save(clusters map[string]*Cluster) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	data, err := json.MarshalIndent(clusters, "", "  ")
	if err != nil {
		return fmt.Errorf("cluster store: marshal: %w", err)
	}
	tmp := cs.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("cluster store: write tmp: %w", err)
	}
	if err := os.Rename(tmp, cs.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("cluster store: rename: %w", err)
	}
	return nil
}
