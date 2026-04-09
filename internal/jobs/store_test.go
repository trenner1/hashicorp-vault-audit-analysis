package jobs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeJob(id, status string) *Job {
	return &Job{
		ID:        id,
		Command:   "system-overview",
		Args:      []string{"file.log"},
		Status:    status,
		Output:    []string{"line 1", "line 2"},
		ExitCode:  0,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func TestNewStore_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "jobs")
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil store")
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Errorf("dir %q was not created", dir)
	}
}

func TestStore_SaveAndLoad(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	job := makeJob("job-001", "done")
	if err := s.Save(job); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := s.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("LoadAll returned %d jobs, want 1", len(loaded))
	}
	if loaded[0].ID != "job-001" {
		t.Errorf("loaded ID = %q, want job-001", loaded[0].ID)
	}
	if loaded[0].Status != "done" {
		t.Errorf("loaded Status = %q, want done", loaded[0].Status)
	}
}

func TestStore_SaveOverwrite(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	job := makeJob("job-001", "running")
	s.Save(job) //nolint:errcheck

	job.Status = "done"
	job.ExitCode = 0
	s.Save(job) //nolint:errcheck

	loaded, _ := s.LoadAll()
	if len(loaded) != 1 {
		t.Fatalf("want 1 job, got %d", len(loaded))
	}
	if loaded[0].Status != "done" {
		t.Errorf("overwrite failed: status = %q, want done", loaded[0].Status)
	}
}

func TestStore_Delete(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	s.Save(makeJob("job-001", "done"))   //nolint:errcheck
	s.Save(makeJob("job-002", "error"))  //nolint:errcheck

	if err := s.Delete("job-001"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	loaded, _ := s.LoadAll()
	if len(loaded) != 1 {
		t.Fatalf("after delete: want 1 job, got %d", len(loaded))
	}
	if loaded[0].ID != "job-002" {
		t.Errorf("wrong job survived: %q", loaded[0].ID)
	}
}

func TestStore_DeleteNonExistent(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	// Should not return an error for a missing file.
	if err := s.Delete("does-not-exist"); err != nil {
		t.Errorf("Delete missing file = %v, want nil", err)
	}
}

func TestStore_LoadAllEmpty(t *testing.T) {
	s, _ := NewStore(t.TempDir())
	loaded, err := s.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll on empty store: %v", err)
	}
	if len(loaded) != 0 {
		t.Errorf("empty store LoadAll returned %d items", len(loaded))
	}
}

func TestStore_LoadAllSkipsCorrupt(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)

	// Write a valid job.
	s.Save(makeJob("good", "done")) //nolint:errcheck

	// Write a corrupt JSON file.
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{not json"), 0644) //nolint:errcheck

	loaded, err := s.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(loaded) != 1 {
		t.Errorf("want 1 valid job, got %d", len(loaded))
	}
}

func TestStore_LoadAllCleansTmpFiles(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)

	// Simulate a leftover .tmp file from a crashed write.
	tmpPath := filepath.Join(dir, "orphan.tmp")
	os.WriteFile(tmpPath, []byte("partial"), 0644) //nolint:errcheck

	s.LoadAll() //nolint:errcheck

	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error(".tmp file was not cleaned up by LoadAll")
	}
}
