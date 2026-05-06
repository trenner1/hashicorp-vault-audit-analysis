package jobs

import (
	"testing"
	"time"
)

// newTestQueue returns a queue with persistence disabled (no store, no real binary).
// Tests that need job execution should set BinaryPath to a real executable.
func newTestQueue() *Queue {
	return NewQueue(NewBroker())
}

func TestQueue_SubmitAndGet(t *testing.T) {
	q := newTestQueue()
	job := q.Submit("system-overview", []string{"file.log"})

	if job == nil {
		t.Fatal("Submit returned nil")
	}
	if job.ID == "" {
		t.Error("job ID should not be empty")
	}
	if job.Command != "system-overview" {
		t.Errorf("Command = %q, want system-overview", job.Command)
	}
	if job.Status != "pending" && job.Status != "running" && job.Status != "done" && job.Status != "error" {
		t.Errorf("unexpected initial status %q", job.Status)
	}

	got, ok := q.Get(job.ID)
	if !ok {
		t.Fatalf("Get(%q) not found", job.ID)
	}
	if got.ID != job.ID {
		t.Errorf("Get returned ID %q, want %q", got.ID, job.ID)
	}
}

func TestQueue_SubmitWithID(t *testing.T) {
	q := newTestQueue()
	job := q.SubmitWithID("custom-id-abc", "path-hotspots", nil)

	if job.ID != "custom-id-abc" {
		t.Errorf("job ID = %q, want custom-id-abc", job.ID)
	}
	_, ok := q.Get("custom-id-abc")
	if !ok {
		t.Error("SubmitWithID job not found via Get")
	}
}

func TestQueue_GetMissing(t *testing.T) {
	q := newTestQueue()
	_, ok := q.Get("does-not-exist")
	if ok {
		t.Error("Get should return false for unknown ID")
	}
}

func TestQueue_List(t *testing.T) {
	q := newTestQueue()
	q.SubmitWithID("j1", "cmd-a", nil)
	q.SubmitWithID("j2", "cmd-b", nil)
	q.SubmitWithID("j3", "cmd-c", nil)

	jobs := q.List()
	if len(jobs) != 3 {
		t.Errorf("List returned %d jobs, want 3", len(jobs))
	}
}

func TestQueue_Stats(t *testing.T) {
	q := newTestQueue()
	// Force job into known state to make stats deterministic.
	q.mu.Lock()
	q.jobs["s1"] = &Job{ID: "s1", Status: "done"}
	q.jobs["s2"] = &Job{ID: "s2", Status: "done"}
	q.jobs["s3"] = &Job{ID: "s3", Status: "error"}
	q.mu.Unlock()

	stats := q.Stats()
	if stats["done"] != 2 {
		t.Errorf("stats[done] = %d, want 2", stats["done"])
	}
	if stats["error"] != 1 {
		t.Errorf("stats[error] = %d, want 1", stats["error"])
	}
	if stats["pending"] != 0 {
		t.Errorf("stats[pending] = %d, want 0", stats["pending"])
	}
}

func TestQueue_Delete(t *testing.T) {
	q := newTestQueue()

	// Inject a terminal job directly.
	q.mu.Lock()
	q.jobs["del-1"] = &Job{ID: "del-1", Status: "done"}
	q.mu.Unlock()

	if ok := q.Delete("del-1"); !ok {
		t.Error("Delete returned false for existing done job")
	}
	if _, ok := q.Get("del-1"); ok {
		t.Error("deleted job still returned by Get")
	}
}

func TestQueue_DeleteNonTerminal(t *testing.T) {
	q := newTestQueue()
	q.mu.Lock()
	q.jobs["run-1"] = &Job{ID: "run-1", Status: "running"}
	q.mu.Unlock()

	if ok := q.Delete("run-1"); ok {
		t.Error("Delete should return false for running job")
	}
}

func TestQueue_DeleteMissing(t *testing.T) {
	q := newTestQueue()
	if ok := q.Delete("ghost"); ok {
		t.Error("Delete should return false for missing job")
	}
}

func TestQueue_CancelMissing(t *testing.T) {
	q := newTestQueue()
	if ok := q.Cancel("ghost"); ok {
		t.Error("Cancel should return false for missing job")
	}
}

func TestQueue_Prune(t *testing.T) {
	q := newTestQueue()
	old := time.Now().Add(-48 * time.Hour)
	recent := time.Now().Add(-1 * time.Hour)

	q.mu.Lock()
	q.jobs["old-done"] = &Job{ID: "old-done", Status: "done", UpdatedAt: old}
	q.jobs["old-err"] = &Job{ID: "old-err", Status: "error", UpdatedAt: old}
	q.jobs["recent"] = &Job{ID: "recent", Status: "done", UpdatedAt: recent}
	q.jobs["running"] = &Job{ID: "running", Status: "running", UpdatedAt: old}
	q.mu.Unlock()

	pruned := q.Prune(24 * time.Hour)
	if pruned != 2 {
		t.Errorf("Prune returned %d, want 2 (old done + old error)", pruned)
	}

	// Recent done job should survive.
	if _, ok := q.Get("recent"); !ok {
		t.Error("recent done job was incorrectly pruned")
	}
	// Running job should survive even if old.
	if _, ok := q.Get("running"); !ok {
		t.Error("running job was incorrectly pruned")
	}
	// Old terminal jobs should be gone.
	if _, ok := q.Get("old-done"); ok {
		t.Error("old done job should have been pruned")
	}
	if _, ok := q.Get("old-err"); ok {
		t.Error("old error job should have been pruned")
	}
}

func TestQueue_SetMaxConcurrentZeroMeansUnlimited(t *testing.T) {
	q := newTestQueue()
	q.SetMaxConcurrent(0)
	if q.sem != nil {
		t.Error("sem should be nil for unlimited concurrency")
	}
	q.SetMaxConcurrent(-1)
	if q.sem != nil {
		t.Error("sem should be nil for negative max concurrent")
	}
}

func TestQueue_SetMaxConcurrentPositive(t *testing.T) {
	q := newTestQueue()
	q.SetMaxConcurrent(3)
	if q.sem == nil {
		t.Fatal("sem should not be nil")
	}
	if cap(q.sem) != 3 {
		t.Errorf("sem cap = %d, want 3", cap(q.sem))
	}
}

func TestQueue_MaxConcurrentDefault(t *testing.T) {
	q := newTestQueue()
	if got := q.MaxConcurrent(); got != 0 {
		t.Errorf("default MaxConcurrent = %d, want 0", got)
	}
	q.SetMaxConcurrent(5)
	if got := q.MaxConcurrent(); got != 5 {
		t.Errorf("MaxConcurrent after set = %d, want 5", got)
	}
}

func TestQueue_SetStoreLoadsJobs(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)

	// Pre-populate the store with a completed job.
	store.Save(&Job{ //nolint:errcheck
		ID:        "persisted-job",
		Command:   "token-analysis",
		Status:    "done",
		Output:    []string{"out"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	q := newTestQueue()
	q.SetStore(store)

	if _, ok := q.Get("persisted-job"); !ok {
		t.Error("SetStore should load persisted jobs into the queue")
	}
}

func TestQueue_SetStoreMarksPendingAsError(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)

	store.Save(&Job{ //nolint:errcheck
		ID:        "mid-flight",
		Command:   "system-overview",
		Status:    "running",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	q := newTestQueue()
	q.SetStore(store)

	job, ok := q.Get("mid-flight")
	if !ok {
		t.Fatal("mid-flight job not loaded")
	}
	if job.Status != "error" {
		t.Errorf("mid-flight job status = %q, want error", job.Status)
	}
}
