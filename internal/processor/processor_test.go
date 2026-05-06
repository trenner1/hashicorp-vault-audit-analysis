package processor

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/audit"
)

// testdataPath returns the path to a file in the shared testdata directory.
func testdataPath(name string) string {
	// processor package lives at internal/processor; testdata is at internal/testdata.
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "testdata", name)
}

// writeLines writes lines to a temp file and returns its path.
func writeLines(t *testing.T, lines []string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "audit-*.ndjson")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer f.Close()
	for _, l := range lines {
		f.WriteString(l + "\n") //nolint:errcheck
	}
	return f.Name()
}

// countingState is a minimal accumulator that tallies parsed entries.
type countingState struct {
	total    int
	requests int
	kvPaths  []string
}

func newCounting() countingState { return countingState{} }

func processEntry(e *audit.AuditEntry, s *countingState) {
	s.total++
	if e.EntryType == "request" {
		s.requests++
		if e.IsKVOperation() {
			s.kvPaths = append(s.kvPaths, e.Path())
		}
	}
}

func mergeCount(a, b countingState) countingState {
	a.total += b.total
	a.requests += b.requests
	a.kvPaths = append(a.kvPaths, b.kvPaths...)
	return a
}

// ── RunFiles ──────────────────────────────────────────────────────────────────

func TestRunFiles_EmptySlice(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PlainProgress = true
	state, stats, err := RunFiles(cfg, nil, newCounting, processEntry, mergeCount)
	if err != nil {
		t.Fatalf("RunFiles(nil): %v", err)
	}
	if state.total != 0 {
		t.Errorf("total = %d, want 0", state.total)
	}
	if stats.FilesProcessed != 0 {
		t.Errorf("FilesProcessed = %d, want 0", stats.FilesProcessed)
	}
}

func TestRunFiles_SingleFile(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PlainProgress = true // suppress ANSI codes in test output
	cfg.ShowFileCompletion = false

	path := testdataPath("sample.ndjson")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("testdata file not found: %s", path)
	}

	state, stats, err := RunFiles(cfg, []string{path}, newCounting, processEntry, mergeCount)
	if err != nil {
		t.Fatalf("RunFiles: %v", err)
	}

	// sample.ndjson has 22 JSON lines + 1 invalid line = 23 total; 22 parsed
	if stats.TotalLines != 23 {
		t.Errorf("TotalLines = %d, want 23", stats.TotalLines)
	}
	if stats.ParsedEntries != 22 {
		t.Errorf("ParsedEntries = %d, want 22", stats.ParsedEntries)
	}
	if stats.SkippedLines != 1 {
		t.Errorf("SkippedLines = %d, want 1", stats.SkippedLines)
	}
	if stats.FilesProcessed != 1 {
		t.Errorf("FilesProcessed = %d, want 1", stats.FilesProcessed)
	}

	// 11 request entries in sample.ndjson
	if state.requests != 11 {
		t.Errorf("requests = %d, want 11", state.requests)
	}
}

func TestRunFiles_ParallelTwoFiles(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PlainProgress = true
	cfg.ShowFileCompletion = false

	// Write two small files with known content.
	line := `{"type":"request","time":"2024-01-01T00:00:00Z","request":{"id":"r1","operation":"read","path":"secret/data/x","mount_type":"kv","mount_point":"secret/","namespace":{"id":"root"},"remote_address":"1.2.3.4"}}`
	f1 := writeLines(t, []string{line, line})
	f2 := writeLines(t, []string{line, line, line})

	state, stats, err := RunFiles(cfg, []string{f1, f2}, newCounting, processEntry, mergeCount)
	if err != nil {
		t.Fatalf("RunFiles parallel: %v", err)
	}
	if stats.ParsedEntries != 5 {
		t.Errorf("ParsedEntries = %d, want 5", stats.ParsedEntries)
	}
	if stats.FilesProcessed != 2 {
		t.Errorf("FilesProcessed = %d, want 2", stats.FilesProcessed)
	}
	if state.requests != 5 {
		t.Errorf("requests = %d, want 5", state.requests)
	}
}

func TestRunFiles_ModeSequentialForced(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeSequential
	cfg.PlainProgress = true
	cfg.ShowFileCompletion = false

	line := `{"type":"response","time":"2024-01-01T00:00:00Z","request":{"id":"r1","operation":"read","path":"pki/cert/ca","mount_type":"pki","mount_point":"pki/","namespace":{"id":"root"},"remote_address":"1.2.3.4"}}`
	f1 := writeLines(t, []string{line})
	f2 := writeLines(t, []string{line})

	_, stats, err := RunFiles(cfg, []string{f1, f2}, newCounting, processEntry, mergeCount)
	if err != nil {
		t.Fatalf("RunFiles sequential: %v", err)
	}
	if stats.ParsedEntries != 2 {
		t.Errorf("ParsedEntries = %d, want 2", stats.ParsedEntries)
	}
}

func TestRunFiles_ModeParallelForced(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeParallel
	cfg.PlainProgress = true
	cfg.ShowFileCompletion = false

	line := `{"type":"request","time":"2024-01-01T00:00:00Z","request":{"id":"r1","operation":"read","path":"secret/data/y","mount_type":"kv","mount_point":"secret/","namespace":{"id":"root"},"remote_address":"1.2.3.4"}}`
	f := writeLines(t, []string{line, line})
	// Even a single file runs in parallel goroutines when ModeParallel.
	_, stats, err := RunFiles(cfg, []string{f}, newCounting, processEntry, mergeCount)
	if err != nil {
		t.Fatalf("RunFiles parallel forced: %v", err)
	}
	if stats.ParsedEntries != 2 {
		t.Errorf("ParsedEntries = %d, want 2", stats.ParsedEntries)
	}
}

func TestRunFiles_SkipsInvalidJSON(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PlainProgress = true
	cfg.ShowFileCompletion = false

	good := `{"type":"request","time":"2024-01-01T00:00:00Z","request":{"id":"r1","operation":"read","path":"p","namespace":{"id":"root"},"remote_address":"1.2.3.4"}}`
	f := writeLines(t, []string{good, "not json at all", good})

	_, stats, err := RunFiles(cfg, []string{f}, newCounting, processEntry, mergeCount)
	if err != nil {
		t.Fatalf("RunFiles skip invalid: %v", err)
	}
	if stats.ParsedEntries != 2 {
		t.Errorf("ParsedEntries = %d, want 2", stats.ParsedEntries)
	}
	if stats.SkippedLines != 1 {
		t.Errorf("SkippedLines = %d, want 1", stats.SkippedLines)
	}
}

func TestRunFiles_StrictParsingReturnsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PlainProgress = true
	cfg.StrictParsing = true
	cfg.ShowFileCompletion = false

	good := `{"type":"request","time":"2024-01-01T00:00:00Z","request":{"id":"r1","operation":"read","path":"p","namespace":{"id":"root"},"remote_address":"1.2.3.4"}}`
	f := writeLines(t, []string{good, "{bad json}"})

	_, _, err := RunFiles(cfg, []string{f}, newCounting, processEntry, mergeCount)
	if err == nil {
		t.Error("expected error for strict parsing + invalid JSON, got nil")
	}
}

func TestRunFiles_FileNotFound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PlainProgress = true

	_, _, err := RunFiles(cfg, []string{"/no/such/file.ndjson"}, newCounting, processEntry, mergeCount)
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

// ── Stats ─────────────────────────────────────────────────────────────────────

func TestStats_Merge(t *testing.T) {
	a := Stats{TotalLines: 100, ParsedEntries: 90, SkippedLines: 10, FilesProcessed: 1}
	b := Stats{TotalLines: 50, ParsedEntries: 48, SkippedLines: 2, FilesProcessed: 1}
	a.Merge(b)

	if a.TotalLines != 150 {
		t.Errorf("TotalLines = %d, want 150", a.TotalLines)
	}
	if a.ParsedEntries != 138 {
		t.Errorf("ParsedEntries = %d, want 138", a.ParsedEntries)
	}
	if a.SkippedLines != 12 {
		t.Errorf("SkippedLines = %d, want 12", a.SkippedLines)
	}
	if a.FilesProcessed != 2 {
		t.Errorf("FilesProcessed = %d, want 2", a.FilesProcessed)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func TestFormatNum(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1,000"},
		{1234567, "1,234,567"},
		{1000000000, "1,000,000,000"},
	}
	for _, c := range cases {
		if got := formatNum(c.in); got != c.want {
			t.Errorf("formatNum(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBaseName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/foo/bar/baz.log", "baz.log"},
		{"baz.log", "baz.log"},
		{"/single", "single"},
		{"a/b", "b"},
	}
	for _, c := range cases {
		if got := baseName(c.in); got != c.want {
			t.Errorf("baseName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
