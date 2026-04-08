// Package processor provides generic, streaming, parallel audit log processing.
//
// The core function is RunFiles, which processes one or more audit log files
// (plain, .gz, or .zst) with automatic parallel vs sequential selection:
//   - 1 file  → sequential (no goroutine overhead)
//   - 2+ files → parallel (one goroutine per file, bounded by runtime.NumCPU())
//
// Usage pattern:
//
//	type MyState struct { counts map[string]int }
//
//	result, stats, err := processor.RunFiles(
//	    processor.DefaultConfig(),
//	    logFiles,
//	    func() MyState { return MyState{counts: make(map[string]int)} },
//	    func(entry *audit.AuditEntry, s *MyState) { s.counts[entry.Path()]++ },
//	    func(a, b MyState) MyState { /* merge b into a */ return a },
//	)
package processor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/audit"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/reader"
)

// Mode controls parallel vs sequential processing selection.
type Mode int

const (
	// ModeAuto selects sequential for 1 file, parallel for 2+.
	ModeAuto Mode = iota
	// ModeSequential always processes files one at a time.
	ModeSequential
	// ModeParallel always uses a goroutine per file.
	ModeParallel
)

// Config controls processor behaviour.
type Config struct {
	Mode               Mode
	ProgressFrequency  int    // update progress every N lines
	ShowFileCompletion bool   // print a line when each file finishes
	ProgressLabel      string // label shown in the progress bar
	StrictParsing      bool   // fail on any JSON parse error
	PlainProgress      bool   // use plain-text progress (set automatically when stderr is not a TTY)
	PlainProgressFreq  int    // emit a plain-text progress line every N entries (default 100_000)
}

// DefaultConfig returns sensible defaults matching the Rust implementation.
// When stderr is not a TTY (e.g. piped to the server), it automatically
// switches to plain-text progress output so no ANSI escape codes appear.
func DefaultConfig() Config {
	plain := !isTTY(os.Stderr)
	return Config{
		Mode:               ModeAuto,
		ProgressFrequency:  2000,
		ShowFileCompletion: true,
		ProgressLabel:      "Processing",
		StrictParsing:      false,
		PlainProgress:      plain,
		PlainProgressFreq:  100_000,
	}
}

// Stats records what happened during a processing run.
type Stats struct {
	TotalLines     int
	ParsedEntries  int
	SkippedLines   int
	FilesProcessed int
}

// Merge adds other into s in-place.
func (s *Stats) Merge(other Stats) {
	s.TotalLines += other.TotalLines
	s.ParsedEntries += other.ParsedEntries
	s.SkippedLines += other.SkippedLines
	s.FilesProcessed += other.FilesProcessed
}

// Report prints a summary to stderr.
func (s Stats) Report() {
	fmt.Fprintf(os.Stderr, "\nProcessing Summary:\n")
	fmt.Fprintf(os.Stderr, "  Files processed: %d\n", s.FilesProcessed)
	fmt.Fprintf(os.Stderr, "  Total lines: %s\n", formatNum(s.TotalLines))
	fmt.Fprintf(os.Stderr, "  Parsed entries: %s\n", formatNum(s.ParsedEntries))
	if s.SkippedLines > 0 {
		pct := float64(s.SkippedLines) / float64(s.TotalLines) * 100
		fmt.Fprintf(os.Stderr, "  Skipped lines: %s (%.2f%%)\n", formatNum(s.SkippedLines), pct)
	}
}

// ---------- Public generic entry point ----------

// RunFiles processes multiple audit log files with streaming.
//
// Parameters:
//   - cfg        – processing config
//   - files      – file paths (plain, .gz, .zst all supported)
//   - newState   – factory called once per worker to create a fresh accumulator
//   - process    – called for every successfully parsed AuditEntry
//   - merge      – combines two accumulators into one (must be commutative)
func RunFiles[T any](
	cfg Config,
	files []string,
	newState func() T,
	process func(*audit.AuditEntry, *T),
	merge func(T, T) T,
) (T, Stats, error) {
	zero := newState()
	if len(files) == 0 {
		return zero, Stats{}, nil
	}

	useParallel := cfg.Mode == ModeParallel ||
		(cfg.Mode == ModeAuto && len(files) > 1)

	if useParallel {
		return runParallel(cfg, files, newState, process, merge)
	}
	return runSequential(cfg, files, newState, process, merge)
}

// ---------- Sequential ----------

func runSequential[T any](
	cfg Config,
	files []string,
	newState func() T,
	process func(*audit.AuditEntry, *T),
	merge func(T, T) T,
) (T, Stats, error) {
	fmt.Fprintf(os.Stderr, "Processing %d file(s) sequentially...\n", len(files))

	combined := newState()
	var totalStats Stats

	for i, path := range files {
		fmt.Fprintf(os.Stderr, "[%d/%d] Processing: %s\n", i+1, len(files), path)

		var pb *progressbar.ProgressBar
		if cfg.PlainProgress {
			// Skip line pre-count and use a silent bar; plain progress is
			// printed inside processOneFile via fmt.Fprintf instead.
			pb = newSilentBar()
		} else {
			lineCount, err := countLines(path)
			if err != nil {
				return combined, totalStats, err
			}
			pb = newBar(lineCount, cfg.ProgressLabel)
		}

		state := newState()
		stats, err := processOneFile(path, process, &state, pb, cfg)
		if err != nil {
			return combined, totalStats, err
		}
		if !cfg.PlainProgress {
			pb.Finish()
			fmt.Fprintln(os.Stderr)
		}

		if cfg.ShowFileCompletion {
			fmt.Fprintf(os.Stderr, "[%d/%d] ✓ Completed: %s (%s lines)\n",
				i+1, len(files), baseName(path), formatNum(stats.TotalLines))
		}

		combined = merge(combined, state)
		totalStats.Merge(stats)
	}
	return combined, totalStats, nil
}

// ---------- Parallel ----------

type fileResult[T any] struct {
	state T
	stats Stats
	err   error
}

func runParallel[T any](
	cfg Config,
	files []string,
	newState func() T,
	process func(*audit.AuditEntry, *T),
	merge func(T, T) T,
) (T, Stats, error) {
	zero := newState()
	fmt.Fprintf(os.Stderr, "Processing %d files in parallel...\n", len(files))

	var pb *progressbar.ProgressBar
	var pbMu sync.Mutex
	var processed atomic.Int64

	if cfg.PlainProgress {
		pb = newSilentBar()
	} else {
		// Pre-scan total line count for accurate TTY progress bar.
		fmt.Fprintln(os.Stderr, "Scanning files to determine total work...")
		total := parallelCount(files)
		fmt.Fprintf(os.Stderr, "Total lines to process: %s\n", formatNum(total))
		pb = newBar(total, cfg.ProgressLabel)
	}

	results := make([]fileResult[T], len(files))

	// Limit concurrency to number of CPUs.
	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup

	for i, path := range files {
		i, path := i, path
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			state := newState()
			stats, err := processOneFileParallel(path, process, &state, &pbMu, pb, &processed, cfg)

			if cfg.ShowFileCompletion {
				msg := fmt.Sprintf("[%d/%d] ✓ Completed: %s (%s lines)",
					i+1, len(files), baseName(path), formatNum(stats.TotalLines))
				pbMu.Lock()
				if !cfg.PlainProgress {
					pb.Clear() //nolint:errcheck
				}
				fmt.Fprintln(os.Stderr, msg)
				pbMu.Unlock()
			}

			results[i] = fileResult[T]{state: state, stats: stats, err: err}
		}()
	}
	wg.Wait()
	if !cfg.PlainProgress {
		pb.Finish() //nolint:errcheck
		fmt.Fprintln(os.Stderr)
	}

	// Check errors and aggregate.
	combined := newState()
	var totalStats Stats
	for _, r := range results {
		if r.err != nil {
			return zero, Stats{}, r.err
		}
		combined = merge(combined, r.state)
		totalStats.Merge(r.stats)
	}

	fmt.Fprintf(os.Stderr, "Processed %s total lines\n", formatNum(int(processed.Load())))
	return combined, totalStats, nil
}

// ---------- Single-file streaming core ----------

func processOneFile[T any](
	path string,
	process func(*audit.AuditEntry, *T),
	state *T,
	pb *progressbar.ProgressBar,
	cfg Config,
) (Stats, error) {
	rc, err := reader.OpenFile(path)
	if err != nil {
		return Stats{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer rc.Close()

	var stats Stats
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024) // 4 MB line buffer

	plainFreq := cfg.PlainProgressFreq
	if plainFreq <= 0 {
		plainFreq = 100_000
	}

	for scanner.Scan() {
		line := scanner.Text()
		stats.TotalLines++

		if cfg.PlainProgress {
			if stats.TotalLines%plainFreq == 0 {
				fmt.Fprintf(os.Stderr, "[progress] %s entries processed...\n", formatNum(stats.TotalLines))
			}
		} else if stats.TotalLines%cfg.ProgressFrequency == 0 {
			pb.Add(cfg.ProgressFrequency) //nolint:errcheck
		}

		if line == "" {
			continue
		}
		var entry audit.AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			stats.SkippedLines++
			if cfg.StrictParsing {
				return stats, fmt.Errorf("parse line %d in %s: %w", stats.TotalLines, path, err)
			}
			continue
		}
		stats.ParsedEntries++
		process(&entry, state)
	}

	// Flush remaining TTY progress.
	if !cfg.PlainProgress {
		rem := stats.TotalLines % cfg.ProgressFrequency
		if rem > 0 {
			pb.Add(rem) //nolint:errcheck
		}
	}

	if err := scanner.Err(); err != nil {
		return stats, fmt.Errorf("read %s: %w", path, err)
	}
	stats.FilesProcessed = 1
	return stats, nil
}

// processOneFileParallel is like processOneFile but updates a shared atomic counter
// and uses a mutex-protected progress bar.
func processOneFileParallel[T any](
	path string,
	process func(*audit.AuditEntry, *T),
	state *T,
	pbMu *sync.Mutex,
	pb *progressbar.ProgressBar,
	processed *atomic.Int64,
	cfg Config,
) (Stats, error) {
	rc, err := reader.OpenFile(path)
	if err != nil {
		return Stats{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer rc.Close()

	var stats Stats
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	plainFreq := cfg.PlainProgressFreq
	if plainFreq <= 0 {
		plainFreq = 100_000
	}

	for scanner.Scan() {
		line := scanner.Text()
		stats.TotalLines++

		if cfg.PlainProgress {
			if stats.TotalLines%plainFreq == 0 {
				fmt.Fprintf(os.Stderr, "[progress] %s entries processed (%s)...\n",
					formatNum(stats.TotalLines), baseName(path))
			}
		} else if stats.TotalLines%cfg.ProgressFrequency == 0 {
			n := processed.Add(int64(cfg.ProgressFrequency))
			pbMu.Lock()
			pb.Set(int(n)) //nolint:errcheck
			pbMu.Unlock()
		}

		if line == "" {
			continue
		}
		var entry audit.AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			stats.SkippedLines++
			if cfg.StrictParsing {
				return stats, fmt.Errorf("parse line %d in %s: %w", stats.TotalLines, path, err)
			}
			continue
		}
		stats.ParsedEntries++
		process(&entry, state)
	}

	if !cfg.PlainProgress {
		rem := stats.TotalLines % cfg.ProgressFrequency
		if rem > 0 {
			n := processed.Add(int64(rem))
			pbMu.Lock()
			pb.Set(int(n)) //nolint:errcheck
			pbMu.Unlock()
		}
	}

	if err := scanner.Err(); err != nil {
		return stats, fmt.Errorf("read %s: %w", path, err)
	}
	stats.FilesProcessed = 1
	return stats, nil
}

// ---------- Line counting ----------

func countLines(path string) (int, error) {
	rc, err := reader.OpenFile(path)
	if err != nil {
		return 0, err
	}
	defer rc.Close()

	n := 0
	buf := make([]byte, 64*1024)
	for {
		c, err := rc.Read(buf)
		for _, b := range buf[:c] {
			if b == '\n' {
				n++
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func parallelCount(files []string) int {
	type result struct{ n int }
	ch := make(chan result, len(files))
	for _, f := range files {
		f := f
		go func() {
			n, _ := countLines(f)
			ch <- result{n}
		}()
	}
	total := 0
	for range files {
		total += (<-ch).n
	}
	return total
}

// ---------- Progress bar ----------

// isTTY reports whether the given file is connected to a terminal.
func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func newBar(total int, label string) *progressbar.ProgressBar {
	return progressbar.NewOptions(total,
		progressbar.OptionSetDescription(label),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(40),
		progressbar.OptionThrottle(150*time.Millisecond),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionClearOnFinish(),
	)
}

// newSilentBar returns a no-op progress bar that discards all output.
// Used in non-TTY mode where ANSI escape codes would corrupt the output stream.
func newSilentBar() *progressbar.ProgressBar {
	return progressbar.NewOptions(-1,
		progressbar.OptionSetWriter(io.Discard),
	)
}

// ---------- Helpers ----------

func baseName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}

func formatNum(n int) string {
	s := fmt.Sprintf("%d", n)
	out := make([]byte, 0, len(s)+(len(s)-1)/3)
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}
