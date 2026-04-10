package jobs

import (
	"bufio"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Job represents an async job executing a vault-audit command.
type Job struct {
	ID        string    `json:"id"`
	Command   string    `json:"command"`
	Args      []string  `json:"args"`
	Status    string    `json:"status"` // "pending", "running", "done", "error", "cancelled"
	Output    []string  `json:"output"`
	ExitCode  int       `json:"exit_code"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Error     string    `json:"error"`

	// cmd holds the running process so it can be cancelled. Not serialised.
	cmd *exec.Cmd
}

// Queue manages an in-memory collection of async jobs.
type Queue struct {
	mu         sync.RWMutex
	jobs       map[string]*Job
	binaryPath string
	workDir    string // CWD for child processes; "" = inherit server CWD
	broker     *Broker
	store      *Store        // nil = no persistence
	sem        chan struct{} // nil = unlimited concurrency
}

// NewQueue creates a new job queue with the given SSE broker.
func NewQueue(broker *Broker) *Queue {
	return &Queue{
		jobs:       make(map[string]*Job),
		binaryPath: "./vault-audit",
		broker:     broker,
	}
}

// SetMaxConcurrent caps the number of jobs that can run simultaneously.
// A value ≤ 0 means unlimited (the default). Must be called before any jobs
// are submitted to take effect cleanly.
func (q *Queue) SetMaxConcurrent(n int) {
	if n <= 0 {
		q.sem = nil
		return
	}
	q.sem = make(chan struct{}, n)
}

// SetBinaryPath sets the path to the vault-audit binary.
func (q *Queue) SetBinaryPath(path string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.binaryPath = path
}

// SetWorkDir sets the working directory for all child processes spawned by
// this queue. When set to the uploads directory, relative output-file paths
// written by vault-audit (e.g. "entity_mappings.json") land there
// automatically and become visible through the /ingest/files API.
func (q *Queue) SetWorkDir(dir string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.workDir = dir
}

// SetStore attaches a persistent store and loads all previously saved jobs.
// Any jobs that were running or pending at the last shutdown are marked as
// errored, since their processes no longer exist.
func (q *Queue) SetStore(s *Store) {
	q.store = s

	saved, err := s.LoadAll()
	if err != nil {
		return // non-fatal: start with empty history
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	for _, job := range saved {
		// Jobs that were mid-flight will never complete — mark them interrupted.
		// "cancelled" is already terminal, so leave it as-is.
		if job.Status == "running" || job.Status == "pending" {
			job.Status = "error"
			job.Error = "interrupted: server restarted"
			job.UpdatedAt = time.Now()
			_ = s.Save(job) // update on disk too
		}
		q.jobs[job.ID] = job
	}
}

// Submit creates a job with a new UUID, starts it in the background, and
// returns it immediately.
func (q *Queue) Submit(cmd string, args []string) *Job {
	return q.SubmitWithID(uuid.New().String(), cmd, args)
}

// SubmitWithID is like Submit but uses a caller-supplied ID.  Use this when
// the ID must be known before submission — e.g. to embed a short form of it
// inside an output filename so the file can be traced back to the job that
// created it.
func (q *Queue) SubmitWithID(id, cmd string, args []string) *Job {
	job := &Job{
		ID:        id,
		Command:   cmd,
		Args:      args,
		Status:    "pending",
		Output:    []string{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	q.mu.Lock()
	q.jobs[job.ID] = job
	q.mu.Unlock()

	if q.store != nil {
		_ = q.store.Save(job)
	}

	// Snapshot the job before launching the goroutine so the caller gets a
	// stable copy to serialize.  After go executeJob starts, only queue
	// internals may write to the original pointer under q.mu.
	snapshot := *job
	go q.executeJob(job)
	return &snapshot
}

// MaxConcurrent returns the current concurrency cap (0 = unlimited).
func (q *Queue) MaxConcurrent() int {
	if q.sem == nil {
		return 0
	}
	return cap(q.sem)
}

// Stats returns counts of jobs in each status for monitoring.
func (q *Queue) Stats() map[string]int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	counts := map[string]int{
		"pending":   0,
		"running":   0,
		"done":      0,
		"error":     0,
		"cancelled": 0,
	}
	for _, j := range q.jobs {
		counts[j.Status]++
	}
	return counts
}

// Delete removes a job from the queue (and persistent store if attached).
// Returns false if the job was not found or is still running/pending.
func (q *Queue) Delete(id string) bool {
	q.mu.Lock()
	job, ok := q.jobs[id]
	if !ok {
		q.mu.Unlock()
		return false
	}
	if job.Status == "running" || job.Status == "pending" {
		q.mu.Unlock()
		return false // must cancel first
	}
	delete(q.jobs, id)
	q.mu.Unlock()

	if q.store != nil {
		_ = q.store.Delete(id)
	}
	return true
}

// Prune removes all terminal jobs older than the given age. Returns count deleted.
func (q *Queue) Prune(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	q.mu.Lock()
	var toDelete []string
	for id, j := range q.jobs {
		if j.Status != "running" && j.Status != "pending" && j.UpdatedAt.Before(cutoff) {
			toDelete = append(toDelete, id)
		}
	}
	for _, id := range toDelete {
		delete(q.jobs, id)
	}
	q.mu.Unlock()

	if q.store != nil {
		for _, id := range toDelete {
			_ = q.store.Delete(id)
		}
	}
	return len(toDelete)
}

// Get retrieves a job by ID.
func (q *Queue) Get(id string) (*Job, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	job, ok := q.jobs[id]
	if !ok {
		return nil, false
	}
	// Return a snapshot so callers can read/serialize without holding the lock.
	// Output is a slice; append never mutates existing elements, so the header
	// copy is safe — the snapshot captures the current length/contents.
	snapshot := *job
	return &snapshot, true
}

// List returns snapshots of all jobs sorted by creation time (newest first).
func (q *Queue) List() []*Job {
	q.mu.RLock()
	defer q.mu.RUnlock()
	out := make([]*Job, 0, len(q.jobs))
	for _, j := range q.jobs {
		snap := *j // value copy while holding the lock
		out = append(out, &snap)
	}
	return out
}

// executeJob runs the command, streams output line-by-line, then marks done/error.
func (q *Queue) executeJob(job *Job) {
	// Acquire concurrency slot — blocks until a slot is free.
	// If the job was cancelled while it was waiting, drop it.
	if q.sem != nil {
		q.sem <- struct{}{}
		defer func() { <-q.sem }()

		q.mu.RLock()
		status := job.Status
		q.mu.RUnlock()
		if status == "cancelled" {
			return
		}
	}

	q.mu.Lock()
	job.Status = "running"
	job.UpdatedAt = time.Now()
	q.mu.Unlock()

	q.mu.RLock()
	binaryPath := q.binaryPath
	workDir := q.workDir
	q.mu.RUnlock()

	// Build: vault-audit <command> [args...]
	// binaryPath is a fixed absolute path set at server startup (not user input).
	// job.Command is validated against the allowedCommands allowlist in
	// internal/api/handlers_analysis.go before the job is ever enqueued, so
	// only known subcommand names reach this call site.
	cmdArgs := append([]string{job.Command}, job.Args...)
	cmd := exec.Command(binaryPath, cmdArgs...) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	// Set working directory so relative output paths (e.g. entity_mappings.json)
	// land in the uploads directory and become visible through the Files API.
	if workDir != "" {
		cmd.Dir = workDir
	}

	// Use io.Pipe so stdout and stderr both feed the same scanner.
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		pw.Close()
		q.finishJob(job, -1, err.Error())
		return
	}

	// Store the process handle so Cancel() can kill it.
	q.mu.Lock()
	job.cmd = cmd
	q.mu.Unlock()

	// Wait for the process in a goroutine; close the pipe writer when done
	// so the scanner below sees EOF.
	waitErr := make(chan error, 1)
	go func() {
		waitErr <- cmd.Wait()
		pw.Close()
	}()

	// Read combined output line by line — this unblocks when pw is closed.
	// Vault audit log lines are JSON objects and can exceed the default 64 KB
	// scanner limit, causing the scanner to stop reading while the process is
	// still writing. That deadlocks cmd.Wait() permanently.
	// Use a 10 MB per-line buffer to handle large entries, and always drain
	// the pipe on scanner error so the child process is never stuck.
	const maxLineBytes = 10 * 1024 * 1024 // 10 MB
	scanner := bufio.NewScanner(pr)
	scanner.Buffer(make([]byte, 64*1024), maxLineBytes)

	for scanner.Scan() {
		line := scanner.Text()

		q.mu.Lock()
		job.Output = append(job.Output, line)
		q.mu.Unlock()

		if q.broker != nil {
			q.broker.Publish(job.ID, line)
		}
	}

	// If the scanner hit a buffer-overflow or any other error, drain the pipe
	// so the child process can finish writing and exit normally.
	if scanner.Err() != nil {
		errLine := "[truncated: output line exceeded 10 MB limit — " + scanner.Err().Error() + "]"
		q.mu.Lock()
		job.Output = append(job.Output, errLine)
		q.mu.Unlock()
		if q.broker != nil {
			q.broker.Publish(job.ID, errLine)
		}
		io.Copy(io.Discard, pr) //nolint:errcheck
	}

	// Collect exit status.
	exitCode := 0
	errMsg := ""
	if err := <-waitErr; err != nil {
		errMsg = err.Error()
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	q.finishJob(job, exitCode, errMsg)

	// Signal SSE subscribers that the stream is finished.
	if q.broker != nil {
		q.broker.CloseJob(job.ID)
	}
}

// Cancel kills a running or pending job. Returns false if the job is not
// found or is already in a terminal state.
func (q *Queue) Cancel(id string) bool {
	q.mu.Lock()
	job, ok := q.jobs[id]
	if !ok {
		q.mu.Unlock()
		return false
	}
	if job.Status != "running" && job.Status != "pending" {
		q.mu.Unlock()
		return false
	}
	// Mark cancelled immediately so the UI sees it right away.
	job.Status = "cancelled"
	job.Error = "cancelled by user"
	job.UpdatedAt = time.Now()
	cmd := job.cmd
	q.mu.Unlock()

	// Kill the OS process if it is running.
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}

	if q.store != nil {
		_ = q.store.Save(job)
	}
	if q.broker != nil {
		q.broker.CloseJob(id)
	}
	return true
}

// finishJob sets the terminal state of a job and persists it.
// If the job was already cancelled, it preserves the cancelled status.
func (q *Queue) finishJob(job *Job, exitCode int, errMsg string) {
	q.mu.Lock()
	// Don't overwrite a cancellation that raced with natural completion.
	if job.Status != "cancelled" {
		if errMsg != "" {
			job.Status = "error"
			job.Error = errMsg
		} else {
			job.Status = "done"
		}
	}
	job.ExitCode = exitCode
	job.UpdatedAt = time.Now()
	q.mu.Unlock()

	if q.store != nil {
		_ = q.store.Save(job) // persist final state + full output
	}
}
