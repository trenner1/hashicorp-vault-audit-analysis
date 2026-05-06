# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Build & Test Commands

```bash
# Build CLI binary
make build                    # → ./build/vault-audit

# Build API server
make server                   # → ./server

# Run tests
go test ./...                 # All tests
go test ./... -v -count=1     # Verbose, no cache
go test ./internal/processor  # Single package

# Run single test
go test -v -run TestName ./path/to/package

# Coverage
make cover                    # Terminal summary
make cover-html               # Browser report

# Lint
make lint                     # staticcheck + vet
golangci-lint run             # Full linting suite
```

## Project-Specific Patterns

### Dual Architecture (CLI + API Server)
- **CLI binary** (`cmd/vault-audit/main.go`): Standalone tool, uses `internal/commands/` directly
- **API server** (`cmd/server/main.go`): Wraps CLI binary as subprocess, NOT a library import
- Server spawns `./vault-audit` child processes via `internal/jobs/queue.go`
- Child process CWD = `uploadDir` so relative output files land in uploads directory

### File Processing Modes
- `processor.RunFiles()` auto-selects: 1 file = sequential, 2+ files = parallel
- Parallel uses goroutine-per-file (bounded by `runtime.NumCPU()`)
- Progress bar switches to plain text when stderr is not a TTY (server context)

### Compressed File Handling
- `internal/reader/reader.go` auto-detects `.gz` and `.zst` by extension
- Streaming decompression (no temp files)
- All commands support compressed files transparently

### Test Data Location
- Shared test data: `internal/testdata/sample.ndjson`
- Tests use `runtime.Caller(0)` to locate testdata relative to test file
- Pattern: `filepath.Join(filepath.Dir(file), "..", "testdata", name)`

### Vault Client Environment Variables
- Respects standard Vault env vars: `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_TOKEN_FILE`, `VAULT_NAMESPACE`, `VAULT_SKIP_VERIFY`
- Token precedence: flag → `VAULT_TOKEN` → `VAULT_TOKEN_FILE`
- Default addr: `http://127.0.0.1:8200`

### API Server Configuration
- All paths resolved to absolute on startup (`filepath.Abs()`)
- Job queue `workDir` = `uploadDir` so child processes write to correct location
- Persistent stores optional (non-fatal if unavailable)
- SSE for real-time job progress (`internal/jobs/sse.go`)

### Error Handling Conventions
- `.golangci.yml` excludes intentional fire-and-forget errors (progress bar, fmt.Fprint)
- CSV writer errors checked via `w.Error()` after loop, not per-write
- JSON unmarshal errors from intermediate marshal/unmarshal intentionally ignored

### Linter Suppressions
- G304 (file inclusion): User-supplied log paths are intentional
- G402 (TLS InsecureSkipVerify): User-supplied `--insecure` flag
- G404 (weak random): Test data generation only
- G115 (integer overflow): Reviewed, safe in context