# Project Architecture Rules (Non-Obvious Only)

## Two-Phase Architecture Evolution
- Phase 1 (COMPLETE): Go port of Rust CLI with feature parity
- Phase 2 (IN PROGRESS): REST API + React UI platform
- Phase 1 code reused by Phase 2 without refactoring

## Dual Binary Design Pattern
- CLI (`cmd/vault-audit/`) = standalone tool, calls `internal/commands/` directly
- API server (`cmd/server/`) = wraps CLI as subprocess, NOT library import
- Server spawns `./vault-audit` child processes via `internal/jobs/queue.go`
- Child process CWD = `uploadDir` so relative outputs land in correct location

## File Processing Architecture
- `processor.RunFiles()` auto-selects processing mode:
  - 1 file → sequential (no goroutine overhead)
  - 2+ files → parallel (goroutine-per-file, bounded by CPU count)
- Progress bar auto-switches to plain text when stderr is not TTY
- This enables same code to work in CLI and server contexts

## API Server Design Constraints
- All paths resolved to absolute on startup (`filepath.Abs()`)
- Job queue `workDir` = `uploadDir` for child process CWD
- Persistent stores (jobs, config) are optional (non-fatal if unavailable)
- SSE for real-time job progress streaming to UI
- Child processes write relative files to uploads directory

## Frontend Architecture
- React 18 + TypeScript + Vite
- TanStack Query for server state management
- Vite proxy routes `/api` to backend (dev mode)
- Production: nginx serves static files + proxies API

## Compressed File Strategy
- `internal/reader/reader.go` auto-detects `.gz`/`.zst` by extension
- Streaming decompression (no temp files)
- All commands transparently support compressed inputs
- Key differentiator from other audit tools

## Test Data Organization
- Shared test data: `internal/testdata/sample.ndjson`
- Tests use `runtime.Caller(0)` to locate testdata relative to test file
- Pattern: `filepath.Join(filepath.Dir(file), "..", "testdata", name)`

## Vault Client Design
- Respects standard Vault env vars: `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_TOKEN_FILE`, `VAULT_NAMESPACE`, `VAULT_SKIP_VERIFY`
- Token precedence: flag → `VAULT_TOKEN` → `VAULT_TOKEN_FILE`
- Default addr: `http://127.0.0.1:8200`

## Error Handling Philosophy
- Progress bar errors intentionally ignored (fire-and-forget)
- CSV writer errors checked via `w.Error()` AFTER loop, not per-write
- Intermediate JSON marshal/unmarshal errors intentionally ignored in some contexts
- See `.golangci.yml` for documented suppressions with rationale