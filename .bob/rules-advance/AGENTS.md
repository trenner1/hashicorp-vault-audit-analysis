# Project Advanced Coding Rules (Non-Obvious Only)

## Dual Architecture Pattern
- CLI binary (`cmd/vault-audit/`) and API server (`cmd/server/`) are SEPARATE executables
- Server spawns CLI as subprocess via `internal/jobs/queue.go`, NOT library import
- Commands in `internal/commands/` are called directly by CLI, wrapped by server

## File Processing Architecture
- `processor.RunFiles()` auto-selects sequential (1 file) vs parallel (2+ files)
- Parallel mode uses goroutine-per-file bounded by `runtime.NumCPU()`
- Progress bar auto-switches to plain text when stderr is not TTY (server context)

## Child Process Working Directory
- Job queue sets `workDir` = `uploadDir` for spawned processes
- Relative output files (e.g., `entity_mappings.json`) land in uploads directory
- This is intentional so Files API can discover generated outputs

## Compressed File Support
- `internal/reader/reader.go` auto-detects `.gz`/`.zst` by extension
- Streaming decompression (no temp files created)
- All commands transparently support compressed inputs

## Test Data Pattern
- Shared test data: `internal/testdata/sample.ndjson`
- Tests use `runtime.Caller(0)` to locate testdata relative to test file
- Pattern: `filepath.Join(filepath.Dir(file), "..", "testdata", name)`

## Error Handling Conventions
- Progress bar errors intentionally ignored (fire-and-forget)
- CSV writer errors checked via `w.Error()` AFTER loop, not per-write
- Intermediate JSON marshal/unmarshal errors intentionally ignored in some contexts
- See `.golangci.yml` for documented suppressions

## Vault Client Token Precedence
- Flag → `VAULT_TOKEN` env → `VAULT_TOKEN_FILE` env
- Default addr: `http://127.0.0.1:8200`
- All standard Vault env vars respected

## API Server Path Resolution
- All paths resolved to absolute on startup via `filepath.Abs()`
- Persistent stores (jobs, config) are optional (non-fatal if unavailable)
- SSE used for real-time job progress streaming

## Browser & MCP Tools
- This mode has access to browser_action and MCP tools
- Use for web-based testing or external integrations