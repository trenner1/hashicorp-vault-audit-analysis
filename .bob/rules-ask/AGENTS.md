# Project Documentation Rules (Non-Obvious Only)

## Architecture Documentation
- `ARCHITECTURE.md` describes two-phase evolution: Phase 1 (Go port) → Phase 2 (Platform)
- Phase 1 is COMPLETE (Go CLI with all Rust features)
- Phase 2 is IN PROGRESS (API server + React UI)

## Dual Binary Architecture
- `cmd/vault-audit/` = standalone CLI tool (complete, production-ready)
- `cmd/server/` = REST API server that wraps CLI as subprocess
- Server does NOT import CLI as library - spawns it as child process
- This is intentional design to reuse CLI without refactoring

## Frontend Architecture
- React 18 + TypeScript + Vite
- TanStack Query for server state
- Recharts for visualization
- Tailwind CSS v4 for styling
- Proxy config in `vite.config.ts` routes `/api` to backend

## Test Organization
- Test files use `_test.go` suffix (standard Go convention)
- Shared test data in `internal/testdata/sample.ndjson`
- Tests use `runtime.Caller(0)` pattern to locate testdata
- Pattern: `filepath.Join(filepath.Dir(file), "..", "testdata", name)`

## Build System
- Makefile provides all build/test/lint commands
- `make build` → CLI binary at `./build/vault-audit`
- `make server` → API server at `./server`
- `make dev` → runs both API server + frontend dev server concurrently

## Docker Deployment
- `docker-compose.yml` defines API + UI services
- API uses `Dockerfile.api`, UI uses `Dockerfile.ui`
- Volumes: `uploads` (log files), `data` (persistent config/jobs)
- Environment variables control all configuration

## Compressed File Support
- All commands transparently support `.gz` and `.zst` files
- Streaming decompression (no temp files)
- This is a key differentiator from other audit tools

## Parallel Processing
- `processor.RunFiles()` auto-selects: 1 file = sequential, 2+ = parallel
- Parallel uses goroutine-per-file (bounded by CPU count)
- Progress bar switches to plain text when stderr is not TTY