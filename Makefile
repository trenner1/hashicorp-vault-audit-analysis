BINARY     := vault-audit
MODULE     := github.com/trenner1/hashicorp-vault-audit-analysis
CMD        := ./cmd/vault-audit
BUILD_DIR  := ./build
LDFLAGS    := -ldflags="-s -w"
GOFLAGS    := -trimpath

.PHONY: all build install test lint clean tidy vet

all: build

## build: Compile binary to ./build/vault-audit
build:
	@mkdir -p $(BUILD_DIR)
	go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD)
	@echo "Built: $(BUILD_DIR)/$(BINARY)"

## install: Install binary to GOPATH/bin
install:
	go install $(GOFLAGS) $(LDFLAGS) $(CMD)

## test: Run all tests
test:
	go test ./... -v -count=1

## test-race: Run tests with race detector
test-race:
	go test ./... -race -count=1

## bench: Run benchmarks
bench:
	go test ./... -bench=. -benchmem -run=^$

## lint: Run staticcheck and vet
lint: vet
	@which staticcheck >/dev/null 2>&1 || go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

## vet: Run go vet
vet:
	go vet ./...

## tidy: Tidy and verify modules
tidy:
	go mod tidy
	go mod verify

## clean: Remove build artifacts
clean:
	rm -rf $(BUILD_DIR)

## release: Build release binaries for multiple platforms
release:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux   GOARCH=amd64  go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64  $(CMD)
	GOOS=linux   GOARCH=arm64  go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-arm64  $(CMD)
	GOOS=darwin  GOARCH=amd64  go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 $(CMD)
	GOOS=darwin  GOARCH=arm64  go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 $(CMD)
	GOOS=windows GOARCH=amd64  go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe $(CMD)
	@echo "Release binaries built in $(BUILD_DIR)/"

help:
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

# Phase 2: API server
.PHONY: server dev-server

## server: Build API server binary
server:
	go build -o server ./cmd/server/

## dev-server: Run API server with vault-audit binary
dev-server: vault-audit server
	VAULT_AUDIT_BINARY=./vault-audit ./server

# Frontend
.PHONY: frontend-install frontend-dev frontend-build

## frontend-install: Install frontend dependencies
frontend-install:
	cd frontend && npm install

## frontend-dev: Start frontend dev server
frontend-dev:
	cd frontend && npm run dev

## frontend-build: Build frontend for production
frontend-build:
	cd frontend && npm run build

# Docker
.PHONY: docker-build docker-up docker-down

## docker-build: Build Docker images
docker-build:
	docker-compose build

## docker-up: Start Docker containers
docker-up:
	docker-compose up -d

## docker-down: Stop Docker containers
docker-down:
	docker-compose down

# Full dev: run API server + frontend dev server concurrently
.PHONY: dev

## dev: Start API server and frontend dev server concurrently
dev: vault-audit server
	@echo "Starting API server on :8080 and frontend on :5173"
	@VAULT_AUDIT_BINARY=./vault-audit ./server & cd frontend && npm run dev
