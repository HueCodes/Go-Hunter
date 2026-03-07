# Go-Hunter Makefile
# Comprehensive build, test, and development automation

# ==============================================================================
# Variables
# ==============================================================================

# Go settings
GO ?= go
GOFLAGS ?=
CGO_ENABLED ?= 0

# Project settings
PROJECT_NAME := go-hunter
MODULE := github.com/hugh/go-hunter
SERVER_PKG := ./cmd/server
WORKER_PKG := ./cmd/worker

# Build settings
BUILD_DIR := ./bin
SERVER_BINARY := $(BUILD_DIR)/server
WORKER_BINARY := $(BUILD_DIR)/worker

# Version info (inject at build time)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -ldflags "-w -s -X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Docker settings
DOCKER_COMPOSE := docker compose
DOCKER_REGISTRY ?=
IMAGE_NAME := $(PROJECT_NAME)
IMAGE_TAG ?= $(VERSION)

# Database settings
DATABASE_URL ?= postgres://gohunter:gohunter_secret@localhost:5432/gohunter?sslmode=disable
MIGRATIONS_DIR := ./migrations

# Colors for terminal output
COLOR_RESET := \033[0m
COLOR_GREEN := \033[32m
COLOR_YELLOW := \033[33m
COLOR_BLUE := \033[34m
COLOR_CYAN := \033[36m

# Release platforms
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# ==============================================================================
# Help
# ==============================================================================

.PHONY: help
help: ## Show all available commands
	@echo "$(COLOR_CYAN)Go-Hunter Development Commands$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_GREEN)Usage:$(COLOR_RESET) make [target]"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf ""} /^[a-zA-Z_-]+:.*?##/ { printf "  $(COLOR_YELLOW)%-20s$(COLOR_RESET) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""

.DEFAULT_GOAL := help

# ==============================================================================
# Setup
# ==============================================================================

.PHONY: setup
setup: ## Install dependencies (go mod download, tools)
	@echo "$(COLOR_BLUE)==> Downloading Go modules...$(COLOR_RESET)"
	$(GO) mod download
	$(GO) mod verify
	@echo "$(COLOR_BLUE)==> Installing dev tools...$(COLOR_RESET)"
	@$(MAKE) install-tools
	@echo "$(COLOR_GREEN)==> Setup complete!$(COLOR_RESET)"

.PHONY: install-tools
install-tools: ## Install dev tools (golangci-lint, migrate, air)
	@echo "$(COLOR_BLUE)==> Installing golangci-lint...$(COLOR_RESET)"
	@command -v golangci-lint >/dev/null 2>&1 || { \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin; \
	}
	@echo "$(COLOR_BLUE)==> Installing golang-migrate...$(COLOR_RESET)"
	@command -v migrate >/dev/null 2>&1 || { \
		$(GO) install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest; \
	}
	@echo "$(COLOR_BLUE)==> Installing air (hot reload)...$(COLOR_RESET)"
	@command -v air >/dev/null 2>&1 || { \
		$(GO) install github.com/air-verse/air@latest; \
	}
	@echo "$(COLOR_GREEN)==> Tools installed!$(COLOR_RESET)"

# ==============================================================================
# Development
# ==============================================================================

.PHONY: dev
dev: ## Run server with hot reload (use air if available, else go run)
	@echo "$(COLOR_BLUE)==> Starting server in development mode...$(COLOR_RESET)"
	@if command -v air >/dev/null 2>&1; then \
		air -c .air.toml 2>/dev/null || air -- -c . $(SERVER_PKG); \
	else \
		echo "$(COLOR_YELLOW)air not found, using go run (install with: make install-tools)$(COLOR_RESET)"; \
		$(GO) run $(SERVER_PKG); \
	fi

.PHONY: dev-worker
dev-worker: ## Run worker in development mode
	@echo "$(COLOR_BLUE)==> Starting worker in development mode...$(COLOR_RESET)"
	$(GO) run $(WORKER_PKG)

.PHONY: dev-all
dev-all: ## Run both server and worker (requires tmux or run in separate terminals)
	@echo "$(COLOR_BLUE)==> Starting server and worker...$(COLOR_RESET)"
	@if command -v tmux >/dev/null 2>&1; then \
		tmux new-session -d -s gohunter 'make dev' && \
		tmux split-window -h 'make dev-worker' && \
		tmux attach-session -t gohunter; \
	else \
		echo "$(COLOR_YELLOW)tmux not found. Run in separate terminals:$(COLOR_RESET)"; \
		echo "  Terminal 1: make dev"; \
		echo "  Terminal 2: make dev-worker"; \
	fi

.PHONY: run
run: build ## Build and run the server
	@echo "$(COLOR_BLUE)==> Running server...$(COLOR_RESET)"
	$(SERVER_BINARY)

.PHONY: run-worker
run-worker: build-worker ## Build and run the worker
	@echo "$(COLOR_BLUE)==> Running worker...$(COLOR_RESET)"
	$(WORKER_BINARY)

# ==============================================================================
# Infrastructure
# ==============================================================================

.PHONY: infra-up
infra-up: ## Start PostgreSQL and Redis via docker-compose
	@echo "$(COLOR_BLUE)==> Starting infrastructure services...$(COLOR_RESET)"
	$(DOCKER_COMPOSE) up -d postgres redis
	@echo "$(COLOR_GREEN)==> Waiting for services to be healthy...$(COLOR_RESET)"
	@sleep 3
	@$(DOCKER_COMPOSE) ps

.PHONY: infra-down
infra-down: ## Stop infrastructure
	@echo "$(COLOR_BLUE)==> Stopping infrastructure services...$(COLOR_RESET)"
	$(DOCKER_COMPOSE) stop postgres redis
	@echo "$(COLOR_GREEN)==> Infrastructure stopped$(COLOR_RESET)"

.PHONY: infra-logs
infra-logs: ## View infrastructure logs
	$(DOCKER_COMPOSE) logs -f postgres redis

.PHONY: infra-status
infra-status: ## Show infrastructure status
	@echo "$(COLOR_BLUE)==> Infrastructure status:$(COLOR_RESET)"
	@$(DOCKER_COMPOSE) ps postgres redis

# ==============================================================================
# Database
# ==============================================================================

.PHONY: db-migrate
db-migrate: ## Run migrations up
	@echo "$(COLOR_BLUE)==> Running database migrations...$(COLOR_RESET)"
	@if command -v migrate >/dev/null 2>&1; then \
		migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" up; \
	else \
		echo "$(COLOR_YELLOW)migrate not found, install with: make install-tools$(COLOR_RESET)"; \
		exit 1; \
	fi
	@echo "$(COLOR_GREEN)==> Migrations complete$(COLOR_RESET)"

.PHONY: db-migrate-down
db-migrate-down: ## Roll back last migration
	@echo "$(COLOR_BLUE)==> Rolling back last migration...$(COLOR_RESET)"
	@if command -v migrate >/dev/null 2>&1; then \
		migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down 1; \
	else \
		echo "$(COLOR_YELLOW)migrate not found, install with: make install-tools$(COLOR_RESET)"; \
		exit 1; \
	fi
	@echo "$(COLOR_GREEN)==> Rollback complete$(COLOR_RESET)"

.PHONY: db-migrate-status
db-migrate-status: ## Show migration status
	@echo "$(COLOR_BLUE)==> Migration status:$(COLOR_RESET)"
	@if command -v migrate >/dev/null 2>&1; then \
		migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" version; \
	else \
		echo "$(COLOR_YELLOW)migrate not found, install with: make install-tools$(COLOR_RESET)"; \
	fi

.PHONY: db-reset
db-reset: ## Drop and recreate database
	@echo "$(COLOR_YELLOW)==> WARNING: This will delete all data!$(COLOR_RESET)"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo "$(COLOR_BLUE)==> Dropping database...$(COLOR_RESET)"
	@PGPASSWORD=gohunter_secret psql -h localhost -U gohunter -d postgres -c "DROP DATABASE IF EXISTS gohunter;" 2>/dev/null || true
	@echo "$(COLOR_BLUE)==> Creating database...$(COLOR_RESET)"
	@PGPASSWORD=gohunter_secret psql -h localhost -U gohunter -d postgres -c "CREATE DATABASE gohunter;" 2>/dev/null || true
	@echo "$(COLOR_BLUE)==> Running migrations...$(COLOR_RESET)"
	@$(MAKE) db-migrate
	@echo "$(COLOR_GREEN)==> Database reset complete$(COLOR_RESET)"

.PHONY: db-seed
db-seed: ## Seed with sample data
	@echo "$(COLOR_BLUE)==> Seeding database...$(COLOR_RESET)"
	$(GO) run ./scripts/seed.go
	@echo "$(COLOR_GREEN)==> Seeding complete$(COLOR_RESET)"

.PHONY: db-create-migration
db-create-migration: ## Create a new migration (usage: make db-create-migration NAME=add_users)
	@if [ -z "$(NAME)" ]; then \
		echo "$(COLOR_YELLOW)Usage: make db-create-migration NAME=migration_name$(COLOR_RESET)"; \
		exit 1; \
	fi
	@echo "$(COLOR_BLUE)==> Creating migration: $(NAME)$(COLOR_RESET)"
	@if command -v migrate >/dev/null 2>&1; then \
		migrate create -ext sql -dir $(MIGRATIONS_DIR) -seq $(NAME); \
	else \
		echo "$(COLOR_YELLOW)migrate not found, install with: make install-tools$(COLOR_RESET)"; \
		exit 1; \
	fi

# ==============================================================================
# Testing
# ==============================================================================

.PHONY: test
test: ## Run all tests
	@echo "$(COLOR_BLUE)==> Running tests...$(COLOR_RESET)"
	$(GO) test $(GOFLAGS) ./...
	@echo "$(COLOR_GREEN)==> Tests passed$(COLOR_RESET)"

.PHONY: test-unit
test-unit: ## Run unit tests only
	@echo "$(COLOR_BLUE)==> Running unit tests...$(COLOR_RESET)"
	$(GO) test $(GOFLAGS) -short ./...
	@echo "$(COLOR_GREEN)==> Unit tests passed$(COLOR_RESET)"

.PHONY: test-integration
test-integration: ## Run integration tests (with build tag)
	@echo "$(COLOR_BLUE)==> Running integration tests...$(COLOR_RESET)"
	$(GO) test $(GOFLAGS) -tags=integration ./...
	@echo "$(COLOR_GREEN)==> Integration tests passed$(COLOR_RESET)"

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	@echo "$(COLOR_BLUE)==> Running tests with coverage...$(COLOR_RESET)"
	$(GO) test $(GOFLAGS) -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "$(COLOR_GREEN)==> Coverage report generated: coverage.html$(COLOR_RESET)"
	@$(GO) tool cover -func=coverage.out | tail -1

.PHONY: test-race
test-race: ## Run tests with race detector
	@echo "$(COLOR_BLUE)==> Running tests with race detector...$(COLOR_RESET)"
	CGO_ENABLED=1 $(GO) test $(GOFLAGS) -race ./...
	@echo "$(COLOR_GREEN)==> Race detection tests passed$(COLOR_RESET)"

.PHONY: test-verbose
test-verbose: ## Run tests with verbose output
	@echo "$(COLOR_BLUE)==> Running tests (verbose)...$(COLOR_RESET)"
	$(GO) test $(GOFLAGS) -v ./...

.PHONY: bench
bench: ## Run benchmarks
	@echo "$(COLOR_BLUE)==> Running benchmarks...$(COLOR_RESET)"
	$(GO) test $(GOFLAGS) -bench=. -benchmem ./...

# ==============================================================================
# Code Quality
# ==============================================================================

.PHONY: lint
lint: ## Run golangci-lint
	@echo "$(COLOR_BLUE)==> Running linter...$(COLOR_RESET)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "$(COLOR_YELLOW)golangci-lint not found, install with: make install-tools$(COLOR_RESET)"; \
		exit 1; \
	fi
	@echo "$(COLOR_GREEN)==> Linting passed$(COLOR_RESET)"

.PHONY: fmt
fmt: ## Format code with gofmt
	@echo "$(COLOR_BLUE)==> Formatting code...$(COLOR_RESET)"
	$(GO) fmt ./...
	@echo "$(COLOR_GREEN)==> Formatting complete$(COLOR_RESET)"

.PHONY: vet
vet: ## Run go vet
	@echo "$(COLOR_BLUE)==> Running go vet...$(COLOR_RESET)"
	$(GO) vet ./...
	@echo "$(COLOR_GREEN)==> Vet passed$(COLOR_RESET)"

.PHONY: check
check: fmt vet lint test ## Run all checks (fmt, vet, lint, test)
	@echo "$(COLOR_GREEN)==> All checks passed!$(COLOR_RESET)"

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	@echo "$(COLOR_BLUE)==> Tidying modules...$(COLOR_RESET)"
	$(GO) mod tidy
	@echo "$(COLOR_GREEN)==> Modules tidied$(COLOR_RESET)"

# ==============================================================================
# Build
# ==============================================================================

.PHONY: build
build: build-server build-worker ## Build server and worker binaries
	@echo "$(COLOR_GREEN)==> Build complete$(COLOR_RESET)"

.PHONY: build-server
build-server: ## Build server binary
	@echo "$(COLOR_BLUE)==> Building server...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(LDFLAGS) -o $(SERVER_BINARY) $(SERVER_PKG)
	@echo "$(COLOR_GREEN)==> Server built: $(SERVER_BINARY)$(COLOR_RESET)"

.PHONY: build-worker
build-worker: ## Build worker binary
	@echo "$(COLOR_BLUE)==> Building worker...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(LDFLAGS) -o $(WORKER_BINARY) $(WORKER_PKG)
	@echo "$(COLOR_GREEN)==> Worker built: $(WORKER_BINARY)$(COLOR_RESET)"

.PHONY: build-linux
build-linux: ## Build for Linux (amd64)
	@echo "$(COLOR_BLUE)==> Building for Linux amd64...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/server-linux-amd64 $(SERVER_PKG)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/worker-linux-amd64 $(WORKER_PKG)
	@echo "$(COLOR_GREEN)==> Linux build complete$(COLOR_RESET)"

.PHONY: clean
clean: ## Remove build artifacts
	@echo "$(COLOR_BLUE)==> Cleaning build artifacts...$(COLOR_RESET)"
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	@echo "$(COLOR_GREEN)==> Clean complete$(COLOR_RESET)"

# ==============================================================================
# Docker
# ==============================================================================

.PHONY: docker-build
docker-build: ## Build Docker images
	@echo "$(COLOR_BLUE)==> Building Docker images...$(COLOR_RESET)"
	$(DOCKER_COMPOSE) build server worker
	@echo "$(COLOR_GREEN)==> Docker images built$(COLOR_RESET)"

.PHONY: docker-up
docker-up: ## Run full stack with Docker Compose
	@echo "$(COLOR_BLUE)==> Starting full stack with Docker...$(COLOR_RESET)"
	$(DOCKER_COMPOSE) up -d
	@echo "$(COLOR_GREEN)==> Stack is running$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_CYAN)Services:$(COLOR_RESET)"
	@echo "  Server:   http://localhost:8080"
	@echo "  Postgres: localhost:5432"
	@echo "  Redis:    localhost:6379"
	@echo ""
	@$(DOCKER_COMPOSE) ps

.PHONY: docker-down
docker-down: ## Stop Docker stack
	@echo "$(COLOR_BLUE)==> Stopping Docker stack...$(COLOR_RESET)"
	$(DOCKER_COMPOSE) down
	@echo "$(COLOR_GREEN)==> Stack stopped$(COLOR_RESET)"

.PHONY: docker-logs
docker-logs: ## View Docker logs
	$(DOCKER_COMPOSE) logs -f

.PHONY: docker-logs-server
docker-logs-server: ## View server logs
	$(DOCKER_COMPOSE) logs -f server

.PHONY: docker-logs-worker
docker-logs-worker: ## View worker logs
	$(DOCKER_COMPOSE) logs -f worker

.PHONY: docker-restart
docker-restart: ## Restart Docker stack
	@echo "$(COLOR_BLUE)==> Restarting Docker stack...$(COLOR_RESET)"
	$(DOCKER_COMPOSE) restart
	@echo "$(COLOR_GREEN)==> Stack restarted$(COLOR_RESET)"

.PHONY: docker-clean
docker-clean: ## Remove Docker containers, volumes, and images
	@echo "$(COLOR_YELLOW)==> WARNING: This will remove all containers, volumes, and images!$(COLOR_RESET)"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	$(DOCKER_COMPOSE) down -v --rmi local
	@echo "$(COLOR_GREEN)==> Docker cleanup complete$(COLOR_RESET)"

.PHONY: docker-shell-server
docker-shell-server: ## Open shell in server container
	$(DOCKER_COMPOSE) exec server sh

.PHONY: docker-shell-worker
docker-shell-worker: ## Open shell in worker container
	$(DOCKER_COMPOSE) exec worker sh

# ==============================================================================
# Release
# ==============================================================================

.PHONY: release
release: clean ## Build release binaries for multiple platforms
	@echo "$(COLOR_BLUE)==> Building release binaries...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)/release
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/}; \
		echo "$(COLOR_CYAN)Building for $$GOOS/$$GOARCH...$(COLOR_RESET)"; \
		ext=""; \
		if [ "$$GOOS" = "windows" ]; then ext=".exe"; fi; \
		GOOS=$$GOOS GOARCH=$$GOARCH CGO_ENABLED=0 $(GO) build $(LDFLAGS) \
			-o $(BUILD_DIR)/release/server-$$GOOS-$$GOARCH$$ext $(SERVER_PKG); \
		GOOS=$$GOOS GOARCH=$$GOARCH CGO_ENABLED=0 $(GO) build $(LDFLAGS) \
			-o $(BUILD_DIR)/release/worker-$$GOOS-$$GOARCH$$ext $(WORKER_PKG); \
	done
	@echo ""
	@echo "$(COLOR_GREEN)==> Release binaries built:$(COLOR_RESET)"
	@ls -la $(BUILD_DIR)/release/

.PHONY: release-checksums
release-checksums: release ## Generate checksums for release binaries
	@echo "$(COLOR_BLUE)==> Generating checksums...$(COLOR_RESET)"
	@cd $(BUILD_DIR)/release && shasum -a 256 * > checksums.txt
	@echo "$(COLOR_GREEN)==> Checksums generated: $(BUILD_DIR)/release/checksums.txt$(COLOR_RESET)"

# ==============================================================================
# Utilities
# ==============================================================================

.PHONY: deps
deps: ## List all dependencies
	@echo "$(COLOR_BLUE)==> Project dependencies:$(COLOR_RESET)"
	$(GO) list -m all

.PHONY: deps-update
deps-update: ## Update all dependencies
	@echo "$(COLOR_BLUE)==> Updating dependencies...$(COLOR_RESET)"
	$(GO) get -u ./...
	$(GO) mod tidy
	@echo "$(COLOR_GREEN)==> Dependencies updated$(COLOR_RESET)"

.PHONY: deps-graph
deps-graph: ## Show dependency graph (requires graphviz)
	@echo "$(COLOR_BLUE)==> Generating dependency graph...$(COLOR_RESET)"
	@if command -v dot >/dev/null 2>&1; then \
		$(GO) mod graph | sed -Ee 's/@[^[:space:]]+//g' | sort | uniq | \
		awk '{print "\"" $$1 "\" -> \"" $$2 "\";"}' | \
		sed -e 's/^/  /' -e '1s/^/digraph deps {\n/' -e '$$s/$$/\n}/' | \
		dot -Tpng -o deps.png; \
		echo "$(COLOR_GREEN)==> Dependency graph saved: deps.png$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)graphviz not installed, showing text graph$(COLOR_RESET)"; \
		$(GO) mod graph; \
	fi

.PHONY: version
version: ## Show version information
	@echo "$(COLOR_CYAN)Go-Hunter$(COLOR_RESET)"
	@echo "  Version:    $(VERSION)"
	@echo "  Commit:     $(COMMIT)"
	@echo "  Build Time: $(BUILD_TIME)"
	@echo "  Go Version: $(shell $(GO) version | cut -d' ' -f3)"

.PHONY: env
env: ## Show environment variables
	@echo "$(COLOR_CYAN)Environment:$(COLOR_RESET)"
	@echo "  GO:           $(GO)"
	@echo "  GOFLAGS:      $(GOFLAGS)"
	@echo "  CGO_ENABLED:  $(CGO_ENABLED)"
	@echo "  VERSION:      $(VERSION)"
	@echo "  BUILD_DIR:    $(BUILD_DIR)"
	@echo "  DATABASE_URL: $(DATABASE_URL)"

.PHONY: generate
generate: ## Run go generate
	@echo "$(COLOR_BLUE)==> Running go generate...$(COLOR_RESET)"
	$(GO) generate ./...
	@echo "$(COLOR_GREEN)==> Generate complete$(COLOR_RESET)"

.PHONY: mock
mock: ## Generate mocks (if using mockgen)
	@echo "$(COLOR_BLUE)==> Generating mocks...$(COLOR_RESET)"
	@if command -v mockgen >/dev/null 2>&1; then \
		$(GO) generate ./...; \
	else \
		echo "$(COLOR_YELLOW)mockgen not found, install with: go install github.com/golang/mock/mockgen@latest$(COLOR_RESET)"; \
	fi
