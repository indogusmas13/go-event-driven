# Go Event-Driven Microservices Makefile

# Variables
APP_NAME=go-event-driven
BFF_BINARY=bff
USER_SERVICE_BINARY=user-service
MIGRATE_BINARY=migrate

# Build directory
BUILD_DIR=build

# Docker
DOCKER_COMPOSE=docker-compose

# Go commands
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt

# Default target
.DEFAULT_GOAL := help

## help: Show this help message
.PHONY: help
help:
	@echo "Available commands:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## build: Build all binaries
.PHONY: build
build: build-bff build-user-service build-migrate

## build-bff: Build BFF service binary
.PHONY: build-bff
build-bff:
	@echo "Building BFF service..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BFF_BINARY) ./cmd/bff

## build-user-service: Build User service binary
.PHONY: build-user-service
build-user-service:
	@echo "Building User service..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(USER_SERVICE_BINARY) ./cmd/user-service

## build-migrate: Build migration tool
.PHONY: build-migrate
build-migrate:
	@echo "Building migration tool..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(MIGRATE_BINARY) ./cmd/migrate

## run: Run all services locally
.PHONY: run
run:
	@echo "Starting services with Docker Compose..."
	$(DOCKER_COMPOSE) up --build

## run-bff: Run BFF service locally
.PHONY: run-bff
run-bff:
	@echo "Starting BFF service..."
	$(GOCMD) run ./cmd/bff

## run-user-service: Run User service locally
.PHONY: run-user-service
run-user-service:
	@echo "Starting User service..."
	$(GOCMD) run ./cmd/user-service

## test: Run all tests
.PHONY: test
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

## test-coverage: Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## clean: Clean build files
.PHONY: clean
clean:
	@echo "Cleaning build files..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

## deps: Download and tidy dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

## fmt: Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...

## lint: Run linter (requires golangci-lint)
.PHONY: lint
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

## docker-build: Build Docker images
.PHONY: docker-build
docker-build:
	@echo "Building Docker images..."
	$(DOCKER_COMPOSE) build

## docker-up: Start services with Docker Compose
.PHONY: docker-up
docker-up:
	@echo "Starting services with Docker Compose..."
	$(DOCKER_COMPOSE) up -d

## docker-down: Stop Docker Compose services
.PHONY: docker-down
docker-down:
	@echo "Stopping Docker Compose services..."
	$(DOCKER_COMPOSE) down

## docker-logs: View Docker Compose logs
.PHONY: docker-logs
docker-logs:
	$(DOCKER_COMPOSE) logs -f

## migrate-up: Run database migrations
.PHONY: migrate-up
migrate-up:
	@echo "Running database migrations..."
	./scripts/migrate.sh up

## migrate-down: Rollback database migrations
.PHONY: migrate-down
migrate-down:
	@echo "Rolling back database migrations..."
	./scripts/migrate.sh down

## migrate-create: Create new migration (usage: make migrate-create name=migration_name)
.PHONY: migrate-create
migrate-create:
	@if [ -z "$(name)" ]; then \
		echo "Error: migration name is required. Usage: make migrate-create name=migration_name"; \
		exit 1; \
	fi
	@echo "Creating migration: $(name)"
	./scripts/migrate.sh create $(name)

## migrate-status: Show migration status
.PHONY: migrate-status
migrate-status:
	@echo "Checking migration status..."
	./scripts/migrate.sh status

## setup: Initial project setup
.PHONY: setup
setup:
	@echo "Setting up project..."
	chmod +x scripts/*.sh
	$(MAKE) deps
	@echo "Project setup complete!"

## dev: Start development environment
.PHONY: dev
dev:
	@echo "Starting development environment..."
	$(DOCKER_COMPOSE) up postgres kafka -d
	@echo "Waiting for services to be ready..."
	@sleep 5
	$(MAKE) migrate-up
	@echo "Development environment ready!"

## stop: Stop all services
.PHONY: stop
stop:
	@echo "Stopping all services..."
	$(DOCKER_COMPOSE) down

## logs: Show logs for all services
.PHONY: logs
logs: docker-logs

## health: Check service health
.PHONY: health
health:
	@echo "Checking service health..."
	@curl -s http://localhost:8080/health || echo "BFF service not responding"
	@curl -s http://localhost:8081/health || echo "User service not responding"

## install-tools: Install required development tools
.PHONY: install-tools
install-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	@echo "Development tools installed!"

.PHONY: all
all: clean fmt lint test build