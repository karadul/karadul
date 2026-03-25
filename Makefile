.PHONY: build build-all test test-race test-cover clean install lint fmt vet help

# Build variables
BINARY_NAME=karadul
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Default target
.DEFAULT_GOAL := help

help: ## Show this help
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary for current platform
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/karadul

build-all: ## Build for all platforms (linux, darwin, windows)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 ./cmd/karadul
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 ./cmd/karadul
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 ./cmd/karadul
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 ./cmd/karadul
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe ./cmd/karadul

test: ## Run tests
	go test -v -count=1 ./...

test-race: ## Run tests with race detector
	go test -race -count=1 ./...

test-cover: ## Run tests with coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

test-cover-html: ## Generate HTML coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

benchmark: ## Run benchmarks
	go test -bench=. -benchmem ./...

lint: ## Run linters (requires golangci-lint)
	golangci-lint run ./...

fmt: ## Format code
	go fmt ./...

vet: ## Run go vet
	go vet ./...

check: fmt vet test-race ## Run all checks (format, vet, tests with race)

clean: ## Clean build artifacts
	rm -f $(BINARY_NAME)
	rm -rf dist/
	rm -f coverage.out coverage.html
	go clean -cache

install: build ## Install binary to $GOPATH/bin
	go install $(LDFLAGS) ./cmd/karadul

run-server: build ## Build and run coordination server
	./$(BINARY_NAME) server --addr=:8080

dev-setup: ## Setup development environment
	go mod download
	go mod verify

mod-tidy: ## Tidy go modules
	go mod tidy

update-deps: ## Update dependencies
	go get -u ./...
	go mod tidy
