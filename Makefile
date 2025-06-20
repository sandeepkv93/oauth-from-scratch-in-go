# OAuth Server Makefile

.PHONY: build run test clean setup docker-build docker-run deps

# Default target
all: deps build

# Install dependencies
deps:
	go mod tidy
	go mod download

# Build the server
build:
	go build -o bin/oauth-server ./cmd/server

# Run the server
run:
	go run ./cmd/server

# Run with environment file
run-env:
	export $$(cat .env | xargs) && go run ./cmd/server

# Test the application
test:
	go test -v ./...

# Test with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Setup database (requires PostgreSQL)
setup-db:
	createdb oauth_server 2>/dev/null || true
	psql -d oauth_server -f scripts/setup.sql

# Run tests against the server
test-oauth:
	./scripts/test_oauth.sh

# Format code
fmt:
	go fmt ./...

# Lint code (requires golangci-lint)
lint:
	golangci-lint run

# Security scan (requires gosec)
security:
	gosec ./...

# Docker build
docker-build:
	docker build -t oauth-server .

# Docker run
docker-run:
	docker run -p 8080:8080 oauth-server

# Development server with auto-reload (requires air)
dev:
	air

# Install development tools
install-tools:
	go install github.com/cosmtrek/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Generate self-signed certificates for HTTPS
generate-certs:
	mkdir -p certs
	openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
		-subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
		-keyout certs/server.key -out certs/server.crt

# Help
help:
	@echo "Available targets:"
	@echo "  deps         - Install Go dependencies"
	@echo "  build        - Build the OAuth server"
	@echo "  run          - Run the server"
	@echo "  run-env      - Run with .env file"
	@echo "  test         - Run unit tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  clean        - Clean build artifacts"
	@echo "  setup-db     - Setup PostgreSQL database"
	@echo "  test-oauth   - Run OAuth flow tests"
	@echo "  fmt          - Format code"
	@echo "  lint         - Lint code"
	@echo "  security     - Run security scan"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run Docker container"
	@echo "  dev          - Run development server with auto-reload"
	@echo "  install-tools - Install development tools"
	@echo "  generate-certs - Generate self-signed certificates"
	@echo "  help         - Show this help"