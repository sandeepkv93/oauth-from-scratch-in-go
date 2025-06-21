# Migration from Makefile to Taskfile

This project has been migrated from using Makefiles to [Taskfile](https://taskfile.dev/) for better cross-platform support, improved dependency management, and enhanced developer experience.

## Installation

### Install Task

**Linux/macOS (via script):**
```bash
sh -c "$(curl -ssL https://taskfile.dev/install.sh)"
```

**macOS (via Homebrew):**
```bash
brew install go-task/tap/go-task
```

**Windows (via Chocolatey):**
```bash
choco install go-task
```

**Go install:**
```bash
go install github.com/go-task/task/v3/cmd/task@latest
```

**Using the project's task (self-install):**
```bash
task install:taskfile
```

## Quick Start

After installing Task, you can use the same commands as before:

```bash
# Show all available tasks
task --list

# Run the default task (deps + build)
task

# Run specific tasks
task build
task test
task run
```

## Migration Guide

### Old Makefile Commands → New Task Commands

| Old Makefile Command | New Task Command | Description |
|---------------------|------------------|-------------|
| `make` or `make all` | `task` | Default: install deps and build |
| `make deps` | `task deps` | Install dependencies |
| `make build` | `task build` | Build the application |
| `make run` | `task run` | Run the built binary |
| `make run-env` | `task run:env` | Run with .env file |
| `make test` | `task test` | Run all tests |
| `make test-coverage` | `task test:coverage` | Run tests with coverage |
| `make clean` | `task clean` | Clean build artifacts |
| `make setup-db` | `task db:setup` | Setup database |
| `make test-oauth` | `task test:oauth` | Run OAuth tests |
| `make fmt` | `task fmt` | Format code |
| `make lint` | `task lint` | Lint code |
| `make security` | `task security` | Security scan |
| `make docker-build` | `task docker:build` | Build Docker image |
| `make docker-run` | `task docker:run` | Run Docker container |
| `make dev` | `task run:watch` | Development server |
| `make install-tools` | `task install:tools` | Install dev tools |
| `make generate-certs` | `task certs:generate` | Generate certificates |

### New Features in Taskfile

#### Enhanced Commands
- **`task run:dev`** - Direct go run without building
- **`task test:unit`** - Run only unit tests
- **`task test:integration`** - Run only integration tests
- **`task test:race`** - Run tests with race detector
- **`task test:bench`** - Run benchmark tests
- **`task lint:fix`** - Auto-fix linting issues
- **`task build:race`** - Build with race detector
- **`task check`** - Run all checks (fmt, lint, security, test)
- **`task ci`** - Complete CI pipeline

#### Docker Enhancements
- **`task docker:run:env`** - Run container with .env file
- **`task docker:shell`** - Interactive shell in container

#### Database Operations
- **`task db:migrate`** - Run migrations
- **`task db:reset`** - Reset database

#### Kubernetes Support
- **`task k8s:deploy`** - Deploy to Kubernetes
- **`task k8s:status`** - Check deployment status
- **`task k8s:logs`** - View logs
- **`task k8s:port-forward`** - Port forward to local

#### Git Operations
- **`task git:hooks:install`** - Install Git hooks
- **`task git:tag:create TAG=v1.0.0`** - Create and push tags
- **`task git:changelog`** - Generate changelog

#### Release Management
- **`task release`** - Build for multiple platforms
- **`task load:test`** - Run load tests
- **`task docs:serve`** - Serve documentation

## Key Improvements

### 1. Better Dependency Management
- Tasks can depend on other tasks
- Automatic dependency resolution
- Source/target file checking for incremental builds

### 2. Cross-Platform Support
- Works identically on Windows, macOS, and Linux
- No need for platform-specific Makefiles

### 3. Enhanced Output
- Colored output for better readability
- Progress indicators
- Clear task descriptions

### 4. Modular Organization
- Main tasks in `Taskfile.yml`
- Kubernetes tasks in `.taskfile/k8s.yml`
- Git operations in `.taskfile/git.yml`

### 5. Advanced Features
- Environment variable support
- Template variables
- Conditional execution
- File watching capabilities

## Environment Variables

Taskfile supports the same environment variables as the Makefile, plus additional ones:

```bash
# Build configuration
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

# Application configuration
export SERVER_PORT=8080
export DB_HOST=localhost
export JWT_SECRET=your-secret
```

## IDE Integration

### VS Code
Install the "Task" extension for VS Code to run tasks directly from the editor.

### GoLand/IntelliJ
Configure external tools to run Task commands.

## Backward Compatibility

The Makefile is kept for backward compatibility but marked as deprecated. It will be removed in a future version.

## Troubleshooting

### Task not found
```bash
# Install Task globally
task install:taskfile

# Or use go install
go install github.com/go-task/task/v3/cmd/task@latest
```

### Permission issues on Unix systems
```bash
chmod +x $(which task)
```

### Windows execution policy
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Migration Checklist

- [ ] Install Task (`task install:taskfile`)
- [ ] Install development tools (`task install:tools`)
- [ ] Test basic commands (`task build`, `task test`)
- [ ] Setup Git hooks (`task git:hooks:install`)
- [ ] Update CI/CD scripts to use `task ci`
- [ ] Update documentation references
- [ ] Remove Makefile dependency from team workflows

## Getting Help

```bash
# List all available tasks
task --list

# Get help for a specific task
task --summary build

# Show task dependencies
task --deps build
```

For more information about Taskfile, visit: https://taskfile.dev/