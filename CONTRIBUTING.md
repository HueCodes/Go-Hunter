# Contributing to Go-Hunter

Thank you for your interest in contributing to Go-Hunter. This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Welcome](#welcome)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Style](#code-style)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)
- [Architecture Overview](#architecture-overview)

## Welcome

We welcome contributions from the community. Whether you are fixing a bug, improving documentation, or adding a new feature, your contributions help make Go-Hunter better for everyone.

Before contributing, please take a moment to review this document to ensure a smooth contribution process.

## Getting Started

### Prerequisites

Ensure you have the following installed on your system:

- **Go 1.22+** - [Download Go](https://go.dev/dl/)
- **Docker** - Required for running PostgreSQL and Redis locally
- **Make** - For running build and development commands

Optional but recommended:

- **golangci-lint** - For code linting
- **golang-migrate** - For database migrations

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

   ```bash
   git clone https://github.com/YOUR_USERNAME/go-hunter.git
   cd go-hunter
   ```

3. Add the upstream repository as a remote:

   ```bash
   git remote add upstream https://github.com/hugh/go-hunter.git
   ```

### Setup Steps

1. Install Go dependencies and development tools:

   ```bash
   make setup
   ```

   This command downloads Go modules and installs required development tools (golangci-lint, golang-migrate, air).

2. Copy the environment configuration:

   ```bash
   cp .env.example .env
   ```

3. Start the infrastructure services (PostgreSQL and Redis):

   ```bash
   make infra-up
   ```

4. Run database migrations:

   ```bash
   make db-migrate
   ```

5. Verify the setup by running tests:

   ```bash
   make test
   ```

## Development Workflow

### Creating a Branch

Create a new branch for your work from the latest main:

```bash
git fetch upstream
git checkout -b feature/your-feature-name upstream/main
```

Use descriptive branch names with prefixes:

- `feature/` - New features
- `fix/` - Bug fixes
- `refactor/` - Code refactoring
- `docs/` - Documentation changes
- `test/` - Test additions or modifications

### Making Changes

1. Start the development server with hot reload:

   ```bash
   make dev
   ```

   Or run the worker in development mode:

   ```bash
   make dev-worker
   ```

2. Make your changes, ensuring you follow the code style guidelines.

3. Write or update tests as needed.

4. Commit your changes with clear, descriptive commit messages.

### Running Tests

Run the full test suite before submitting:

```bash
make test
```

Additional test commands:

```bash
# Run unit tests only (faster)
make test-unit

# Run tests with race detection
make test-race

# Run tests with coverage report
make test-coverage

# Run integration tests
make test-integration

# Run benchmarks
make bench
```

### Code Formatting and Linting

Before committing, ensure your code passes all quality checks:

```bash
# Format code
make fmt

# Run go vet
make vet

# Run linter
make lint

# Run all checks (fmt, vet, lint, test)
make check
```

Tidy module dependencies if you have added or removed packages:

```bash
make tidy
```

## Code Style

### Go Conventions

Follow standard Go conventions and idioms:

- Use `gofmt` for formatting (handled by `make fmt`)
- Follow [Effective Go](https://go.dev/doc/effective_go) guidelines
- Use meaningful variable and function names
- Keep functions focused and reasonably sized
- Prefer composition over inheritance

### Project-Specific Patterns

**Interfaces**

- Define interfaces where they are used, not where they are implemented
- Keep interfaces small and focused (prefer single-method interfaces when practical)
- Use interfaces for external dependencies to enable testing

**Error Handling**

- Always check and handle errors explicitly
- Wrap errors with context using `fmt.Errorf("context: %w", err)`
- Return errors rather than using panic for recoverable conditions
- Use custom error types when callers need to distinguish between error cases

**Structured Logging**

- Use `log/slog` for structured logging
- Include relevant context in log messages
- Use appropriate log levels (Debug, Info, Warn, Error)

**Context**

- Pass `context.Context` as the first parameter to functions that perform I/O
- Respect context cancellation and timeouts

### Comment Guidelines

- Write comments that explain why, not what
- Document all exported functions, types, and constants
- Use complete sentences with proper punctuation
- Keep comments up to date when code changes

Example:

```go
// ValidateCredentials checks whether the provided cloud credentials
// are valid by attempting to authenticate with the provider API.
// Returns an error if authentication fails or credentials are expired.
func ValidateCredentials(ctx context.Context, creds *CloudCredentials) error {
    // ...
}
```

## Testing Requirements

### Unit Tests Required

All new code must include unit tests. Aim for meaningful test coverage that validates behavior, not just line coverage.

### Table-Driven Tests Preferred

Use table-driven tests for functions with multiple test cases:

```go
func TestParsePorts(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected []int
        wantErr  bool
    }{
        {"single port", "80", []int{80}, false},
        {"multiple ports", "80,443", []int{80, 443}, false},
        {"port range", "1000-1003", []int{1000, 1001, 1002, 1003}, false},
        {"invalid port", "70000", nil, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := ParsePorts(tt.input)
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            require.NoError(t, err)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

### Integration Test Guidelines

- Tag integration tests with `//go:build integration`
- Integration tests should be self-contained and clean up after themselves
- Use the test utilities in `internal/testutil/` for common setup tasks
- Run integration tests with `make test-integration`

### How to Run Tests

```bash
# All tests
make test

# Unit tests only
make test-unit

# With verbose output
make test-verbose

# With coverage
make test-coverage

# With race detection (recommended before submitting)
make test-race

# Specific package
go test ./internal/scanner/...

# Specific test
go test -run TestParsePorts ./internal/scanner/...
```

## Pull Request Process

### PR Title Format

Use a clear, descriptive title following this format:

```
<type>: <short description>
```

Types:

- `feat` - New feature
- `fix` - Bug fix
- `refactor` - Code refactoring
- `docs` - Documentation changes
- `test` - Test additions or modifications
- `chore` - Maintenance tasks

Examples:

- `feat: add Azure blob storage scanner`
- `fix: handle timeout in port scanner`
- `refactor: extract common HTTP client logic`
- `docs: update API endpoint documentation`

### Description Template

Include the following in your PR description:

```markdown
## Summary

Brief description of the changes and their purpose.

## Changes

- Bullet point list of specific changes
- Include any breaking changes

## Testing

Describe how you tested these changes:
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Related Issues

Closes #123 (if applicable)
```

### Review Process

1. Submit your pull request against the `main` branch
2. Ensure all CI checks pass
3. Request a review from a maintainer
4. Address any feedback from reviewers
5. Once approved, a maintainer will merge your PR

### CI Checks That Must Pass

The following checks run automatically on all pull requests:

- **Lint** - golangci-lint must pass with no errors
- **Test** - All tests must pass with race detection enabled
- **Build** - Both server and worker binaries must build successfully
- **Security** - gosec and govulncheck must pass

You can run these checks locally before pushing:

```bash
make check
```

## Reporting Issues

### Bug Reports

When reporting a bug, please include:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Go version (`go version`)
- Operating system and version
- Relevant logs or error messages
- Any relevant configuration

### Feature Requests

When requesting a feature, please include:

- A clear, descriptive title
- The problem this feature would solve
- Your proposed solution (if any)
- Any alternatives you have considered
- Whether you are willing to implement this feature

## Architecture Overview

For detailed architecture documentation, see the `docs/architecture/` directory.

### Key Directories

```
go-hunter/
├── cmd/
│   ├── server/          # HTTP API server entrypoint
│   └── worker/          # Background job worker entrypoint
├── internal/
│   ├── api/             # HTTP handlers, middleware, routes
│   ├── assets/          # Asset discovery and management
│   ├── auth/            # Authentication and authorization
│   ├── database/        # Database connection and models
│   ├── findings/        # Security findings management
│   ├── scanner/         # Cloud scanning implementations
│   ├── tasks/           # Background task definitions
│   ├── testutil/        # Test utilities and helpers
│   ├── users/           # User management
│   └── web/             # Web interface (if applicable)
├── pkg/                 # Public packages (importable by external code)
├── migrations/          # Database migration files
├── scripts/             # Utility scripts
└── docs/                # Documentation
    ├── api/             # API documentation
    ├── architecture/    # Architecture documentation
    └── decisions/       # Architecture decision records
```

### Key Concepts

- **Multi-tenancy** - All data is scoped to organizations
- **Background Jobs** - Long-running tasks use Redis-backed job queues (Asynq)
- **Cloud Providers** - Modular scanner implementations for AWS, Azure, GCP, Cloudflare, and DigitalOcean

---

Thank you for contributing to Go-Hunter.
