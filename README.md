# Go-Hunter

A multi-tenant cloud attack-surface discovery platform built in Go.

## Features

- **Asset Discovery**: Automatically discover assets from cloud providers (AWS, GCP, Azure, etc.)
- **Port Scanning**: Identify open ports and services
- **HTTP Probing**: Detect web services and technologies
- **Vulnerability Checking**: Run custom security checks
- **Real-time Dashboard**: HTMX-powered dashboard with live updates
- **Multi-tenant**: Full organization isolation with role-based access

## Tech Stack

- **Backend**: Go 1.22+, Chi router
- **Database**: PostgreSQL with GORM
- **Queue**: Redis + Asynq for background jobs
- **Frontend**: HTMX + Tailwind CSS + Alpine.js
- **Auth**: JWT with bcrypt password hashing
- **Encryption**: age for credential encryption

## Quick Start

### Prerequisites

- Go 1.22+
- Docker and Docker Compose
- Make (optional)

### Development Setup

1. **Clone and setup environment**
   ```bash
   cd Go-Hunter
   cp .env.example .env
   ```

2. **Start infrastructure**
   ```bash
   docker-compose up -d postgres redis
   ```

3. **Run database migrations**
   ```bash
   go run scripts/seed.go
   ```

4. **Start the server**
   ```bash
   go run ./cmd/server
   ```

5. **Start the worker** (in another terminal)
   ```bash
   go run ./cmd/worker
   ```

6. **Visit the dashboard**
   Open http://localhost:8080

### Using Docker

```bash
# Build and run everything
docker-compose up --build
```

## Project Structure

```
go-hunter/
├── cmd/
│   ├── server/          # HTTP API + dashboard
│   └── worker/          # Background job processor
├── internal/
│   ├── api/             # HTTP handlers, middleware, DTOs
│   ├── assets/          # Asset discovery logic
│   ├── auth/            # JWT, password hashing
│   ├── database/        # GORM models, migrations
│   ├── findings/        # Vulnerability storage
│   ├── scanner/         # Scanning engines
│   ├── tasks/           # Asynq task definitions
│   └── users/           # User/org management
├── pkg/
│   ├── config/          # Viper configuration
│   ├── crypto/          # age encryption
│   ├── queue/           # Asynq wrapper
│   └── util/            # Logging, helpers
├── migrations/          # SQL migrations
├── web/
│   ├── templates/       # Go templates
│   └── static/          # CSS, JS assets
└── scripts/             # Dev scripts
```

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Create account
- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/logout` - Logout

### Assets
- `GET /api/v1/assets` - List assets
- `POST /api/v1/assets` - Create asset
- `GET /api/v1/assets/:id` - Get asset
- `DELETE /api/v1/assets/:id` - Delete asset

### Scans
- `GET /api/v1/scans` - List scans
- `POST /api/v1/scans` - Start scan
- `GET /api/v1/scans/:id` - Get scan status
- `POST /api/v1/scans/:id/cancel` - Cancel scan

### Findings
- `GET /api/v1/findings` - List findings
- `GET /api/v1/findings/:id` - Get finding
- `PUT /api/v1/findings/:id/status` - Update status

## Configuration

Environment variables (see `.env.example`):

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_PORT` | Server port | 8080 |
| `SERVER_ENV` | Environment (development/production) | development |
| `DATABASE_HOST` | PostgreSQL host | localhost |
| `DATABASE_PORT` | PostgreSQL port | 5432 |
| `REDIS_HOST` | Redis host | localhost |
| `JWT_SECRET` | JWT signing secret | (required) |
| `ENCRYPTION_KEY` | age key for credential encryption | (auto-generated in dev) |

## Development

```bash
# Run tests
go test ./...

# Run with hot reload (using air)
air

# Format code
go fmt ./...

# Lint
golangci-lint run
```

## License

MIT
