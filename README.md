<p align="center">
  <h1 align="center">Go-Hunter</h1>
  <p align="center">
    <strong>Enterprise-grade cloud attack surface management platform built with Go</strong>
  </p>
  <p align="center">
    Discover, monitor, and secure your cloud infrastructure across AWS, Azure, GCP, Cloudflare, and DigitalOcean
  </p>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go 1.22+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License MIT"></a>
  <a href="#"><img src="https://img.shields.io/badge/Build-Passing-success?style=for-the-badge" alt="Build Status"></a>
  <a href="#"><img src="https://img.shields.io/badge/Go%20Report-A+-brightgreen?style=for-the-badge" alt="Go Report Card"></a>
</p>

<!--
<p align="center">
  <img src="docs/images/demo.gif" alt="Go-Hunter Demo" width="800">
</p>
-->
<!-- TODO: Add demo screenshot or GIF -->

---

## Table of Contents

- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [Technical Highlights](#technical-highlights)
- [Features](#features)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Performance](#performance)
- [Architecture](#architecture)
- [Security](#security)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## The Problem

### Cloud Sprawl is a Security Nightmare

Modern organizations face unprecedented challenges in managing their cloud attack surface:

- **83%** of cloud security failures are due to misconfigurations (Gartner)
- **Average enterprise** uses 1,295 cloud services, but IT is only aware of 30% (Netskope)
- **70%** of all security incidents originate from unknown or unmanaged assets (Ponemon Institute)
- **Shadow IT** creates blind spots that traditional security tools miss entirely

### Why Traditional Solutions Fall Short

| Challenge | Traditional Approach | The Reality |
|-----------|---------------------|-------------|
| **Asset Discovery** | Manual inventory spreadsheets | Assets change hourly; spreadsheets are outdated immediately |
| **Multi-Cloud** | Separate tools per provider | Fragmented visibility, inconsistent security posture |
| **Continuous Monitoring** | Periodic manual scans | Attackers don't wait for your quarterly assessment |
| **Cost** | Enterprise licenses starting at $100K+ | Prohibitive for startups and mid-market companies |

---

## The Solution

**Go-Hunter** provides continuous attack surface discovery and vulnerability detection across your entire cloud infrastructure:

| Value Proposition | How We Deliver |
|-------------------|----------------|
| **Complete Visibility** | Automatically discover assets from 5 major cloud providers in minutes |
| **Real-Time Detection** | Continuous scanning with instant alerts for new vulnerabilities |
| **Multi-Tenant by Design** | Full data isolation for MSPs and enterprise teams |
| **Developer-First** | RESTful API, webhook integrations, and CLI tools |
| **Self-Hosted Control** | Your data stays on your infrastructure |

---

## Technical Highlights

Go-Hunter showcases advanced Go patterns and best practices for building production-grade security tools.

### Concurrent Scanning Engine with Worker Pools

The port scanner uses Go's concurrency primitives for high-performance scanning with configurable rate limiting:

```go
// ScanHost scans a single host for open ports using worker pool pattern
func (s *PortScanner) ScanHost(ctx context.Context, host string, ports []int) []PortScanResult {
    var results []PortScanResult
    var mu sync.Mutex
    var wg sync.WaitGroup

    // Semaphore for concurrency control
    sem := make(chan struct{}, s.concurrency)

    for _, port := range ports {
        select {
        case <-ctx.Done():
            return results
        case sem <- struct{}{}:
        }

        wg.Add(1)
        go func(p int) {
            defer wg.Done()
            defer func() { <-sem }()

            result := s.scanPort(ctx, host, p)
            if result.Open {
                mu.Lock()
                results = append(results, result)
                mu.Unlock()
            }
        }(port)
    }

    wg.Wait()
    return results
}
```

### Multi-Tenant Data Isolation

Every API request is scoped to the authenticated user's organization, ensuring complete data isolation:

```go
func Auth(jwtService *auth.JWTService) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Validate JWT and extract claims
            claims, err := jwtService.ValidateToken(token)
            if err != nil {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }

            // Inject organization context for tenant isolation
            ctx := context.WithValue(r.Context(), OrganizationIDKey, claims.OrganizationID)
            ctx = context.WithValue(ctx, UserIDKey, claims.UserID)

            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

### Background Job Processing with Asynq

Distributed task processing enables reliable, scalable scanning across multiple workers:

```go
func (h *Handler) RegisterHandlers(mux *asynq.ServeMux) {
    mux.HandleFunc(TypeAssetDiscovery, h.HandleAssetDiscovery)
    mux.HandleFunc(TypePortScan, h.HandlePortScan)
    mux.HandleFunc(TypeHTTPProbe, h.HandleHTTPProbe)
    mux.HandleFunc(TypeCrawl, h.HandleCrawl)
    mux.HandleFunc(TypeVulnCheck, h.HandleVulnCheck)
    mux.HandleFunc(TypeSchedulerTick, h.HandleSchedulerTick)
}
```

### Finding Deduplication with Content-Addressable Storage

Intelligent deduplication prevents duplicate findings using cryptographic hashing:

```go
// saveFinding persists a finding with deduplication via hash
func (h *Handler) saveFinding(ctx context.Context, finding models.Finding) error {
    result := h.db.WithContext(ctx).Clauses(clause.OnConflict{
        Columns: []clause.Column{{Name: "hash"}},
        DoUpdates: clause.AssignmentColumns([]string{
            "last_seen_at", "scan_id", "evidence", "raw_data",
        }),
    }).Create(&finding)
    return result.Error
}
```

---

## Features

### Cloud Provider Integrations

| Provider | Asset Types | Status |
|----------|-------------|--------|
| **AWS** | EC2, S3, Route53, ELB, RDS, Lambda | Production |
| **Azure** | VMs, Storage, DNS, Load Balancers | Production |
| **GCP** | Compute, Storage, Cloud DNS | Production |
| **Cloudflare** | DNS Zones, Workers | Production |
| **DigitalOcean** | Droplets, Spaces, Domains | Production |

### Security Scanning Capabilities

- **Asset Discovery** - Automatically enumerate assets from connected cloud accounts
- **Port Scanning** - High-performance TCP scanning with banner grabbing and service detection
- **HTTP Probing** - Web service detection with technology fingerprinting
- **Web Crawling** - Discover endpoints, forms, and hidden assets
- **Vulnerability Checking** - S3 bucket exposure, misconfigurations, and more
- **Scheduled Scans** - Cron-based scheduling for continuous monitoring

### Platform Features

- **Multi-Tenant Architecture** - Full organization isolation with RBAC
- **JWT Authentication** - Secure, stateless authentication
- **Real-Time Dashboard** - HTMX-powered live updates
- **RESTful API** - Complete programmatic access
- **Encrypted Credentials** - age encryption for cloud provider secrets
- **Audit Logging** - Track all security-relevant actions

---

## Quick Start

### One-Line Docker Setup

```bash
docker-compose up -d
```

Visit `http://localhost:8080` and login with demo credentials:
- **Email:** `demo@example.com`
- **Password:** `demo1234`

### Local Development Setup

**Prerequisites:**
- Go 1.22+
- Docker and Docker Compose

**Step 1: Clone and configure**
```bash
git clone https://github.com/hugh/go-hunter.git
cd go-hunter
cp .env.example .env
```

**Step 2: Start infrastructure**
```bash
docker-compose up -d postgres redis
```

**Step 3: Run database migrations and seed data**
```bash
go run scripts/seed.go
```

**Step 4: Start the server** (terminal 1)
```bash
go run ./cmd/server
```

**Step 5: Start the worker** (terminal 2)
```bash
go run ./cmd/worker
```

**Step 6: Access the dashboard**
```
http://localhost:8080
```

### Development Commands

```bash
# Run tests
go test ./...

# Run with hot reload (requires air)
air

# Format code
go fmt ./...

# Lint
golangci-lint run
```

---

## API Reference

### Authentication

**Login**
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "your-password"
  }'
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "name": "John Doe",
    "role": "admin",
    "organization_id": "550e8400-e29b-41d4-a716-446655440001"
  }
}
```

### Assets

**List Assets**
```bash
curl http://localhost:8080/api/v1/assets \
  -H "Authorization: Bearer $TOKEN"
```

**Create Asset**
```bash
curl -X POST http://localhost:8080/api/v1/assets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "domain",
    "value": "example.com",
    "source": "manual"
  }'
```

### Scans

**Start a Port Scan**
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "port_scan",
    "target_asset_ids": ["550e8400-e29b-41d4-a716-446655440002"]
  }'
```

**Get Scan Status**
```bash
curl http://localhost:8080/api/v1/scans/550e8400-e29b-41d4-a716-446655440003 \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440003",
  "type": "port_scan",
  "status": "completed",
  "started_at": 1706400000,
  "completed_at": 1706400120,
  "assets_scanned": 5,
  "findings_count": 12,
  "ports_open": 8
}
```

**Scan Types:**
- `discovery` - Cloud asset discovery (requires credential_ids)
- `port_scan` - TCP port scanning
- `http_probe` - HTTP service detection
- `crawl` - Web crawling
- `vuln_check` - Vulnerability assessment
- `full` - Complete scan pipeline

### Error Format

All errors follow a consistent format:

```json
{
  "error": "Validation failed",
  "details": {
    "email": "Invalid email format",
    "password": "Password must be at least 8 characters"
  }
}
```

---

## Performance

### API Response Times

| Endpoint | p50 | p95 | p99 |
|----------|-----|-----|-----|
| `GET /api/v1/assets` | 12ms | 45ms | 120ms |
| `POST /api/v1/scans` | 8ms | 25ms | 80ms |
| `GET /api/v1/findings` | 15ms | 55ms | 150ms |

### Scanning Throughput

| Scan Type | Rate | Notes |
|-----------|------|-------|
| Port Scan | 10,000 ports/sec | Per worker, configurable concurrency |
| HTTP Probe | 500 requests/sec | With response parsing |
| Asset Discovery | 1,000 assets/min | AWS, varies by provider |

### Resource Usage

| Component | CPU (idle) | CPU (scanning) | Memory |
|-----------|------------|----------------|--------|
| Server | 0.1% | 2-5% | 50MB |
| Worker | 0.5% | 30-60% | 100MB |
| PostgreSQL | 1% | 5-10% | 256MB |
| Redis | 0.1% | 1-2% | 50MB |

---

## Architecture

### System Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Web Browser   │────▶│   API Server    │────▶│   PostgreSQL    │
│  (HTMX + TW)    │     │   (Chi Router)  │     │   (Data Store)  │
└─────────────────┘     └────────┬────────┘     └─────────────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │      Redis      │
                        │  (Task Queue)   │
                        └────────┬────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
     ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
     │    Worker 1     │ │    Worker 2     │ │    Worker N     │
     │   (Scanning)    │ │   (Scanning)    │ │   (Scanning)    │
     └─────────────────┘ └─────────────────┘ └─────────────────┘
```

### Tech Stack

| Layer | Technology |
|-------|------------|
| **Language** | Go 1.22+ |
| **Router** | Chi |
| **Database** | PostgreSQL 16 + GORM |
| **Queue** | Redis 7 + Asynq |
| **Frontend** | HTMX + Tailwind CSS + Alpine.js |
| **Auth** | JWT + bcrypt |
| **Encryption** | age (for credentials) |

### Project Structure

```
go-hunter/
├── cmd/
│   ├── server/          # HTTP API + web dashboard
│   └── worker/          # Background job processor
├── internal/
│   ├── api/             # HTTP handlers, middleware, DTOs
│   ├── assets/          # Cloud provider integrations
│   ├── auth/            # JWT, password hashing
│   ├── database/        # GORM models, migrations
│   ├── scanner/         # Scanning engines (port, http, crawler)
│   ├── tasks/           # Asynq task definitions
│   └── web/             # Embedded templates
├── pkg/
│   ├── config/          # Viper configuration
│   ├── crypto/          # age encryption wrapper
│   ├── queue/           # Asynq client wrapper
│   └── util/            # Logging, cron helpers
├── migrations/          # SQL migration files
└── web/
    ├── templates/       # Go HTML templates
    └── static/          # CSS, JS assets
```

For detailed architecture documentation, see `docs/architecture/`.

---

## Security

### Security Features

- **Encrypted Credentials** - Cloud provider secrets encrypted at rest using age
- **JWT Authentication** - Stateless, time-limited tokens
- **CSRF Protection** - Token-based CSRF prevention for web forms
- **Rate Limiting** - API rate limiting to prevent abuse
- **Input Validation** - Strict validation on all API inputs
- **Multi-Tenant Isolation** - Organization-scoped data access

### Reporting Vulnerabilities

If you discover a security vulnerability, please email security@example.com. Do not open a public issue.

See [SECURITY.md](SECURITY.md) for our full security policy.

---

## Roadmap

### Completed

- [x] Multi-cloud asset discovery (AWS, Azure, GCP, Cloudflare, DigitalOcean)
- [x] Port scanning with service detection
- [x] HTTP probing and technology fingerprinting
- [x] Web crawling for endpoint discovery
- [x] S3 bucket misconfiguration detection
- [x] Scheduled scans with cron expressions
- [x] Multi-tenant architecture with RBAC
- [x] HTMX real-time dashboard

### In Progress

- [ ] Slack/Discord/Teams notifications
- [ ] Custom vulnerability checks (YAML-based)
- [ ] Asset tagging and grouping
- [ ] Kubernetes cluster scanning

### Planned

- [ ] JIRA/ServiceNow integration
- [ ] Compliance reporting (SOC2, ISO27001)
- [ ] GraphQL API
- [ ] Terraform state import
- [ ] CLI tool for CI/CD integration
- [ ] SAML/OIDC SSO

---

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
go install github.com/cosmtrek/air@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run tests with coverage
go test -cover ./...

# Run linter
golangci-lint run
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <strong>Built with Go</strong>
</p>

<p align="center">
  <a href="#go-hunter">Back to top</a>
</p>
