# Go-Hunter Architecture

This document provides a comprehensive overview of the Go-Hunter system architecture, a multi-tenant cloud attack-surface discovery platform.

## High-Level System Architecture

```
                                    +-------------------+
                                    |   Web Dashboard   |
                                    |  (HTMX + Alpine)  |
                                    +--------+----------+
                                             |
                                             v
+----------------+              +------------------------+
|   API Client   | ----------> |      API Server        |
| (REST/JSON)    |             |   (Chi Router + JWT)   |
+----------------+              +--------+---------------+
                                         |
                    +--------------------+--------------------+
                    |                    |                    |
                    v                    v                    v
           +---------------+    +----------------+    +---------------+
           |   PostgreSQL  |    |     Redis      |    |    Worker     |
           |   (GORM)      |    |   (Asynq)      |    |   (Asynq)     |
           +---------------+    +-------+--------+    +-------+-------+
                                        |                     |
                                        +----------+----------+
                                                   |
                                                   v
                                    +-----------------------------+
                                    |        Scan Pipeline        |
                                    +-----------------------------+
                                    | - Asset Discovery           |
                                    | - Port Scanner              |
                                    | - HTTP Prober               |
                                    | - Web Crawler               |
                                    | - Vulnerability Checker     |
                                    +-----------------------------+
                                                   |
                    +------------------------------+------------------------------+
                    |              |              |              |                |
                    v              v              v              v                v
             +----------+   +----------+   +----------+   +-------------+   +-----------+
             |   AWS    |   |   GCP    |   |  Azure   |   | DigitalOcean|   | Cloudflare|
             +----------+   +----------+   +----------+   +-------------+   +-----------+
```

## Component Overview

### 1. API Server (`cmd/server`)

The main HTTP server handling web requests and API calls.

**Key Responsibilities:**
- RESTful API endpoints for assets, scans, findings, and credentials
- Web dashboard serving (HTMX + Go templates)
- JWT-based authentication and authorization
- Rate limiting and CORS handling
- Enqueuing background jobs via Asynq

**Technology Stack:**
- **Router**: go-chi/chi v5 - Lightweight, idiomatic HTTP router
- **ORM**: GORM with PostgreSQL driver
- **Auth**: golang-jwt/jwt for token management, bcrypt for password hashing
- **Templates**: Go html/template with embedded filesystem

### 2. Worker (`cmd/worker`)

Background job processor for long-running scan operations.

**Key Responsibilities:**
- Processing scan tasks from Redis queue
- Cloud asset discovery across multiple providers
- Network scanning (port scanning, HTTP probing)
- Web crawling for endpoint discovery
- Vulnerability checking (S3 bucket misconfigurations, etc.)
- Scheduled scan execution

**Technology Stack:**
- **Queue**: Asynq (Redis-backed job queue)
- **Scheduler**: Asynq scheduler for cron-based tasks

### 3. Database Layer (`internal/database`)

PostgreSQL database with GORM ORM for data persistence.

**Core Models:**
- `Organization` - Tenant container with plan limits
- `User` - User accounts with organization membership
- `CloudCredential` - Encrypted cloud provider credentials
- `Asset` - Discovered infrastructure (domains, IPs, buckets, etc.)
- `Scan` - Scan execution records with status tracking
- `Finding` - Security findings with severity and remediation
- `ScheduledScan` - Cron-based recurring scans

### 4. Assets Service (`internal/assets`)

Cloud provider integration layer for credential management and asset discovery.

**Supported Providers:**
- AWS (EC2, S3, Route53, ELB)
- Google Cloud Platform (Compute, Storage, DNS)
- Microsoft Azure (VMs, Storage, DNS)
- DigitalOcean (Droplets, Spaces)
- Cloudflare (DNS, Zones)

### 5. Scanner Module (`internal/scanner`)

Security scanning engines for attack surface discovery.

**Scanners:**
- `PortScanner` - TCP port scanning with banner grabbing
- `HTTPProber` - HTTP/HTTPS service detection
- `WebCrawler` - Web application crawling and endpoint discovery
- `S3Checker` - AWS S3 bucket misconfiguration detection

## Data Flow: Scanning Pipeline

```
User Request                              Background Processing
     |                                           |
     v                                           v
+----+----+                              +-------+-------+
|  POST   |   creates                    |    Worker     |
| /scans  | ---------> Scan Record -----> picks up task |
+---------+            (pending)         +-------+-------+
     |                                           |
     v                                           v
+----+----+                              +-------+-------+
| Asynq   |   enqueues                   | Task Handler  |
| Client  | ---------> Redis Queue       | executes scan |
+---------+                              +-------+-------+
                                                 |
                              +------------------+------------------+
                              |                  |                  |
                              v                  v                  v
                       +------+------+    +------+------+    +------+------+
                       | Discovery   |    | Port Scan   |    | HTTP Probe  |
                       | (cloud API) |    | (TCP dial)  |    | (HTTP GET)  |
                       +------+------+    +------+------+    +------+------+
                              |                  |                  |
                              v                  v                  v
                       +------+------+    +------+------+    +------+------+
                       |   Assets    |    |  Findings   |    |  Findings   |
                       | (database)  |    | (database)  |    | (database)  |
                       +-------------+    +-------------+    +-------------+
                                                 |
                                                 v
                                         +------+------+
                                         | Scan Status |
                                         |  completed  |
                                         +-------------+
```

## Multi-Tenant Isolation Model

```
+-------------------------------------------------------------------+
|                        PostgreSQL Database                         |
+-------------------------------------------------------------------+
|                                                                     |
|  +----------------+  +----------------+  +----------------+         |
|  | Organization A |  | Organization B |  | Organization C |         |
|  +-------+--------+  +-------+--------+  +-------+--------+         |
|          |                   |                   |                  |
|    +-----+-----+       +-----+-----+       +-----+-----+            |
|    |           |       |           |       |           |            |
|    v           v       v           v       v           v            |
|  +---+       +---+   +---+       +---+   +---+       +---+          |
|  |User|      |User|  |User|      |User|  |User|      |User|         |
|  +---+       +---+   +---+       +---+   +---+       +---+          |
|                                                                     |
|  All tables have organization_id foreign key:                       |
|  - assets.organization_id        -> organizations.id                |
|  - findings.organization_id      -> organizations.id                |
|  - scans.organization_id         -> organizations.id                |
|  - cloud_credentials.organization_id -> organizations.id            |
|  - scheduled_scans.organization_id -> organizations.id              |
+-------------------------------------------------------------------+

Isolation Enforcement:
+-------------------+     +-------------------+     +-------------------+
|   Auth Middleware |---->| Extract org_id    |---->| Filter all        |
|   (JWT Token)     |     | from JWT claims   |     | queries by org_id |
+-------------------+     +-------------------+     +-------------------+
```

**Key Isolation Mechanisms:**
1. **JWT Claims**: Organization ID embedded in JWT token at login
2. **Middleware Injection**: `organization_id` extracted and added to request context
3. **Query Filtering**: All database queries include `WHERE organization_id = ?`
4. **Role-Based Access**: Users have roles (owner, admin, member) within their organization

## Technology Choices

### Backend Framework

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Go 1.22+ | Strong concurrency, static typing, single binary deployment |
| HTTP Router | go-chi/chi | Lightweight, standard http.Handler compatible, middleware support |
| ORM | GORM | Mature Go ORM, PostgreSQL JSON support, auto-migrations |
| Auth | JWT (golang-jwt) | Stateless authentication, widely supported |
| Config | Viper | Flexible configuration from env/files |

### Data Storage

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Primary DB | PostgreSQL | JSONB support, mature, excellent Go drivers |
| Queue/Cache | Redis | Fast in-memory store, Asynq compatibility |
| Migrations | golang-migrate | SQL-based migrations, version tracking |

### Background Processing

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Job Queue | Asynq | Simple API, Redis-backed, built-in retry/scheduling |
| Scheduler | Asynq Scheduler | Cron-like scheduling for recurring scans |

### Frontend

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Interactivity | HTMX | Server-side rendering, minimal JavaScript |
| Styling | Tailwind CSS | Utility-first CSS, rapid development |
| Reactivity | Alpine.js | Lightweight, declarative UI interactions |
| Templates | Go html/template | Built-in, secure, fast |

### Security

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Password Hashing | bcrypt | Industry standard, adaptive work factor |
| Credential Encryption | age (filippo.io/age) | Modern encryption, Go-native, simple API |
| CSRF Protection | Token-based | Secure form submissions |

## Directory Structure

```
go-hunter/
├── cmd/
│   ├── server/          # HTTP API server entry point
│   └── worker/          # Background job processor entry point
├── internal/
│   ├── api/
│   │   ├── handlers/    # HTTP request handlers
│   │   ├── middleware/  # Auth, logging, rate limiting
│   │   ├── dto/         # Data transfer objects
│   │   ├── validation/  # Request validation
│   │   └── router.go    # Route definitions
│   ├── assets/
│   │   ├── aws/         # AWS provider implementation
│   │   ├── gcp/         # GCP provider implementation
│   │   ├── azure/       # Azure provider implementation
│   │   ├── digitalocean/# DigitalOcean provider
│   │   ├── cloudflare/  # Cloudflare provider
│   │   ├── service.go   # Credential & discovery service
│   │   └── provider.go  # Provider interface
│   ├── auth/
│   │   ├── jwt.go       # JWT token management
│   │   ├── password.go  # Bcrypt password hashing
│   │   └── service.go   # Auth business logic
│   ├── database/
│   │   ├── models/      # GORM model definitions
│   │   └── database.go  # Connection management
│   ├── scanner/
│   │   ├── port_scanner.go   # TCP port scanning
│   │   ├── http_prober.go    # HTTP service detection
│   │   ├── web_crawler.go    # Web crawling
│   │   └── s3_checker.go     # S3 misconfiguration checks
│   ├── tasks/
│   │   ├── types.go     # Task payload definitions
│   │   └── handlers.go  # Asynq task handlers
│   └── web/
│       ├── embed.go     # Embedded templates/static files
│       ├── templates/   # Go HTML templates
│       └── static/      # CSS, JS assets
├── pkg/
│   ├── config/          # Viper configuration
│   ├── crypto/          # age encryption wrapper
│   ├── queue/           # Asynq client wrapper
│   └── util/            # Logging, helpers
├── migrations/          # SQL migration files
└── scripts/             # Development scripts
```

## Security Architecture

### Credential Storage Flow

```
User Input           Encryption                    Database
    |                    |                            |
    v                    v                            v
+--------+         +-----------+               +-------------+
| Access |  --->   | age       |  --->         | bytea       |
| Key    |         | Encrypt() |               | (encrypted) |
| Secret |         +-----------+               +-------------+
+--------+              ^                            |
                        |                            v
                   X25519 Key                  +-------------+
                   (ENCRYPTION_KEY)            | Decrypt on  |
                                               | worker read |
                                               +-------------+
```

### Request Authentication Flow

```
HTTP Request
     |
     v
+----+----+     +------------+     +------------+     +------------+
| Extract | --> | Validate   | --> | Extract    | --> | Add to     |
| Bearer  |     | JWT        |     | Claims     |     | Context    |
| Token   |     | Signature  |     | (user_id,  |     |            |
+---------+     +------------+     | org_id,    |     +------------+
                                   | role)      |           |
                                   +------------+           v
                                                     +------------+
                                                     | Handler    |
                                                     | (org-scoped|
                                                     |  queries)  |
                                                     +------------+
```

## Deployment Considerations

### Required Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_HOST` | PostgreSQL host | Yes |
| `DATABASE_PORT` | PostgreSQL port | Yes |
| `DATABASE_USER` | PostgreSQL user | Yes |
| `DATABASE_PASSWORD` | PostgreSQL password | Yes |
| `DATABASE_NAME` | PostgreSQL database name | Yes |
| `REDIS_HOST` | Redis host | Yes |
| `REDIS_PORT` | Redis port | Yes |
| `JWT_SECRET` | JWT signing secret (min 32 chars) | Yes |
| `ENCRYPTION_KEY` | age private key for credentials | Yes (prod) |
| `SERVER_PORT` | HTTP server port | No (default: 8080) |
| `SERVER_ENV` | Environment (development/production) | No |

### Container Deployment

The application is designed for containerized deployment with:
- Separate containers for API server and worker
- Shared PostgreSQL and Redis instances
- Environment-based configuration
- Graceful shutdown handling

### Scaling Considerations

- **Horizontal Scaling**: Multiple worker instances can process jobs concurrently
- **Queue Prioritization**: Asynq supports priority queues (critical, default, low)
- **Database Pooling**: GORM connection pooling for efficient DB access
- **Rate Limiting**: Built-in rate limiting to protect against abuse
