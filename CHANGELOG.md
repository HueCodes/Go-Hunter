# Changelog

All notable changes to Go-Hunter will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Comprehensive test suite for task handlers (HandleAssetDiscovery, HandlePortScan, HandleHTTPProbe, HandleCrawl, HandleVulnCheck, HandleSchedulerTick)
- Authentication middleware test suite with full JWT validation coverage
- AWS provider test suite with mock client infrastructure
- Test utilities package with reusable fixtures and helpers (`internal/testutil`)
- MIT LICENSE file for legal clarity
- Security hardening: Docker containers now run as non-root user (uid/gid 1000)

### Changed
- Increased overall test coverage from 20% to 23.6%
- Enhanced Dockerfile with security best practices (non-root execution)
- Improved test infrastructure with comprehensive helper functions

### Fixed
- Compilation error in `benchmark_test.go` UUID pointer handling
- Broken demo image reference in README

### Security
- Docker containers now run as non-root user `gohunter` (uid/gid 1000)
- This prevents privilege escalation and follows container security best practices

## [1.0.0] - 2026-01-27

### Added

#### Core Features
- **Multi-cloud asset discovery** across 5 cloud providers:
  - AWS (EC2, S3, Route53, ELB/ALB) with support for 18 regions
  - Azure (VMs, Storage, DNS) with resource group scanning
  - GCP (Compute Engine, Cloud Storage, Cloud DNS) with project-based discovery
  - Cloudflare (DNS zones and records)
  - DigitalOcean (Droplets, Volumes, Domains)
- **Concurrent port scanning** with configurable worker pools (default 100 concurrent scans)
- **HTTP/HTTPS probing** with:
  - Technology fingerprinting (detects Nginx, Apache, Express, React, Angular, etc.)
  - TLS certificate analysis and expiration tracking
  - Redirect chain following
  - Custom header extraction
- **Web crawling** for comprehensive endpoint discovery
- **S3 bucket security scanning** detecting public read/write misconfigurations
- **Real-time web dashboard** using HTMX and Tailwind CSS with:
  - Asset inventory management
  - Scan history and results
  - Finding severity visualization
  - Organization management
- **Scheduled scans** with cron expression support for automation

#### Architecture & Infrastructure
- **Multi-tenant SaaS architecture** with organization-level data isolation
- **Background job processing** using Asynq (Redis-backed queue)
  - Reliable task distribution
  - Automatic retry with exponential backoff
  - Dead letter queue for failed tasks
- **JWT authentication** with refresh token support
- **Encrypted credential storage** using age encryption (X25519)
- **RESTful API** with comprehensive endpoints for assets, scans, findings, and more
- **Database migrations** with rollback support via golang-migrate
- **Docker containerization** with multi-stage builds for minimal image size

#### Security Features
- **CSRF protection** for all web forms with SameSite cookies
- **Rate limiting** per IP address (default: 100 requests/minute)
- **Input validation** on all API endpoints using go-playground/validator
- **SQL injection prevention** with GORM parameterized queries
- **Multi-tenant data isolation** enforced at database query level
- **Security scanning in CI** with gosec and govulncheck

#### Developer Experience
- **Comprehensive API documentation** in `docs/api/`
- **Architecture decision records** (ADRs) for key design choices
- **GitHub Actions CI/CD** with automated testing and security scanning
- **Makefile** with common development commands
- **Docker Compose** setup for local development

### Technical Highlights

#### Concurrent Scanning
```go
// Semaphore-based concurrency control
sem := make(chan struct{}, cfg.ConcurrentScans)
for _, region := range regions {
    wg.Add(1)
    sem <- struct{}{}
    go func(region string) {
        defer wg.Done()
        defer func() { <-sem }()
        // Scan region...
    }(region)
}
```

#### Multi-Tenant Query Scoping
All database queries are automatically scoped to the authenticated organization:
```go
db.Where("organization_id = ?", orgID).Find(&assets)
```

#### Credential Encryption
Cloud credentials are encrypted at rest using age (X25519) encryption:
```go
encrypted, err := encryptor.Encrypt(credentials)
// Stored in database as encrypted blob
```

### Database Schema
- **organizations** - Tenant isolation and subscription management
- **users** - User accounts with bcrypt password hashing
- **cloud_credentials** - Encrypted cloud provider credentials
- **assets** - Discovered infrastructure (IPs, domains, S3 buckets, etc.)
- **scans** - Scan jobs with status tracking
- **findings** - Security findings with severity classification
- **scheduled_scans** - Cron-based recurring scans

### Dependencies
- **Go 1.22+** - Latest Go features and performance improvements
- **PostgreSQL 14+** - Primary database with JSONB support
- **Redis 7+** - Task queue backend
- **Asynq** - Reliable background job processing
- **GORM** - Database ORM with auto-migrations
- **Chi** - Lightweight HTTP router
- **HTMX** - Modern web interactions without heavy JavaScript
- **Tailwind CSS** - Utility-first styling

### Testing & Quality
- **Test coverage**: 20%+ (growing with each release)
- **Continuous Integration** with GitHub Actions
- **Security scanning** with gosec and govulncheck
- **Linting** with golangci-lint

### Documentation
- Comprehensive README with quick start guide
- API documentation with example requests
- Architecture decision records (ADRs)
- Security documentation including threat model
- Docker deployment guide

### Known Limitations
- Demo screenshot not yet available
- Cloud provider tests require mock infrastructure (SDK v2 mocking in progress)
- Some middleware test coverage pending (CSRF, rate limiting)
- Azure and GCP provider tests need additional mock infrastructure

---

## Release Strategy

### Versioning
- MAJOR version for incompatible API changes
- MINOR version for new features (backward compatible)
- PATCH version for bug fixes

### Release Checklist
- [ ] Update CHANGELOG.md
- [ ] Run full test suite: `make test`
- [ ] Run security scans: `make security-check`
- [ ] Update version in README badges
- [ ] Tag release: `git tag -a v1.x.x -m "Release v1.x.x"`
- [ ] Build and push Docker images
- [ ] Update documentation

---

## Contributing

When contributing changes:
1. Add entry to Unreleased section
2. Use categories: Added, Changed, Deprecated, Removed, Fixed, Security
3. Include issue/PR numbers when applicable
4. Write from user perspective (what changed, not how)

## Links
- [Keep a Changelog](https://keepachangelog.com/)
- [Semantic Versioning](https://semver.org/)
- [Project Repository](https://github.com/yourusername/go-hunter)
