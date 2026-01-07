# Go-Hunter Follow-Up Work

This document outlines remaining work items for the Go-Hunter project, organized by priority and category.

## Completed Items

### Scan Scheduling (Completed)
- Cron-based recurring scans with full CRUD API
- Database model: `internal/database/models/scheduled_scan.go`
- Migration: `migrations/000002_scheduled_scans.up.sql`
- API handler: `internal/api/handlers/schedules.go`
- Scheduler tick handler: `internal/tasks/handlers.go` (HandleSchedulerTick)
- Cron utilities: `pkg/util/cron.go`
- Routes: `/api/v1/schedules` (GET, POST), `/api/v1/schedules/{id}` (GET, PUT, DELETE), `/api/v1/schedules/{id}/trigger` (POST)
- Comprehensive test coverage: `internal/api/handlers/schedules_test.go`

### Code Quality - Service Interfaces (Completed)
- Auth interfaces: `internal/auth/interfaces.go` (Authenticator, TokenService)
- Asset interfaces: `internal/assets/interfaces.go` (CredentialManager, AssetDiscoverer, AssetService)
- Scanner interfaces: `internal/scanner/interfaces.go` (PortScannerInterface, HTTPProberInterface, WebCrawlerInterface, S3CheckerInterface)

### Code Quality - golangci-lint (Completed)
- Configuration: `.golangci.yml`
- All lint issues fixed

### Code Quality - Scanner Tests (Completed)
- Port scanner tests: `internal/scanner/port_scanner_test.go` (20+ test cases)
- HTTP prober tests: `internal/scanner/http_prober_test.go` (20+ test cases)
- S3 checker tests: `internal/scanner/s3_checker_test.go` (6+ test cases)

---

## Features to Add

### High Priority

#### 1. Webhooks/Notifications
- Notify on new critical findings
- Support Slack, Discord, email, generic webhook
- Add notification preferences per organization

**Implementation notes:**
- Create `internal/notifications/` package with provider interfaces
- Add `notification_channels` and `notification_preferences` tables
- Trigger notifications from finding creation in task handlers

#### 3. Export Functionality
- Export findings as CSV, JSON, PDF report
- Add `/api/v1/findings/export` endpoint
- Support filtering by date range, severity, status

**Implementation notes:**
- Create `internal/export/` package
- Use `jung-kurt/gofpdf` or similar for PDF generation
- Stream large exports to avoid memory issues

### Medium Priority

#### 4. Asset Tagging
- Allow users to tag/group assets
- Filter scans and findings by tags
- Bulk tagging operations

**Implementation notes:**
- Create `tags` and `asset_tags` junction tables
- Add tag CRUD endpoints
- Update asset list endpoint to filter by tags

#### 5. Audit Logging
- Track user actions: login, credential changes, scan triggers
- Add `audit_logs` table
- Create audit middleware for automatic logging

**Implementation notes:**
- Create `internal/audit/` package
- Add middleware that logs to database
- Include: user_id, action, resource_type, resource_id, ip_address, timestamp, details (JSONB)

#### 6. Correlation IDs
- Add request ID to all logs
- Pass through to background tasks for tracing
- Return in response headers for debugging

**Implementation notes:**
- Create `internal/api/middleware/requestid.go`
- Use `X-Request-ID` header
- Store in context and propagate to task payloads

#### 7. API Documentation
- Add OpenAPI/Swagger spec
- Consider swaggo/swag for auto-generation
- Host documentation at `/docs`

**Implementation notes:**
- Add swaggo annotations to handlers
- Generate spec with `swag init`
- Serve Swagger UI from embedded files

### Lower Priority

#### 8. Two-Factor Authentication
- TOTP-based 2FA for user accounts
- Recovery codes
- Enforce 2FA for admin users

#### 9. Team Management
- Invite users to organization
- Role-based permissions (owner, admin, member, viewer)
- Activity feed per organization

#### 10. Dashboard Analytics
- Findings over time chart
- Asset growth metrics
- Scan success/failure rates
- Top vulnerabilities by category

## Code Quality Improvements

### 1. Replace Magic Strings with Enums
- Scan types should use typed constants
- Asset types already use typed constants (good)
- Finding severities already use typed constants (good)
- Add scan status constants if not present

### 2. Extract Handler Helper Methods
- Large handlers in `scans.go` should be broken down
- Create shared context extraction helper
- Consolidate JSON response writing

### 3. Increase Test Coverage (Partially Done)
- Scanner tests completed (port scanner, HTTP prober, S3 checker)
- Still needed:
  - `internal/scanner/web_crawler.go` tests
  - `internal/api/middleware/ratelimit.go` tests
  - Integration tests with testcontainers
  - Target 60%+ coverage

## Database Improvements

### 1. Add Down Migration
`migrations/000001_init.down.sql` is empty. Add proper rollback SQL:
```sql
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS assets;
DROP TABLE IF EXISTS cloud_credentials;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS organizations;
```

### 2. Add Indexes
Review query patterns and add missing indexes:
- `findings(asset_id, status)` for filtered finding queries
- `scans(organization_id, status)` for scan listing
- `assets(organization_id, type, is_active)` for asset filtering

### 3. Transaction Wrapping
- Wrap asset discovery saves in transaction
- Use GORM Transaction for atomic operations
- Example pattern:
```go
err := db.Transaction(func(tx *gorm.DB) error {
    // multiple operations
    return nil
})
```

## Security Enhancements

### 1. Secrets Scanning
- Detect exposed secrets in HTTP responses during crawling
- Check for AWS keys, API tokens, passwords in responses
- Flag as critical findings

### 2. SSL/TLS Analysis
- Expand HTTP prober to check cipher suites
- Detect weak ciphers (RC4, 3DES, etc.)
- Check for certificate chain issues

### 3. DNS Security Checks
- Check for dangling DNS records
- Subdomain takeover detection
- SPF/DKIM/DMARC validation

### 4. Cloud Misconfig Checks
- Expand beyond S3 to other AWS services
- Add GCP bucket security checks
- Azure blob storage checks

## Infrastructure

### 1. Docker Improvements
- Multi-stage build for smaller images
- Health check in Dockerfile
- Non-root user

### 2. Kubernetes Support
- Add Helm chart
- Horizontal pod autoscaling
- Pod disruption budgets

### 3. Observability
- Prometheus metrics endpoint
- Structured logging improvements
- Distributed tracing with OpenTelemetry

---

## Quick Start for Contributors

1. Pick an item from this list
2. Create a feature branch: `git checkout -b feature/item-name`
3. Implement the feature
4. Add tests
5. Run `go test ./...` and `golangci-lint run`
6. Create PR with description referencing this document

## Priority Order Recommendation

1. ~~Scan Scheduling~~ (COMPLETED)
2. Export Functionality (commonly requested)
3. Audit Logging (security requirement)
4. Web Crawler Tests (code quality - remaining scanner)
5. Webhooks/Notifications (automation enabler)
