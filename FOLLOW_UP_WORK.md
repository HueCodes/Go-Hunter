# Go-Hunter Follow-Up Work

This document outlines remaining work items for the Go-Hunter project, organized by priority and category.

## Features to Add

### High Priority

#### 1. Scan Scheduling
- Add cron-based recurring scans
- Store schedule in database with new `scan_schedules` table
- Use asynq periodic tasks for execution
- Support daily/weekly/monthly options
- Allow users to enable/disable schedules

**Implementation notes:**
- Create `internal/scheduler/scheduler.go`
- Add `scan_schedules` table with fields: id, org_id, scan_type, cron_expression, enabled, last_run, next_run
- Register periodic task handler in worker

#### 2. Webhooks/Notifications
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

### 1. Add golangci-lint Config
Create `.golangci.yml` with appropriate linters:
```yaml
linters:
  enable:
    - gofmt
    - govet
    - errcheck
    - staticcheck
    - gosimple
    - ineffassign
    - unused
    - misspell
    - gosec
```

### 2. Replace Magic Strings with Enums
- Scan types should use typed constants
- Asset types already use typed constants (good)
- Finding severities already use typed constants (good)
- Add scan status constants if not present

### 3. Extract Handler Helper Methods
- Large handlers in `scans.go` should be broken down
- Create shared context extraction helper
- Consolidate JSON response writing

### 4. Increase Test Coverage
- Add tests for all scanner implementations
- Add integration tests with testcontainers
- Target 60%+ coverage
- Priority files:
  - `internal/scanner/port_scanner.go`
  - `internal/scanner/http_prober.go`
  - `internal/scanner/web_crawler.go`
  - `internal/api/middleware/ratelimit.go`

### 5. Add Interfaces for Services
- Define interfaces for AssetService, ScanService, etc.
- Enable proper mocking in tests
- Example:
```go
type AssetServiceInterface interface {
    CreateCredential(ctx context.Context, ...) (*models.CloudCredential, error)
    DiscoverAssets(ctx context.Context, ...) ([]DiscoveredAsset, error)
    // ...
}
```

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

1. Scan Scheduling (high user value)
2. Export Functionality (commonly requested)
3. Audit Logging (security requirement)
4. Test Coverage (code quality)
5. Webhooks/Notifications (automation enabler)
