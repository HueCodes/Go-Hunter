# ADR-003: Shared Database Multi-Tenancy with Organization ID

## Status

Accepted

## Context

Go-Hunter is designed as a SaaS platform serving multiple organizations. Each organization needs complete data isolation - one organization should never see another organization's:

- Cloud credentials
- Discovered assets
- Security findings
- Scan history
- User accounts (beyond their own members)

### Multi-Tenancy Approaches Considered

1. **Separate Databases per Tenant**
   - Pros: Complete isolation, easy backup/restore per tenant
   - Cons: Complex provisioning, connection pool management, migration overhead

2. **Separate Schemas per Tenant**
   - Pros: Good isolation, single database connection
   - Cons: Schema migration complexity, PostgreSQL-specific

3. **Shared Database with Tenant ID Column**
   - Pros: Simple ops, easy migrations, efficient resource usage
   - Cons: Requires careful query discipline, shared resource contention

4. **Sharded Database**
   - Pros: Horizontal scalability
   - Cons: Complex routing, cross-shard queries impossible

## Decision

We chose **Shared Database with `organization_id` Foreign Key** as our multi-tenancy strategy.

### Implementation Details

**Organization Model** (`internal/database/models/organization.go`):
```go
type Organization struct {
    Base
    Name        string `gorm:"not null" json:"name"`
    Slug        string `gorm:"uniqueIndex;not null" json:"slug"`
    Plan        string `gorm:"default:'free'" json:"plan"` // free, pro, enterprise
    MaxUsers    int    `gorm:"default:5" json:"max_users"`
    MaxAssets   int    `gorm:"default:100" json:"max_assets"`
    MaxScansDay int    `gorm:"default:10" json:"max_scans_day"`

    // Relationships
    Users            []User            `gorm:"foreignKey:OrganizationID"`
    CloudCredentials []CloudCredential `gorm:"foreignKey:OrganizationID"`
    Assets           []Asset           `gorm:"foreignKey:OrganizationID"`
    Scans            []Scan            `gorm:"foreignKey:OrganizationID"`
}
```

**Tenant-Scoped Models**:
```go
// All tenant-scoped models include:
type Asset struct {
    Base
    OrganizationID uuid.UUID `gorm:"type:uuid;index;not null" json:"organization_id"`
    // ... other fields
}

type Finding struct {
    Base
    OrganizationID uuid.UUID `gorm:"type:uuid;index;not null" json:"organization_id"`
    // ... other fields
}

type CloudCredential struct {
    Base
    OrganizationID uuid.UUID `gorm:"type:uuid;index;not null" json:"organization_id"`
    // ... other fields
}

type Scan struct {
    Base
    OrganizationID uuid.UUID `gorm:"type:uuid;index;not null" json:"organization_id"`
    // ... other fields
}
```

**JWT Claims with Organization ID** (`internal/auth/jwt.go`):
```go
type Claims struct {
    UserID         uuid.UUID `json:"user_id"`
    OrganizationID uuid.UUID `json:"organization_id"`
    Email          string    `json:"email"`
    Role           string    `json:"role"`
    jwt.RegisteredClaims
}
```

**Middleware Context Injection** (`internal/api/middleware/auth.go`):
```go
func Auth(jwtService *auth.JWTService) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // ... token validation ...

            claims, err := jwtService.ValidateToken(token)
            if err != nil {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }

            // Inject organization ID into context
            ctx := r.Context()
            ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
            ctx = context.WithValue(ctx, OrganizationIDKey, claims.OrganizationID)
            ctx = context.WithValue(ctx, UserRoleKey, claims.Role)

            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// Helper to extract org ID in handlers
func GetOrganizationID(ctx context.Context) uuid.UUID {
    if id, ok := ctx.Value(OrganizationIDKey).(uuid.UUID); ok {
        return id
    }
    return uuid.Nil
}
```

**Handler Query Pattern** (`internal/api/handlers/assets.go`):
```go
func (h *AssetHandler) List(w http.ResponseWriter, r *http.Request) {
    orgID := middleware.GetOrganizationID(r.Context())

    var assets []models.Asset
    query := h.db.Where("organization_id = ?", orgID)

    // Pagination, filtering, etc.
    if err := query.Find(&assets).Error; err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }

    writeJSON(w, http.StatusOK, assets)
}
```

**Worker Task Isolation** (`internal/tasks/handlers.go`):
```go
func (h *Handler) HandlePortScan(ctx context.Context, t *asynq.Task) error {
    var payload PortScanPayload
    json.Unmarshal(t.Payload(), &payload)

    // OrganizationID passed in task payload
    var assets []models.Asset
    h.db.Where("organization_id = ?", payload.OrganizationID).
        Where("id IN ?", payload.AssetIDs).
        Find(&assets)

    // ... scanning logic ...
}
```

## Consequences

### Positive

1. **Simple Operations**: Single database to backup, migrate, and monitor. No per-tenant provisioning.

2. **Efficient Resource Usage**: Connection pooling works across all tenants. No idle connections for inactive tenants.

3. **Easy Migrations**: Schema changes apply to all tenants atomically:
   ```bash
   migrate -path migrations -database $DATABASE_URL up
   ```

4. **Cross-Tenant Queries for Admin**: Platform-wide analytics possible when needed:
   ```sql
   SELECT organization_id, COUNT(*) as findings
   FROM findings
   WHERE severity = 'critical'
   GROUP BY organization_id
   ```

5. **Middleware-Enforced Isolation**: Organization ID flows through the entire request lifecycle:
   - JWT token contains `organization_id`
   - Middleware extracts and injects into context
   - Handlers use context to scope queries
   - Workers receive `organization_id` in task payloads

6. **Index Optimization**: Composite indexes on `(organization_id, ...)` ensure efficient tenant-scoped queries:
   ```go
   OrganizationID uuid.UUID `gorm:"type:uuid;index;not null"`
   ```

### Negative

1. **Query Discipline Required**: Every query must include `WHERE organization_id = ?`. Forgetting this is a security vulnerability.

   **Mitigation**:
   - Code review checklists
   - Integration tests that verify isolation
   - Consider GORM scopes for default filtering

2. **Shared Resource Contention**: Large tenants can impact others during heavy scans.

   **Mitigation**:
   - Per-organization rate limits (`MaxScansDay`)
   - Plan-based quotas (`MaxAssets`, `MaxUsers`)
   - Database connection limits

3. **No Physical Isolation**: Regulatory requirements for some industries may mandate separate databases.

   **Mitigation**:
   - Enterprise tier with dedicated infrastructure
   - Document compliance limitations

4. **Noisy Neighbor Risk**: One tenant's large dataset can slow index operations for all.

   **Mitigation**:
   - Monitor query performance
   - Archive old data aggressively
   - Consider partitioning by organization_id for large tables

5. **Backup/Restore Complexity**: Cannot easily restore a single tenant's data.

   **Mitigation**:
   - Point-in-time recovery for disaster scenarios
   - Export APIs for tenant data portability

### Database Schema Considerations

**Indexes** (all tenant-scoped tables):
```sql
CREATE INDEX idx_assets_org_active ON assets(organization_id, is_active);
CREATE INDEX idx_findings_org_status ON findings(organization_id, status, severity);
CREATE INDEX idx_scans_org_status ON scans(organization_id, status);
```

**Unique Constraints**:
```sql
-- Prevent duplicate assets per organization
CREATE UNIQUE INDEX idx_assets_org_type_value
ON assets(organization_id, type, value);

-- Prevent duplicate credentials per organization
CREATE UNIQUE INDEX idx_creds_org_name
ON cloud_credentials(organization_id, name);
```

### Role-Based Access Within Organizations

```go
type OrgMembership struct {
    UserID         uuid.UUID `gorm:"type:uuid;primaryKey"`
    OrganizationID uuid.UUID `gorm:"type:uuid;primaryKey"`
    Role           string    `gorm:"not null;default:'member'"` // owner, admin, member
}

// Middleware for role-based access
func RequireRole(roles ...string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            userRole := GetUserRole(r.Context())
            for _, role := range roles {
                if userRole == role {
                    next.ServeHTTP(w, r)
                    return
                }
            }
            http.Error(w, "Forbidden", http.StatusForbidden)
        })
    }
}
```

## References

- [Multi-Tenant Data Architecture](https://docs.microsoft.com/en-us/azure/architecture/guide/multitenant/approaches/storage-data)
- [PostgreSQL Row Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) - Alternative approach not chosen
- [GORM Scopes](https://gorm.io/docs/scopes.html) - For potential query automation
