# Security Documentation

This document outlines the security features, architecture decisions, and best practices for deploying and maintaining Go-Hunter securely.

## Table of Contents

- [Security Features Overview](#security-features-overview)
- [Multi-Tenant Isolation](#multi-tenant-isolation)
- [Credential Protection](#credential-protection)
- [Security Headers](#security-headers)
- [Rate Limiting Strategy](#rate-limiting-strategy)
- [Responsible Disclosure Policy](#responsible-disclosure-policy)
- [Security Considerations for Deployment](#security-considerations-for-deployment)

---

## Security Features Overview

### Authentication (JWT with HS256)

Go-Hunter uses JSON Web Tokens (JWT) for authentication, implemented in `internal/auth/jwt.go`.

**Implementation Details:**
- **Algorithm**: HMAC-SHA256 (HS256) for token signing
- **Token Expiry**: Configurable via `JWT_EXPIRY_HOURS` (default: 24 hours)
- **Claims Structure**:
  - `user_id`: UUID of the authenticated user
  - `organization_id`: UUID for multi-tenant isolation
  - `email`: User's email address
  - `role`: User's role (owner, admin, member)
  - Standard JWT claims: `exp`, `iat`, `nbf`, `iss`, `sub`
- **Issuer**: `go-hunter`
- **Token Validation**: Strict validation of signing method to prevent algorithm confusion attacks

```go
// Token validation enforces HMAC signing method
if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
    return nil, ErrInvalidToken
}
```

**Token Delivery:**
- Bearer token in `Authorization` header for API requests
- HTTP-only cookies supported for web dashboard

### Password Hashing (bcrypt)

User passwords are hashed using bcrypt with a cost factor of 12, implemented in `internal/auth/password.go`.

**Security Properties:**
- **Cost Factor**: 12 (provides strong protection against brute-force attacks)
- **Automatic Salting**: bcrypt generates a unique salt for each password
- **Constant-Time Comparison**: Uses bcrypt's built-in comparison to prevent timing attacks

```go
const bcryptCost = 12

func HashPassword(password string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
    // ...
}
```

### Credential Encryption (age)

Cloud provider credentials are encrypted at rest using the [age](https://age-encryption.org/) encryption library, implemented in `pkg/crypto/encryptor.go`.

**Implementation Details:**
- **Algorithm**: X25519 (Curve25519 ECDH) for key exchange
- **Symmetric Encryption**: ChaCha20-Poly1305 (age's default)
- **Key Generation**: Uses `age.GenerateX25519Identity()` for secure key generation
- **Storage Format**: Base64-encoded ciphertext stored in PostgreSQL `bytea` column

### Rate Limiting

Rate limiting is implemented using a sliding window algorithm in `internal/api/middleware/ratelimit.go`.

**Features:**
- Configurable requests per window (default: 100 requests/60 seconds)
- Per-IP limiting for unauthenticated requests
- Per-user limiting for authenticated requests
- Standard rate limit headers in responses

### CORS Configuration

Cross-Origin Resource Sharing is configured in `internal/api/router.go` using `go-chi/cors`.

**Configuration:**
- Configurable allowed origins (defaults to localhost for development)
- Allowed methods: GET, POST, PUT, DELETE, OPTIONS
- Allowed headers: Accept, Authorization, Content-Type, X-CSRF-Token
- Exposed headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
- Credentials allowed for cookie-based auth
- Preflight cache: 300 seconds

### Input Validation

All API inputs are validated before processing, implemented in `internal/api/dto/`.

**Validation Rules:**
- **Email**: Regex validation, max 254 characters
- **Password**: Minimum 8 characters, maximum 128 characters
- **Names**: Maximum 100 characters
- **Asset Types**: Whitelisted values (domain, subdomain, ip, cidr, bucket, container, endpoint)
- **Cloud Providers**: Whitelisted values (aws, gcp, azure, digitalocean, cloudflare)
- **Pagination**: Maximum 100 items per page

### SQL Injection Prevention (GORM Parameterized Queries)

All database queries use GORM's parameterized queries, which automatically escape user input:

```go
// Safe: parameterized query
query := h.db.Model(&models.Asset{}).Where("organization_id = ?", orgID)

// Safe: parameterized with multiple conditions
h.db.Where("id = ? AND organization_id = ?", assetID, orgID).First(&asset)
```

---

## Multi-Tenant Isolation

Go-Hunter implements organization-based multi-tenancy with strict data isolation.

### How organization_id Scoping Works

Every tenant resource includes an `organization_id` foreign key that links it to its owning organization:

```go
// Example from models/asset.go
type Asset struct {
    Base
    OrganizationID uuid.UUID `gorm:"type:uuid;index;not null" json:"organization_id"`
    // ...
}
```

**Scoped Resources:**
- Users
- Cloud Credentials
- Assets
- Scans
- Findings
- Scheduled Scans

### Middleware Enforcement

The authentication middleware (`internal/api/middleware/auth.go`) extracts the organization ID from the JWT and adds it to the request context:

```go
// Add claims to context
ctx := r.Context()
ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
ctx = context.WithValue(ctx, OrganizationIDKey, claims.OrganizationID)
ctx = context.WithValue(ctx, UserEmailKey, claims.Email)
ctx = context.WithValue(ctx, UserRoleKey, claims.Role)
```

Handlers retrieve the organization ID from context and use it in all queries:

```go
orgID := middleware.GetOrganizationID(r.Context())
query := h.db.Model(&models.Asset{}).Where("organization_id = ?", orgID)
```

### Database-Level Isolation

**Query Patterns:**

1. **List Operations**: Always filter by organization_id
   ```go
   h.db.Where("organization_id = ?", orgID).Find(&assets)
   ```

2. **Single Resource Access**: Always verify organization ownership
   ```go
   h.db.Where("id = ? AND organization_id = ?", assetID, orgID).First(&asset)
   ```

3. **Create Operations**: Always set organization_id from context
   ```go
   asset := models.Asset{
       OrganizationID: orgID,
       // ...
   }
   ```

4. **Update/Delete Operations**: Always include organization_id in WHERE clause
   ```go
   h.db.Model(&models.Asset{}).
       Where("id = ? AND organization_id = ?", assetID, orgID).
       Update("is_active", false)
   ```

### Role-Based Access Control

The `RequireRole` middleware enables endpoint-level access control:

```go
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

**Available Roles:**
- `owner`: Full organization access
- `admin`: Administrative access
- `member`: Standard user access

---

## Credential Protection

### How Cloud Credentials Are Encrypted

Cloud credentials are encrypted using the age library before storage:

```go
// internal/assets/service.go - CreateCredential
func (s *Service) CreateCredential(ctx context.Context, orgID uuid.UUID, name string, provider models.CloudProvider, credData interface{}) (*models.CloudCredential, error) {
    // Serialize credential data to JSON
    jsonData, err := json.Marshal(credData)
    if err != nil {
        return nil, fmt.Errorf("serializing credentials: %w", err)
    }

    // Encrypt the credential data
    encrypted, err := s.encryptor.Encrypt(jsonData)
    if err != nil {
        return nil, fmt.Errorf("encrypting credentials: %w", err)
    }

    cred := &models.CloudCredential{
        OrganizationID: orgID,
        Name:           name,
        Provider:       provider,
        EncryptedData:  encrypted,  // Stored as bytea in PostgreSQL
        IsActive:       true,
    }
    // ...
}
```

**Encryption Flow:**
1. Credential data is serialized to JSON
2. JSON is encrypted using age X25519 encryption
3. Ciphertext is stored in PostgreSQL `bytea` column
4. Decrypted credentials are never logged or returned in API responses

### Key Management Approach

**Key Generation:**
```bash
# Generate a new encryption key using age-keygen
age-keygen
```

**Key Storage:**
- The encryption key is provided via the `ENCRYPTION_KEY` environment variable
- Keys should be stored in a secure secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager)
- Never commit encryption keys to version control

**Key Format:**
- age X25519 identity string (starts with `AGE-SECRET-KEY-`)

### When Credentials Are Decrypted

Credentials are only decrypted when actively needed:

1. **Credential Validation**: When testing if credentials are valid
2. **Asset Discovery**: When discovering cloud resources
3. **Scanning Operations**: When running security scans that require cloud access

```go
// internal/assets/service.go - getProvider
func (s *Service) getProvider(cred *models.CloudCredential) (Provider, error) {
    // Decrypt credential data
    decrypted, err := s.encryptor.Decrypt(cred.EncryptedData)
    if err != nil {
        return nil, fmt.Errorf("decrypting credentials: %w", err)
    }
    // Use decrypted credentials to create provider client
    // ...
}
```

**Security Guarantees:**
- Decrypted credentials are never returned in API responses
- Credentials are cleared from memory after use (Go garbage collection)
- List operations explicitly clear encrypted data before returning:
  ```go
  for i := range creds {
      creds[i].EncryptedData = nil
  }
  ```

---

## Security Headers

### CORS Headers

Configured in `internal/api/router.go`:

```go
r.Use(cors.Handler(cors.Options{
    AllowedOrigins:   allowedOrigins,
    AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
    AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
    ExposedHeaders:   []string{"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"},
    AllowCredentials: true,
    MaxAge:           300,
}))
```

### CSRF Protection

Implemented in `internal/api/middleware/csrf.go`:

- **Token Length**: 32 bytes (cryptographically random)
- **Token Expiry**: 24 hours
- **Cookie Settings**:
  - `HttpOnly: false` (JavaScript needs to read the token)
  - `Secure: true` (when TLS is enabled)
  - `SameSite: Strict`
- **Validation**: Constant-time comparison to prevent timing attacks
- **Scope**: Only applies to cookie-based authentication (API Bearer tokens are not vulnerable to CSRF)

### Rate Limit Headers

Set by the rate limiting middleware:

- `X-RateLimit-Limit`: Maximum requests per window
- `X-RateLimit-Remaining`: Requests remaining in current window
- `X-RateLimit-Reset`: Unix timestamp when the window resets
- `Retry-After`: Seconds until retry is allowed (when rate limited)

### Recommended Additional Headers

For production deployments, configure your reverse proxy (nginx, Caddy, etc.) to add:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

---

## Rate Limiting Strategy

### Implementation

Rate limiting uses a sliding window algorithm (`internal/api/middleware/ratelimit.go`):

```go
type RateLimiter struct {
    requests      int           // Maximum requests per window
    window        time.Duration // Window duration
    clients       map[string]*clientWindow
    mu            sync.RWMutex
    cleanupTicker *time.Ticker
}
```

### Per-IP Limits (Unauthenticated Requests)

Applied globally to all requests:

```go
func RateLimit(requests int, windowSeconds int) func(http.Handler) http.Handler
```

**IP Detection Priority:**
1. `X-Forwarded-For` header (first IP in chain)
2. `X-Real-IP` header
3. `RemoteAddr` (fallback)

### Per-User Limits (Authenticated Requests)

For authenticated endpoints:

```go
func RateLimitByUser(requests int, windowSeconds int) func(http.Handler) http.Handler
```

**Key Format:**
- Authenticated: `user:{user_id}`
- Unauthenticated: Falls back to IP address

### Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_REQUESTS` | 100 | Maximum requests per window |
| `RATE_LIMIT_WINDOW_SECONDS` | 60 | Window duration in seconds |

### Response When Rate Limited

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1706000000
Retry-After: 45

Rate limit exceeded
```

---

## Responsible Disclosure Policy

### How to Report Vulnerabilities

If you discover a security vulnerability in Go-Hunter, please report it responsibly:

1. **Email**: Send details to security@[your-domain].com
2. **Subject Line**: `[SECURITY] Brief description of the issue`
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Include in Your Report

- Vulnerability type (e.g., SQL injection, XSS, authentication bypass)
- Affected component/endpoint
- Proof of concept (if safe to demonstrate)
- Your assessment of severity (Critical, High, Medium, Low)

### Expected Response Time

| Stage | Timeframe |
|-------|-----------|
| Initial acknowledgment | 24-48 hours |
| Triage and severity assessment | 3-5 business days |
| Resolution timeline provided | 7 business days |
| Patch released (critical issues) | 7-14 days |
| Patch released (other issues) | 30-90 days |

### Bug Bounty

Currently, Go-Hunter does not operate a formal bug bounty program. However, we deeply appreciate security researchers who report vulnerabilities responsibly and will:

- Credit you in our security advisories (if desired)
- Provide a letter of recognition
- Consider establishing a bounty program in the future

### Safe Harbor

We will not take legal action against researchers who:
- Make a good faith effort to avoid privacy violations
- Do not access or modify data belonging to others
- Do not disrupt our services
- Report vulnerabilities promptly and confidentially

---

## Security Considerations for Deployment

### Required Environment Variables

| Variable | Description | Security Notes |
|----------|-------------|----------------|
| `JWT_SECRET` | JWT signing key | **Required**. Use 256+ bits of randomness. Never use default value in production. |
| `ENCRYPTION_KEY` | age encryption key | **Required**. Generate with `age-keygen`. Store securely. |
| `DATABASE_PASSWORD` | PostgreSQL password | **Required**. Use strong, unique password. |
| `REDIS_PASSWORD` | Redis password | Recommended for production. |

### Secrets Management

**Recommended Approaches:**

1. **HashiCorp Vault**
   ```bash
   export JWT_SECRET=$(vault kv get -field=jwt_secret secret/go-hunter)
   export ENCRYPTION_KEY=$(vault kv get -field=encryption_key secret/go-hunter)
   ```

2. **AWS Secrets Manager**
   ```bash
   export JWT_SECRET=$(aws secretsmanager get-secret-value --secret-id go-hunter/jwt --query SecretString --output text)
   ```

3. **Kubernetes Secrets**
   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: go-hunter-secrets
   type: Opaque
   data:
     JWT_SECRET: <base64-encoded-secret>
     ENCRYPTION_KEY: <base64-encoded-key>
   ```

**Never:**
- Commit secrets to version control
- Log secrets
- Pass secrets as command-line arguments (visible in process lists)
- Store secrets in container images

### Network Security Recommendations

1. **TLS/HTTPS**
   - Always use TLS in production
   - Use TLS 1.2 or higher
   - Consider using a reverse proxy (nginx, Caddy) for TLS termination

2. **Database Security**
   - Enable SSL for PostgreSQL connections (`DATABASE_SSLMODE=require`)
   - Use a private network/VPC for database access
   - Restrict database access to application servers only

3. **Redis Security**
   - Enable Redis authentication
   - Use TLS for Redis connections if available
   - Bind Redis to private interfaces only

4. **Firewall Rules**
   - Expose only necessary ports (typically 443 for HTTPS)
   - Use security groups/firewalls to restrict access
   - Consider IP allowlisting for administrative access

### Production Checklist

- [ ] `SERVER_ENV` set to `production`
- [ ] Strong, unique `JWT_SECRET` configured
- [ ] `ENCRYPTION_KEY` generated and stored securely
- [ ] Database using SSL (`DATABASE_SSLMODE=require` or `verify-full`)
- [ ] Redis password configured
- [ ] CORS origins restricted to your domain(s)
- [ ] Rate limiting configured appropriately
- [ ] TLS enabled (via reverse proxy or direct)
- [ ] Security headers configured in reverse proxy
- [ ] Logging configured (but not logging sensitive data)
- [ ] Regular security updates scheduled
- [ ] Backup encryption keys stored separately from backups
- [ ] Monitoring and alerting configured for security events

### Logging Security

The application logs request information but excludes sensitive data:

```go
logger.Info("request",
    "method", r.Method,
    "path", r.URL.Path,
    "status", wrapped.status,
    "size", wrapped.size,
    "duration", duration.String(),
    "ip", r.RemoteAddr,
)
```

**Security Logging Best Practices:**
- Never log passwords, tokens, or API keys
- Log authentication failures for monitoring
- Use structured logging for easy analysis
- Consider log aggregation for security monitoring
- Implement log rotation to manage disk usage

---

## Security Updates

This document was last updated: January 2026

For the latest security information and advisories, check the project's GitHub repository.
