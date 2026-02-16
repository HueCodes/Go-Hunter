# Go-Hunter: Complete Resume-Readiness Improvements

**Context**: This is a continuation prompt to complete the Go-Hunter resume-readiness improvements from 8.0/10 to 9.0/10. Previous work increased test coverage from 20% to 23.6% and completed all critical fixes and high-visibility documentation.

**Current Status**: 10 of 13 tasks complete (77%). See `IMPLEMENTATION_SUMMARY.md` for full details.

---

## Remaining Work Overview

**Goal**: Increase test coverage from 23.6% to 50%+ and add CI/CD enhancements

**Estimated Time**: 6-10 hours total
- High Priority (must do): 4-5 hours
- Medium Priority (should do): 4-5 hours
- Optional Polish: 1-2 hours

**Expected Final Rating**: 9.0/10 (currently 8.0/10)

---

## Task 1: CI/CD Enhancement with Coverage Threshold (HIGH PRIORITY)

**Time**: 1-2 hours
**Impact**: Prevents test coverage regression, professional CI/CD
**File**: `.github/workflows/ci.yml`

### Objective
Add coverage threshold enforcement that fails the build if coverage drops below 50%. This is critical for maintaining quality as the project evolves.

### Implementation Steps

1. **Add coverage threshold check** after line 69 in `.github/workflows/ci.yml`:

```yaml
      - name: Coverage threshold check
        run: |
          coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          echo "Current coverage: $coverage%"
          if (( $(echo "$coverage < 50.0" | bc -l) )); then
            echo "❌ Coverage $coverage% is below 50% threshold"
            exit 1
          fi
          echo "✅ Coverage $coverage% meets threshold"
```

2. **Add coverage HTML report generation**:

```yaml
      - name: Generate coverage HTML
        run: go tool cover -html=coverage.out -o coverage.html

      - name: Upload coverage report
        uses: actions/upload-artifact@v4
        with:
          name: coverage-report
          path: coverage.html
          retention-days: 30
```

3. **Test locally**:
```bash
# Generate coverage
go test -coverprofile=coverage.out ./...

# Check threshold
coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
echo "Coverage: $coverage%"

# Generate HTML report
go tool cover -html=coverage.out -o coverage.html
open coverage.html  # View in browser
```

### Verification
- [ ] CI runs successfully with current coverage (23.6%)
- [ ] Threshold will fail if coverage drops below 50% (after completing other tasks)
- [ ] Coverage HTML report is uploaded as artifact
- [ ] Can download and view coverage report from GitHub Actions

---

## Task 2: Expand API Handler Test Coverage (HIGH PRIORITY)

**Time**: 3-4 hours
**Impact**: +8-10% coverage increase
**Files to enhance**:
- `internal/api/handlers/assets_test.go`
- `internal/api/handlers/scans_test.go`
- `internal/api/handlers/findings_test.go`
- `internal/api/handlers/auth_test.go`

### Current State
Some tests exist but coverage is only ~15%. Need to add:
- Negative test cases (validation failures, unauthorized access)
- Edge cases (empty results, pagination)
- Error scenarios (database errors, invalid input)

### Implementation Pattern

**Example: Expanding `assets_test.go`**

```go
// Add these test cases (refer to existing tests for patterns)

func TestGetAssets_Unauthorized(t *testing.T) {
    // Test without auth token - should return 401
    setup := testutil.NewTestContext(t)
    defer setup.Cleanup()

    req := testutil.UnauthenticatedRequest(t, "GET", "/api/v1/assets", nil)
    rec := httptest.NewRecorder()

    handler := handlers.NewAssetHandler(setup.DB, logger)
    handler.GetAssets(rec, req)

    testutil.AssertStatus(t, rec, http.StatusUnauthorized)
}

func TestGetAssets_WrongOrganization(t *testing.T) {
    // Test that users can't see other org's assets
    setup := testutil.NewTestContext(t)
    defer setup.Cleanup()

    // Create asset for different org
    otherOrg := testutil.CreateTestOrg(t, setup.DB)
    otherAsset := testutil.CreateTestAsset(t, setup.DB, otherOrg.ID, models.AssetTypeIP, "192.0.2.1")

    // Request with setup.User (different org)
    req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/assets", nil, setup.Token)
    rec := httptest.NewRecorder()

    handler := handlers.NewAssetHandler(setup.DB, logger)
    handler.GetAssets(rec, req)

    // Should not include other org's asset
    var response handlers.AssetsResponse
    testutil.ParseJSONResponse(t, rec, &response)

    for _, asset := range response.Assets {
        assert.NotEqual(t, otherAsset.ID, asset.ID, "Should not see other org's assets")
    }
}

func TestCreateAsset_ValidationFailure(t *testing.T) {
    // Test invalid asset creation
    tests := []struct {
        name     string
        payload  interface{}
        errorMsg string
    }{
        {
            name: "empty_value",
            payload: map[string]interface{}{
                "type":   "ip",
                "value":  "",
            },
            errorMsg: "value is required",
        },
        {
            name: "invalid_type",
            payload: map[string]interface{}{
                "type":   "invalid_type",
                "value":  "192.0.2.1",
            },
            errorMsg: "invalid asset type",
        },
        {
            name: "invalid_ip",
            payload: map[string]interface{}{
                "type":   "ip",
                "value":  "not-an-ip",
            },
            errorMsg: "invalid IP address",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            setup := testutil.NewTestContext(t)
            defer setup.Cleanup()

            req := testutil.AuthenticatedRequest(t, "POST", "/api/v1/assets", tt.payload, setup.Token)
            rec := httptest.NewRecorder()

            handler := handlers.NewAssetHandler(setup.DB, logger)
            handler.CreateAsset(rec, req)

            assert.Equal(t, http.StatusBadRequest, rec.Code)
            assert.Contains(t, rec.Body.String(), tt.errorMsg)
        })
    }
}

func TestGetAssets_Pagination(t *testing.T) {
    // Test pagination works correctly
    setup := testutil.NewTestContext(t)
    defer setup.Cleanup()

    // Create 25 assets
    for i := 0; i < 25; i++ {
        testutil.CreateTestAsset(t, setup.DB, setup.Org.ID, models.AssetTypeIP,
            fmt.Sprintf("192.0.2.%d", i))
    }

    // Test first page
    req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/assets?page=1&limit=10", nil, setup.Token)
    rec := httptest.NewRecorder()

    handler := handlers.NewAssetHandler(setup.DB, logger)
    handler.GetAssets(rec, req)

    var response handlers.AssetsResponse
    testutil.ParseJSONResponse(t, rec, &response)

    assert.Equal(t, 10, len(response.Assets))
    assert.Equal(t, 25, response.Total)
    assert.Equal(t, 1, response.Page)
}
```

### Files to Update

**Priority 1: `assets_test.go`** (2 hours)
- [ ] Unauthorized access tests
- [ ] Multi-tenant isolation tests
- [ ] Validation failure tests (empty value, invalid type, invalid format)
- [ ] Pagination tests (page 1, page 2, limits)
- [ ] Database error handling
- [ ] Asset filtering tests (by type, by status)

**Priority 2: `scans_test.go`** (1 hour)
- [ ] Create scan with invalid config
- [ ] Cancel scan that doesn't exist
- [ ] Get scan results for wrong organization
- [ ] Scan status transitions

**Priority 3: `findings_test.go`** (30 minutes)
- [ ] Filter findings by severity
- [ ] Mark finding as resolved/false positive
- [ ] Finding deduplication logic

**Priority 4: `auth_test.go`** (30 minutes)
- [ ] Login with wrong password
- [ ] Login with non-existent user
- [ ] Token refresh flow

### Verification
```bash
# Check coverage improvement
go test -cover ./internal/api/handlers

# Target: 70%+ coverage (currently ~15%)
```

---

## Task 3: Rate Limit Middleware Tests (MEDIUM PRIORITY)

**Time**: 2 hours
**Impact**: +2% coverage, security testing
**File to create**: `internal/api/middleware/ratelimit_test.go`

### Objective
Test rate limiting middleware that protects against abuse. Uses Redis for distributed rate limiting.

### Implementation

**Read the existing middleware first**:
```bash
cat internal/api/middleware/ratelimit.go
```

**Create comprehensive test file** (~150-200 lines):

```go
package middleware

import (
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/alicebob/miniredis/v2"
    "github.com/redis/go-redis/v9"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestRateLimit_AllowedRequests(t *testing.T) {
    // Setup mock Redis
    mr, err := miniredis.Run()
    require.NoError(t, err)
    defer mr.Close()

    client := redis.NewClient(&redis.Options{
        Addr: mr.Addr(),
    })

    // Create rate limiter (100 requests per minute)
    middleware := RateLimit(client, 100, time.Minute)

    handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))

    // Make 50 requests - all should succeed
    for i := 0; i < 50; i++ {
        req := httptest.NewRequest("GET", "/api/test", nil)
        req.RemoteAddr = "192.0.2.1:12345"
        rec := httptest.NewRecorder()

        handler.ServeHTTP(rec, req)
        assert.Equal(t, http.StatusOK, rec.Code, "Request %d should succeed", i)
    }
}

func TestRateLimit_ExceedLimit(t *testing.T) {
    mr, err := miniredis.Run()
    require.NoError(t, err)
    defer mr.Close()

    client := redis.NewClient(&redis.Options{
        Addr: mr.Addr(),
    })

    // Create strict rate limiter (5 requests per minute)
    middleware := RateLimit(client, 5, time.Minute)

    handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))

    // Make 10 requests - first 5 succeed, next 5 fail
    for i := 0; i < 10; i++ {
        req := httptest.NewRequest("GET", "/api/test", nil)
        req.RemoteAddr = "192.0.2.1:12345"
        rec := httptest.NewRecorder()

        handler.ServeHTTP(rec, req)

        if i < 5 {
            assert.Equal(t, http.StatusOK, rec.Code, "Request %d should succeed", i)
        } else {
            assert.Equal(t, http.StatusTooManyRequests, rec.Code, "Request %d should be rate limited", i)
        }
    }
}

func TestRateLimit_DifferentIPs(t *testing.T) {
    // Test that different IPs have separate rate limits
    mr, err := miniredis.Run()
    require.NoError(t, err)
    defer mr.Close()

    client := redis.NewClient(&redis.Options{
        Addr: mr.Addr(),
    })

    middleware := RateLimit(client, 5, time.Minute)
    handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))

    // IP 1: make 5 requests
    for i := 0; i < 5; i++ {
        req := httptest.NewRequest("GET", "/api/test", nil)
        req.RemoteAddr = "192.0.2.1:12345"
        rec := httptest.NewRecorder()
        handler.ServeHTTP(rec, req)
        assert.Equal(t, http.StatusOK, rec.Code)
    }

    // IP 2: should also be able to make 5 requests
    for i := 0; i < 5; i++ {
        req := httptest.NewRequest("GET", "/api/test", nil)
        req.RemoteAddr = "192.0.2.2:12345"
        rec := httptest.NewRecorder()
        handler.ServeHTTP(rec, req)
        assert.Equal(t, http.StatusOK, rec.Code)
    }
}

func TestRateLimit_RateLimitHeaders(t *testing.T) {
    // Test that rate limit headers are set
    mr, err := miniredis.Run()
    require.NoError(t, err)
    defer mr.Close()

    client := redis.NewClient(&redis.Options{
        Addr: mr.Addr(),
    })

    middleware := RateLimit(client, 10, time.Minute)
    handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))

    req := httptest.NewRequest("GET", "/api/test", nil)
    req.RemoteAddr = "192.0.2.1:12345"
    rec := httptest.NewRecorder()

    handler.ServeHTTP(rec, req)

    // Check for X-RateLimit headers
    assert.NotEmpty(t, rec.Header().Get("X-RateLimit-Limit"))
    assert.NotEmpty(t, rec.Header().Get("X-RateLimit-Remaining"))
}
```

### Setup miniredis dependency
```bash
go get github.com/alicebob/miniredis/v2
```

### Verification
```bash
go test ./internal/api/middleware -v -run TestRateLimit
```

---

## Task 4: CSRF Middleware Tests (MEDIUM PRIORITY)

**Time**: 2 hours
**Impact**: +2% coverage, security testing
**File to create**: `internal/api/middleware/csrf_test.go`

### Objective
Test CSRF protection middleware ensuring web forms are protected against cross-site request forgery.

### Implementation

**Read the middleware first**:
```bash
cat internal/api/middleware/csrf.go
```

**Create test file** (~150-200 lines):

```go
package middleware

import (
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestCSRF_GetRequestAllowed(t *testing.T) {
    // GET requests should not require CSRF token
    middleware := CSRF("test-secret")

    handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))

    req := httptest.NewRequest("GET", "/form", nil)
    rec := httptest.NewRecorder()

    handler.ServeHTTP(rec, req)
    assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCSRF_PostWithValidToken(t *testing.T) {
    middleware := CSRF("test-secret")

    // First, get CSRF token from GET request
    getHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Token should be in context or cookie
        w.WriteHeader(http.StatusOK)
    }))

    getReq := httptest.NewRequest("GET", "/form", nil)
    getRec := httptest.NewRecorder()
    getHandler.ServeHTTP(getRec, getReq)

    // Extract CSRF token from cookie
    cookies := getRec.Result().Cookies()
    var csrfToken string
    for _, cookie := range cookies {
        if cookie.Name == "csrf_token" {
            csrfToken = cookie.Value
            break
        }
    }

    assert.NotEmpty(t, csrfToken, "CSRF token should be set in cookie")

    // Now POST with valid token
    postHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))

    postReq := httptest.NewRequest("POST", "/form", strings.NewReader("data"))
    postReq.Header.Set("X-CSRF-Token", csrfToken)
    postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
    postRec := httptest.NewRecorder()

    postHandler.ServeHTTP(postRec, postReq)
    assert.Equal(t, http.StatusOK, postRec.Code)
}

func TestCSRF_PostWithoutToken(t *testing.T) {
    middleware := CSRF("test-secret")

    handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        t.Error("Handler should not be called without CSRF token")
    }))

    req := httptest.NewRequest("POST", "/form", strings.NewReader("data"))
    rec := httptest.NewRecorder()

    handler.ServeHTTP(rec, req)
    assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCSRF_PostWithInvalidToken(t *testing.T) {
    middleware := CSRF("test-secret")

    handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        t.Error("Handler should not be called with invalid CSRF token")
    }))

    req := httptest.NewRequest("POST", "/form", strings.NewReader("data"))
    req.Header.Set("X-CSRF-Token", "invalid-token")
    rec := httptest.NewRecorder()

    handler.ServeHTTP(rec, req)
    assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCSRF_APIEndpointExemption(t *testing.T) {
    // API endpoints should be exempt from CSRF
    middleware := CSRF("test-secret")

    handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))

    req := httptest.NewRequest("POST", "/api/v1/assets", strings.NewReader("{}"))
    rec := httptest.NewRecorder()

    handler.ServeHTTP(rec, req)
    // Should pass through without CSRF check for API
    // (Actual behavior depends on implementation)
}
```

### Verification
```bash
go test ./internal/api/middleware -v -run TestCSRF
```

---

## Task 5: Azure and GCP Provider Test Frameworks (OPTIONAL)

**Time**: 4-6 hours (2-3 hours each)
**Impact**: +4-6% coverage
**Files to create**:
- `internal/assets/azure/provider_test.go`
- `internal/assets/gcp/provider_test.go`

### Objective
Create test frameworks for Azure and GCP providers following the same pattern as AWS tests.

### Azure Provider Tests

**Read the provider first**:
```bash
cat internal/assets/azure/provider.go
```

**Create test file** (similar structure to AWS tests):
```go
package azure

import (
    "context"
    "testing"
    // Azure SDK imports
)

func TestProviderName(t *testing.T) {
    // Test provider name is "azure"
}

func TestValidateCredentials(t *testing.T) {
    // Test credential validation
}

func TestLoadConfig(t *testing.T) {
    // Test Azure config loading with tenant ID, subscription ID
}

func TestDiscoverVMs(t *testing.T) {
    // Test VM discovery (skipped pending httptest mock)
}

func TestDiscoverStorage(t *testing.T) {
    // Test storage account discovery
}
```

**Note**: Azure uses REST APIs, so mocking is easier with `httptest.Server`.

### GCP Provider Tests

**Similar structure**:
```go
package gcp

import (
    "context"
    "testing"
    // GCP SDK imports
)

func TestProviderName(t *testing.T) {
    // Test provider name is "gcp"
}

func TestValidateCredentials(t *testing.T) {
    // Test credential validation
}

func TestDiscoverComputeInstances(t *testing.T) {
    // Test Compute Engine discovery
}

func TestDiscoverStorageBuckets(t *testing.T) {
    // Test Cloud Storage discovery
}
```

**Note**: GCP uses gRPC, which is more complex to mock. Consider skipping detailed tests and focusing on config/validation tests.

---

## Task 6: Push to GitHub and Enable Real Badges (HIGH PRIORITY)

**Time**: 30-60 minutes
**Impact**: High visibility, professional appearance

### Steps

1. **Push all commits to GitHub**:
```bash
# Review commits
git log --oneline -5

# Push to main
git push origin main

# Verify on GitHub
open https://github.com/YOUR_USERNAME/go-hunter
```

2. **Set up Codecov**:
   - Sign up at https://codecov.io (free for open source)
   - Connect your GitHub repository
   - Get upload token
   - Add `CODECOV_TOKEN` to GitHub repository secrets:
     * Settings → Secrets and variables → Actions
     * New repository secret: `CODECOV_TOKEN`
   - CI already uploads coverage (`.github/workflows/ci.yml`)

3. **Generate Go Report Card**:
   - Visit https://goreportcard.com
   - Enter: `github.com/YOUR_USERNAME/go-hunter`
   - Click "Generate Report"
   - Wait for analysis (may take 5-10 minutes)

4. **Update README badges** (replace lines 12-16):
```markdown
<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go 1.22+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License MIT"></a>
  <a href="https://github.com/YOUR_USERNAME/go-hunter/actions"><img src="https://github.com/YOUR_USERNAME/go-hunter/workflows/CI/badge.svg" alt="Build Status"></a>
  <a href="https://goreportcard.com/report/github.com/YOUR_USERNAME/go-hunter"><img src="https://goreportcard.com/badge/github.com/YOUR_USERNAME/go-hunter" alt="Go Report Card"></a>
  <a href="https://codecov.io/gh/YOUR_USERNAME/go-hunter"><img src="https://codecov.io/gh/YOUR_USERNAME/go-hunter/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://pkg.go.dev/github.com/YOUR_USERNAME/go-hunter"><img src="https://pkg.go.dev/badge/github.com/YOUR_USERNAME/go-hunter" alt="GoDoc"></a>
</p>
```

5. **Commit badge updates**:
```bash
git add README.md
git commit -m "Update README with real GitHub badges

Replace placeholder badges with real badges showing:
- CI build status from GitHub Actions
- Test coverage from Codecov
- Code quality from Go Report Card
- API documentation from GoDoc

All badges now display live metrics."

git push origin main
```

### Verification
- [ ] CI badge shows passing (green checkmark)
- [ ] Codecov badge shows coverage percentage
- [ ] Go Report Card shows A or A+ rating
- [ ] All badges are clickable and link to correct pages

---

## Task 7: Optional Polish (1-2 hours)

### 7.1 Pre-commit Hooks (30 minutes)

**File to create**: `.pre-commit-config.yaml`

```yaml
repos:
  - repo: local
    hooks:
      - id: go-test
        name: Go Test
        entry: go test ./...
        language: system
        pass_filenames: false

      - id: go-lint
        name: Go Lint
        entry: golangci-lint run
        language: system
        pass_filenames: false

      - id: go-fmt
        name: Go Format
        entry: gofmt -w
        language: system
        types: [go]
```

**Setup**:
```bash
# Install pre-commit
brew install pre-commit  # macOS
# or: pip install pre-commit

# Install hooks
pre-commit install

# Test
pre-commit run --all-files
```

### 7.2 Dependabot (15 minutes)

**File to create**: `.github/dependabot.yml`

```yaml
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    labels:
      - "dependencies"
      - "go"
```

This automatically creates PRs when Go dependencies have updates.

---

## Verification Checklist

After completing all tasks, verify the final state:

### Code Quality
```bash
# Run all tests
go test ./... -v

# Check coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | grep total
# Target: 50%+ (currently 23.6%)

# Run linters
golangci-lint run

# Check for security issues
gosec ./...
govulncheck ./...
```

### CI/CD
```bash
# Verify CI passes
git push origin main
# Check GitHub Actions - all checks should pass

# Verify coverage threshold works
# (Coverage should be above 50% after completing tasks)
```

### Documentation
- [ ] CHANGELOG.md is up to date
- [ ] README badges show real metrics
- [ ] IMPLEMENTATION_SUMMARY.md reflects final state
- [ ] All documentation is professional and polished

### Final Score Calculation

| Criterion | Weight | Before | Target | Score |
|-----------|--------|--------|--------|-------|
| Test Coverage | 25% | 5/10 (23.6%) | 9/10 (50%+) | 2.25 |
| Documentation | 20% | 9/10 | 9/10 | 1.80 |
| CI/CD Pipeline | 15% | 8/10 | 9/10 | 1.35 |
| Code Quality | 15% | 9/10 | 9/10 | 1.35 |
| Security | 10% | 9/10 | 9/10 | 0.90 |
| Architecture | 10% | 9/10 | 9/10 | 0.90 |
| Polish | 5% | 8/10 | 9/10 | 0.45 |
| **TOTAL** | 100% | 8.0/10 | **9.0/10** | ✅ |

---

## Success Criteria

**Must Have (9.0/10 rating)**:
- ✅ Test coverage ≥ 50%
- ✅ All middleware tests complete (auth, rate limit, CSRF)
- ✅ Expanded API handler tests (70%+ coverage)
- ✅ CI coverage threshold enforcement
- ✅ Real GitHub badges (Codecov, Go Report Card)

**Nice to Have (9.5/10 rating)**:
- ✅ Azure/GCP provider tests
- ✅ Pre-commit hooks
- ✅ Dependabot configuration

---

## Estimated Timeline

**Session 1 (4-5 hours)**: Complete high-priority tasks
- CI/CD enhancement (1-2 hours)
- API handler test expansion (3-4 hours)

**Session 2 (2-3 hours)**: Complete medium-priority tasks
- Rate limit middleware tests (2 hours)
- CSRF middleware tests (2 hours)

**Session 3 (1-2 hours)**: Polish and badges
- Push to GitHub (30 minutes)
- Set up real badges (30-60 minutes)
- Pre-commit hooks (30 minutes)

**Total**: 7-10 hours to reach 9.0/10 rating

---

## Notes for Next Session

### What's Already Done
- ✅ All critical blockers fixed (LICENSE, Dockerfile security, test compilation)
- ✅ Test utilities package exists and is comprehensive
- ✅ AWS provider test framework created
- ✅ Task handler tests complete (15 passing tests)
- ✅ Auth middleware tests complete (16+ passing tests)
- ✅ Professional documentation (CHANGELOG, BADGES guide)

### What Needs Work
- ⏳ Coverage is 23.6%, need to reach 50%+
- ⏳ CI/CD needs coverage threshold
- ⏳ API handlers need expanded tests
- ⏳ Rate limit and CSRF middleware need tests
- ⏳ Real badges need GitHub push and service setup

### Files to Focus On
1. `.github/workflows/ci.yml` - Add coverage threshold
2. `internal/api/handlers/*_test.go` - Expand tests
3. `internal/api/middleware/ratelimit_test.go` - Create
4. `internal/api/middleware/csrf_test.go` - Create
5. `README.md` - Update with real badges after GitHub push

### Testing Strategy
- Use table-driven tests for multiple scenarios
- Use `testutil.NewTestContext(t)` for test setup
- Use `httptest.NewRecorder()` for HTTP testing
- Use `miniredis` for Redis testing (rate limiter)
- Follow existing test patterns in `auth_test.go` and `handlers_test.go`

---

## Quick Start Command

To pick up where we left off, simply run:

```bash
cd /Users/hugh/Dev/projects/Go-Hunter

# Check current coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | grep total

# See what's been done
git log --oneline -5

# Read this prompt
cat NEXT_STEPS_PROMPT.md

# Start with Task 1: CI/CD Enhancement
```

---

**Good luck! With these improvements, Go-Hunter will be a 9.0/10 resume-ready project that will impress any hiring manager.** 🚀
