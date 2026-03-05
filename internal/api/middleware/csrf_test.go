package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCSRFStoreGetOrCreate(t *testing.T) {
	t.Run("creates a new token for new session", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}

		token := store.GetOrCreate("session1")
		assert.NotEmpty(t, token)
	})

	t.Run("returns same token for same session", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}

		token1 := store.GetOrCreate("session1")
		token2 := store.GetOrCreate("session1")
		assert.Equal(t, token1, token2)
	})

	t.Run("returns different tokens for different sessions", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}

		token1 := store.GetOrCreate("session1")
		token2 := store.GetOrCreate("session2")
		assert.NotEqual(t, token1, token2)
	})

	t.Run("regenerates token after expiry", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}

		// Manually insert an expired token
		store.tokens["expired-session"] = CSRFToken{
			Token:     "old-token",
			ExpiresAt: time.Now().Add(-time.Hour),
		}

		token := store.GetOrCreate("expired-session")
		assert.NotEqual(t, "old-token", token)
		assert.NotEmpty(t, token)
	})
}

func TestCSRFStoreValidate(t *testing.T) {
	t.Run("validates correct token", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}
		token := store.GetOrCreate("session1")

		valid := store.Validate("session1", token)
		assert.True(t, valid)
	})

	t.Run("rejects wrong token", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}
		store.GetOrCreate("session1")

		valid := store.Validate("session1", "wrong-token")
		assert.False(t, valid)
	})

	t.Run("rejects unknown session", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}

		valid := store.Validate("nonexistent", "any-token")
		assert.False(t, valid)
	})

	t.Run("rejects expired token", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}
		store.tokens["expired"] = CSRFToken{
			Token:     "valid-token",
			ExpiresAt: time.Now().Add(-time.Minute),
		}

		valid := store.Validate("expired", "valid-token")
		assert.False(t, valid)
	})
}

func TestCSRFMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("skips safe methods GET", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}
		middleware := CSRF(store)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("skips safe methods HEAD", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}
		middleware := CSRF(store)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodHead, "/test", nil)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("skips safe methods OPTIONS", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}
		middleware := CSRF(store)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodOptions, "/test", nil)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("skips CSRF check for Bearer auth", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}
		middleware := CSRF(store)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.Header.Set("Authorization", "Bearer some-jwt-token")
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("returns 403 when no session cookie on POST", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}
		middleware := CSRF(store)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Contains(t, rr.Body.String(), "Session required")
	})

	t.Run("returns 403 when CSRF token missing", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}
		middleware := CSRF(store)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.AddCookie(&http.Cookie{Name: "token", Value: "abcdefghijklmnopqrstuvwxyz123456"})
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Contains(t, rr.Body.String(), "CSRF token missing")
	})

	t.Run("returns 403 when CSRF token is invalid", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}
		middleware := CSRF(store)
		wrapped := middleware(handler)

		sessionCookie := "abcdefghijklmnopqrstuvwxyz123456"
		// Create a valid token first
		store.GetOrCreate(sessionCookie[:16])

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.AddCookie(&http.Cookie{Name: "token", Value: sessionCookie})
		req.Header.Set("X-CSRF-Token", "invalid-token")
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid CSRF token")
	})

	t.Run("allows POST with valid CSRF token in header", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}
		middleware := CSRF(store)
		wrapped := middleware(handler)

		sessionCookie := "abcdefghijklmnopqrstuvwxyz123456"
		csrfToken := store.GetOrCreate(sessionCookie[:16])

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.AddCookie(&http.Cookie{Name: "token", Value: sessionCookie})
		req.Header.Set("X-CSRF-Token", csrfToken)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("allows PUT with valid CSRF token in header", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}
		middleware := CSRF(store)
		wrapped := middleware(handler)

		sessionCookie := "abcdefghijklmnopqrstuvwxyz123456"
		csrfToken := store.GetOrCreate(sessionCookie[:16])

		req := httptest.NewRequest(http.MethodPut, "/test", nil)
		req.AddCookie(&http.Cookie{Name: "token", Value: sessionCookie})
		req.Header.Set("X-CSRF-Token", csrfToken)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("sets CSRF cookie on GET with session", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}
		middleware := CSRF(store)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.AddCookie(&http.Cookie{Name: "token", Value: "abcdefghijklmnopqrstuvwxyz123456"})
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		// Check that a csrf_token cookie was set
		cookies := rr.Result().Cookies()
		var found bool
		for _, c := range cookies {
			if c.Name == "csrf_token" {
				found = true
				assert.NotEmpty(t, c.Value)
				assert.Equal(t, "/", c.Path)
				assert.False(t, c.HttpOnly) // JS needs to read it
				break
			}
		}
		assert.True(t, found, "csrf_token cookie should be set")
	})

	t.Run("does not set CSRF cookie if already present", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}
		middleware := CSRF(store)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.AddCookie(&http.Cookie{Name: "token", Value: "abcdefghijklmnopqrstuvwxyz123456"})
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "existing-token"})
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		cookies := rr.Result().Cookies()
		for _, c := range cookies {
			assert.NotEqual(t, "csrf_token", c.Name, "should not set csrf_token cookie when already present")
		}
	})
}

func TestGetSessionID(t *testing.T) {
	t.Run("returns truncated token cookie value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "token", Value: "abcdefghijklmnopqrstuvwxyz123456"})

		sessionID := getSessionID(req)
		assert.Equal(t, "abcdefghijklmnop", sessionID)
		assert.Len(t, sessionID, 16)
	})

	t.Run("returns full value when token is short", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "token", Value: "short"})

		sessionID := getSessionID(req)
		assert.Equal(t, "short", sessionID)
	})

	t.Run("returns empty string when no token cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		sessionID := getSessionID(req)
		assert.Empty(t, sessionID)
	})

	t.Run("returns exactly 16 chars for 16-char token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "token", Value: "1234567890123456"})

		sessionID := getSessionID(req)
		// len == 16, not > 16, so returns full value
		assert.Equal(t, "1234567890123456", sessionID)
	})
}

func TestGetCSRFToken(t *testing.T) {
	t.Run("returns token for valid session", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "token", Value: "abcdefghijklmnopqrstuvwxyz123456"})

		token := GetCSRFToken(req, store)
		require.NotEmpty(t, token)

		// Calling again should return the same token
		token2 := GetCSRFToken(req, store)
		assert.Equal(t, token, token2)
	})

	t.Run("returns empty string when no session", func(t *testing.T) {
		store := &CSRFStore{tokens: make(map[string]CSRFToken)}

		req := httptest.NewRequest(http.MethodGet, "/", nil)

		token := GetCSRFToken(req, store)
		assert.Empty(t, token)
	})
}
