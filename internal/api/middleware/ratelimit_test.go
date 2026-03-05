package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRateLimiter(t *testing.T) {
	t.Run("uses provided values", func(t *testing.T) {
		rl := NewRateLimiter(50, 30)
		defer rl.cleanupTicker.Stop()

		assert.Equal(t, 50, rl.requests)
		assert.Equal(t, 30*time.Second, rl.window)
		assert.NotNil(t, rl.clients)
	})

	t.Run("defaults when zero values provided", func(t *testing.T) {
		rl := NewRateLimiter(0, 0)
		defer rl.cleanupTicker.Stop()

		assert.Equal(t, 100, rl.requests)
		assert.Equal(t, 60*time.Second, rl.window)
	})

	t.Run("defaults when negative values provided", func(t *testing.T) {
		rl := NewRateLimiter(-1, -5)
		defer rl.cleanupTicker.Stop()

		assert.Equal(t, 100, rl.requests)
		assert.Equal(t, 60*time.Second, rl.window)
	})
}

func TestRateLimiterAllow(t *testing.T) {
	t.Run("allows requests within limit", func(t *testing.T) {
		rl := NewRateLimiter(5, 60)
		defer rl.cleanupTicker.Stop()

		for i := 0; i < 5; i++ {
			allowed, remaining, _ := rl.Allow("192.168.1.1")
			assert.True(t, allowed, "request %d should be allowed", i)
			assert.Equal(t, 5-i-1, remaining, "remaining should decrease")
		}
	})

	t.Run("blocks requests exceeding limit", func(t *testing.T) {
		rl := NewRateLimiter(3, 60)
		defer rl.cleanupTicker.Stop()

		for i := 0; i < 3; i++ {
			allowed, _, _ := rl.Allow("10.0.0.1")
			assert.True(t, allowed)
		}

		allowed, remaining, resetTime := rl.Allow("10.0.0.1")
		assert.False(t, allowed)
		assert.Equal(t, 0, remaining)
		assert.True(t, resetTime.After(time.Now()), "reset time should be in the future")
	})

	t.Run("different IPs have independent limits", func(t *testing.T) {
		rl := NewRateLimiter(2, 60)
		defer rl.cleanupTicker.Stop()

		rl.Allow("ip1")
		rl.Allow("ip1")

		allowed, _, _ := rl.Allow("ip1")
		assert.False(t, allowed, "ip1 should be blocked")

		allowed, _, _ = rl.Allow("ip2")
		assert.True(t, allowed, "ip2 should still be allowed")
	})

	t.Run("sliding window allows after expiry", func(t *testing.T) {
		rl := NewRateLimiter(2, 1) // 1 second window
		defer rl.cleanupTicker.Stop()

		rl.Allow("client")
		rl.Allow("client")

		allowed, _, _ := rl.Allow("client")
		assert.False(t, allowed, "should be blocked")

		// Wait for the window to pass
		time.Sleep(1100 * time.Millisecond)

		allowed, _, _ = rl.Allow("client")
		assert.True(t, allowed, "should be allowed after window expires")
	})
}

func TestRateLimitMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("sets rate limit headers", func(t *testing.T) {
		middleware := RateLimit(10, 60)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "1.2.3.4:5678"
		rr := httptest.NewRecorder()

		wrapped.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "10", rr.Header().Get("X-RateLimit-Limit"))

		remaining, err := strconv.Atoi(rr.Header().Get("X-RateLimit-Remaining"))
		require.NoError(t, err)
		assert.Equal(t, 9, remaining)

		resetStr := rr.Header().Get("X-RateLimit-Reset")
		assert.NotEmpty(t, resetStr)
		resetUnix, err := strconv.ParseInt(resetStr, 10, 64)
		require.NoError(t, err)
		assert.Greater(t, resetUnix, time.Now().Unix()-1)
	})

	t.Run("returns 429 when rate limit exceeded", func(t *testing.T) {
		middleware := RateLimit(2, 60)
		wrapped := middleware(handler)

		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "5.6.7.8:1234"
			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "5.6.7.8:1234"
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusTooManyRequests, rr.Code)
		assert.Equal(t, "0", rr.Header().Get("X-RateLimit-Remaining"))
		assert.NotEmpty(t, rr.Header().Get("Retry-After"))
	})
}

func TestGetClientIP(t *testing.T) {
	t.Run("uses X-Forwarded-For first IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18, 150.172.238.178")

		ip := getClientIP(req)
		assert.Equal(t, "203.0.113.50", ip)
	})

	t.Run("uses X-Forwarded-For single IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.50")

		ip := getClientIP(req)
		assert.Equal(t, "203.0.113.50", ip)
	})

	t.Run("uses X-Real-IP when no X-Forwarded-For", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Real-IP", "10.0.0.100")

		ip := getClientIP(req)
		assert.Equal(t, "10.0.0.100", ip)
	})

	t.Run("prefers X-Forwarded-For over X-Real-IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-For", "1.1.1.1")
		req.Header.Set("X-Real-IP", "2.2.2.2")

		ip := getClientIP(req)
		assert.Equal(t, "1.1.1.1", ip)
	})

	t.Run("falls back to RemoteAddr without port", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:8080"

		ip := getClientIP(req)
		assert.Equal(t, "192.168.1.1", ip)
	})

	t.Run("handles RemoteAddr without port", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1"

		ip := getClientIP(req)
		assert.Equal(t, "192.168.1.1", ip)
	})
}

func TestRateLimitByUserMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("uses user ID from context when present", func(t *testing.T) {
		middleware := RateLimitByUser(2, 60)
		wrapped := middleware(handler)

		userID := uuid.New()

		// Exhaust limit for this user
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "1.2.3.4:5678"
			ctx := context.WithValue(req.Context(), UserIDKey, userID)
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
		}

		// Third request from same user should be blocked
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "1.2.3.4:5678"
		ctx := context.WithValue(req.Context(), UserIDKey, userID)
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusTooManyRequests, rr.Code)

		// Different user from same IP should be allowed
		req = httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "1.2.3.4:5678"
		ctx = context.WithValue(req.Context(), UserIDKey, uuid.New())
		req = req.WithContext(ctx)
		rr = httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("falls back to IP when no user in context", func(t *testing.T) {
		middleware := RateLimitByUser(2, 60)
		wrapped := middleware(handler)

		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "9.9.9.9:1234"
			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
		}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "9.9.9.9:1234"
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	})

	t.Run("sets rate limit headers", func(t *testing.T) {
		middleware := RateLimitByUser(5, 60)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "8.8.8.8:4321"
		userID := uuid.New()
		ctx := context.WithValue(req.Context(), UserIDKey, userID)
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		wrapped.ServeHTTP(rr, req)

		assert.Equal(t, "5", rr.Header().Get("X-RateLimit-Limit"))
		assert.Equal(t, "4", rr.Header().Get("X-RateLimit-Remaining"))
		assert.NotEmpty(t, rr.Header().Get("X-RateLimit-Reset"))
	})
}
