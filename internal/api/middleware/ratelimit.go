package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RateLimiter provides rate limiting functionality using a sliding window algorithm
type RateLimiter struct {
	requests      int           // Maximum requests per window
	window        time.Duration // Window duration
	clients       map[string]*clientWindow
	mu            sync.RWMutex
	cleanupTicker *time.Ticker
}

type clientWindow struct {
	timestamps []time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requests int, windowSeconds int) *RateLimiter {
	if requests <= 0 {
		requests = 100 // Default
	}
	if windowSeconds <= 0 {
		windowSeconds = 60 // Default
	}

	rl := &RateLimiter{
		requests: requests,
		window:   time.Duration(windowSeconds) * time.Second,
		clients:  make(map[string]*clientWindow),
	}

	// Start cleanup goroutine to remove old entries
	rl.cleanupTicker = time.NewTicker(time.Minute)
	go rl.cleanup()

	return rl
}

// cleanup removes expired entries periodically
func (rl *RateLimiter) cleanup() {
	for range rl.cleanupTicker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, client := range rl.clients {
			client.mu.Lock()
			if len(client.timestamps) == 0 {
				delete(rl.clients, ip)
			} else if now.Sub(client.timestamps[len(client.timestamps)-1]) > rl.window*2 {
				// No recent activity, remove client
				delete(rl.clients, ip)
			}
			client.mu.Unlock()
		}
		rl.mu.Unlock()
	}
}

// Allow checks if a request from the given IP should be allowed
func (rl *RateLimiter) Allow(ip string) (bool, int, time.Time) {
	rl.mu.RLock()
	client, exists := rl.clients[ip]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check after acquiring write lock
		if client, exists = rl.clients[ip]; !exists {
			client = &clientWindow{
				timestamps: make([]time.Time, 0, rl.requests),
			}
			rl.clients[ip] = client
		}
		rl.mu.Unlock()
	}

	client.mu.Lock()
	defer client.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	// Remove timestamps outside the window
	validIdx := 0
	for i, ts := range client.timestamps {
		if ts.After(windowStart) {
			validIdx = i
			break
		}
		if i == len(client.timestamps)-1 {
			validIdx = len(client.timestamps)
		}
	}
	client.timestamps = client.timestamps[validIdx:]

	// Calculate remaining requests
	remaining := rl.requests - len(client.timestamps)
	if remaining < 0 {
		remaining = 0
	}

	// Check if limit exceeded
	if len(client.timestamps) >= rl.requests {
		// Calculate when the oldest request in window will expire
		resetTime := client.timestamps[0].Add(rl.window)
		return false, remaining, resetTime
	}

	// Allow request and record timestamp
	client.timestamps = append(client.timestamps, now)
	return true, remaining - 1, now.Add(rl.window)
}

// RateLimit returns a middleware that applies rate limiting
func RateLimit(requests int, windowSeconds int) func(http.Handler) http.Handler {
	limiter := NewRateLimiter(requests, windowSeconds)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get client IP
			ip := getClientIP(r)

			allowed, remaining, resetTime := limiter.Allow(ip)

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limiter.requests))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

			if !allowed {
				w.Header().Set("Retry-After", strconv.FormatInt(int64(resetTime.Sub(time.Now()).Seconds())+1, 10))
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (set by proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list (original client)
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP header (set by some proxies)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Remove port if present
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == ':' {
			return ip[:i]
		}
	}
	return ip
}

// RateLimitByUser returns a middleware that applies rate limiting per authenticated user
func RateLimitByUser(requests int, windowSeconds int) func(http.Handler) http.Handler {
	limiter := NewRateLimiter(requests, windowSeconds)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user ID from context, fall back to IP
			key := getClientIP(r)
			if userID := GetUserID(r.Context()); userID.String() != "00000000-0000-0000-0000-000000000000" {
				key = "user:" + userID.String()
			}

			allowed, remaining, resetTime := limiter.Allow(key)

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limiter.requests))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

			if !allowed {
				w.Header().Set("Retry-After", strconv.FormatInt(int64(resetTime.Sub(time.Now()).Seconds())+1, 10))
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
