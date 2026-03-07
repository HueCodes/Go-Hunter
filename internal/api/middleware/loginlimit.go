package middleware

import (
	"net/http"
	"sync"
	"time"
)

type loginAttempt struct {
	count    int
	lastFail time.Time
	lockUntil time.Time
}

type LoginLimiter struct {
	mu           sync.Mutex
	attempts     map[string]*loginAttempt
	maxAttempts  int
	lockDuration time.Duration
}

func NewLoginLimiter(maxAttempts int, lockDuration time.Duration) *LoginLimiter {
	ll := &LoginLimiter{
		attempts:     make(map[string]*loginAttempt),
		maxAttempts:  maxAttempts,
		lockDuration: lockDuration,
	}
	go ll.cleanup()
	return ll
}

func (ll *LoginLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		ll.mu.Lock()
		now := time.Now()
		for key, attempt := range ll.attempts {
			if now.Sub(attempt.lastFail) > ll.lockDuration*2 {
				delete(ll.attempts, key)
			}
		}
		ll.mu.Unlock()
	}
}

func (ll *LoginLimiter) IsLocked(key string) bool {
	ll.mu.Lock()
	defer ll.mu.Unlock()

	attempt, exists := ll.attempts[key]
	if !exists {
		return false
	}

	if time.Now().Before(attempt.lockUntil) {
		return true
	}

	if time.Now().After(attempt.lockUntil) && attempt.count >= ll.maxAttempts {
		attempt.count = 0
	}

	return false
}

func (ll *LoginLimiter) RecordFailure(key string) {
	ll.mu.Lock()
	defer ll.mu.Unlock()

	attempt, exists := ll.attempts[key]
	if !exists {
		attempt = &loginAttempt{}
		ll.attempts[key] = attempt
	}

	attempt.count++
	attempt.lastFail = time.Now()

	if attempt.count >= ll.maxAttempts {
		multiplier := attempt.count / ll.maxAttempts
		if multiplier > 4 {
			multiplier = 4
		}
		attempt.lockUntil = time.Now().Add(ll.lockDuration * time.Duration(multiplier))
	}
}

func (ll *LoginLimiter) RecordSuccess(key string) {
	ll.mu.Lock()
	defer ll.mu.Unlock()
	delete(ll.attempts, key)
}

func (ll *LoginLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ip = forwarded
			}

			if ll.IsLocked(ip) {
				http.Error(w, "Too many login attempts. Please try again later.", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
