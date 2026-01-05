package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

const (
	csrfTokenLength  = 32
	csrfCookieName   = "csrf_token"
	csrfHeaderName   = "X-CSRF-Token"
	csrfFormField    = "csrf_token"
	csrfTokenExpiry  = 24 * time.Hour
)

// CSRFToken represents a CSRF token with expiry
type CSRFToken struct {
	Token     string
	ExpiresAt time.Time
}

// CSRFStore stores CSRF tokens (in-memory for simplicity)
type CSRFStore struct {
	tokens map[string]CSRFToken
	mu     sync.RWMutex
}

// NewCSRFStore creates a new CSRF token store
func NewCSRFStore() *CSRFStore {
	store := &CSRFStore{
		tokens: make(map[string]CSRFToken),
	}

	// Start cleanup goroutine
	go store.cleanup()

	return store
}

// cleanup removes expired tokens periodically
func (s *CSRFStore) cleanup() {
	ticker := time.NewTicker(time.Hour)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for sessionID, token := range s.tokens {
			if now.After(token.ExpiresAt) {
				delete(s.tokens, sessionID)
			}
		}
		s.mu.Unlock()
	}
}

// GetOrCreate returns an existing token or creates a new one
func (s *CSRFStore) GetOrCreate(sessionID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for existing valid token
	if token, exists := s.tokens[sessionID]; exists {
		if time.Now().Before(token.ExpiresAt) {
			return token.Token
		}
	}

	// Generate new token
	tokenBytes := make([]byte, csrfTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		// Fallback to less secure but functional token
		tokenBytes = []byte(time.Now().String())
	}

	token := base64.URLEncoding.EncodeToString(tokenBytes)

	s.tokens[sessionID] = CSRFToken{
		Token:     token,
		ExpiresAt: time.Now().Add(csrfTokenExpiry),
	}

	return token
}

// Validate checks if the provided token is valid for the session
func (s *CSRFStore) Validate(sessionID, providedToken string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, exists := s.tokens[sessionID]
	if !exists {
		return false
	}

	if time.Now().After(token.ExpiresAt) {
		return false
	}

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(token.Token), []byte(providedToken)) == 1
}

// CSRF returns a middleware that protects against CSRF attacks
// This is primarily for cookie-based authentication (web dashboard)
// API requests using Bearer tokens in headers are not vulnerable to CSRF
func CSRF(store *CSRFStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CSRF check for safe methods
			if r.Method == http.MethodGet ||
			   r.Method == http.MethodHead ||
			   r.Method == http.MethodOptions ||
			   r.Method == http.MethodTrace {
				// For GET requests, ensure CSRF token is set in cookie
				ensureCSRFCookie(w, r, store)
				next.ServeHTTP(w, r)
				return
			}

			// Skip CSRF check if using Bearer token (API requests)
			if authHeader := r.Header.Get("Authorization"); authHeader != "" {
				next.ServeHTTP(w, r)
				return
			}

			// For cookie-based auth, validate CSRF token
			sessionID := getSessionID(r)
			if sessionID == "" {
				http.Error(w, "Session required", http.StatusForbidden)
				return
			}

			// Get CSRF token from header or form
			csrfToken := r.Header.Get(csrfHeaderName)
			if csrfToken == "" {
				csrfToken = r.FormValue(csrfFormField)
			}

			if csrfToken == "" {
				http.Error(w, "CSRF token missing", http.StatusForbidden)
				return
			}

			if !store.Validate(sessionID, csrfToken) {
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ensureCSRFCookie sets the CSRF token cookie if not present
func ensureCSRFCookie(w http.ResponseWriter, r *http.Request, store *CSRFStore) {
	sessionID := getSessionID(r)
	if sessionID == "" {
		return
	}

	// Check if cookie already exists
	if _, err := r.Cookie(csrfCookieName); err == nil {
		return
	}

	// Generate and set CSRF token cookie
	token := store.GetOrCreate(sessionID)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // JavaScript needs to read this
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(csrfTokenExpiry.Seconds()),
	})
}

// getSessionID extracts a session identifier from the request
// Uses the JWT token cookie as session identifier
func getSessionID(r *http.Request) string {
	if cookie, err := r.Cookie("token"); err == nil {
		// Use first 16 chars of token as session ID
		if len(cookie.Value) > 16 {
			return cookie.Value[:16]
		}
		return cookie.Value
	}
	return ""
}

// GetCSRFToken helper to get CSRF token for templates
func GetCSRFToken(r *http.Request, store *CSRFStore) string {
	sessionID := getSessionID(r)
	if sessionID == "" {
		return ""
	}
	return store.GetOrCreate(sessionID)
}
