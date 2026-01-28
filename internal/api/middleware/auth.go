package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/auth"
)

type contextKey string

const (
	UserIDKey         contextKey = "user_id"
	OrganizationIDKey contextKey = "organization_id"
	UserEmailKey      contextKey = "user_email"
	UserRoleKey       contextKey = "user_role"
)

func Auth(jwtService *auth.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var token string

			// 1. Check Authorization header (API requests)
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}

			// 2. Check cookie (web dashboard)
			if token == "" {
				if cookie, err := r.Cookie("token"); err == nil && cookie.Value != "" {
					token = cookie.Value
				}
			}

			// 3. Check X-Auth-Token header (localStorage fallback for AJAX)
			if token == "" {
				token = r.Header.Get("X-Auth-Token")
			}

			if token == "" {
				handleUnauthorized(w, r)
				return
			}

			claims, err := jwtService.ValidateToken(token)
			if err != nil {
				handleUnauthorized(w, r)
				return
			}

			// Add claims to context
			ctx := r.Context()
			ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, OrganizationIDKey, claims.OrganizationID)
			ctx = context.WithValue(ctx, UserEmailKey, claims.Email)
			ctx = context.WithValue(ctx, UserRoleKey, claims.Role)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// handleUnauthorized returns appropriate response based on request type
func handleUnauthorized(w http.ResponseWriter, r *http.Request) {
	// Check if this is a web page request (not API)
	accept := r.Header.Get("Accept")
	isWebRequest := strings.Contains(accept, "text/html") && !strings.HasPrefix(r.URL.Path, "/api/")

	if isWebRequest {
		// Redirect to login for web requests
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Return 401 for API requests
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// Helper functions to extract values from context
func GetUserID(ctx context.Context) uuid.UUID {
	if id, ok := ctx.Value(UserIDKey).(uuid.UUID); ok {
		return id
	}
	return uuid.Nil
}

func GetOrganizationID(ctx context.Context) uuid.UUID {
	if id, ok := ctx.Value(OrganizationIDKey).(uuid.UUID); ok {
		return id
	}
	return uuid.Nil
}

func GetUserEmail(ctx context.Context) string {
	if email, ok := ctx.Value(UserEmailKey).(string); ok {
		return email
	}
	return ""
}

func GetUserRole(ctx context.Context) string {
	if role, ok := ctx.Value(UserRoleKey).(string); ok {
		return role
	}
	return ""
}

// RequireRole middleware ensures user has specific role
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
