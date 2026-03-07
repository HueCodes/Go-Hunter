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
	AuthMethodKey     contextKey = "auth_method"
)

func Auth(jwtService *auth.JWTService) func(http.Handler) http.Handler {
	return AuthWithAPIKey(jwtService, nil)
}

func AuthWithAPIKey(jwtService *auth.JWTService, apiKeyService *auth.APIKeyService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var token string
			var isAPIKey bool

			// 1. Check Authorization header
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
				if strings.HasPrefix(token, "ghk_") {
					isAPIKey = true
				}
			}

			// 2. Check cookie (web dashboard)
			if token == "" {
				if cookie, err := r.Cookie("token"); err == nil && cookie.Value != "" {
					token = cookie.Value
				}
			}

			// 3. Check X-Auth-Token header
			if token == "" {
				token = r.Header.Get("X-Auth-Token")
				if strings.HasPrefix(token, "ghk_") {
					isAPIKey = true
				}
			}

			if token == "" {
				handleUnauthorized(w, r)
				return
			}

			// API key authentication
			if isAPIKey && apiKeyService != nil {
				key, err := apiKeyService.Validate(r.Context(), token)
				if err != nil {
					handleUnauthorized(w, r)
					return
				}

				ctx := r.Context()
				ctx = context.WithValue(ctx, UserIDKey, key.UserID)
				ctx = context.WithValue(ctx, OrganizationIDKey, key.OrganizationID)
				ctx = context.WithValue(ctx, UserRoleKey, key.Role)
				ctx = context.WithValue(ctx, AuthMethodKey, "api_key")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// JWT authentication
			claims, err := jwtService.ValidateToken(token)
			if err != nil {
				handleUnauthorized(w, r)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, OrganizationIDKey, claims.OrganizationID)
			ctx = context.WithValue(ctx, UserEmailKey, claims.Email)
			ctx = context.WithValue(ctx, UserRoleKey, claims.Role)
			ctx = context.WithValue(ctx, AuthMethodKey, "jwt")

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func handleUnauthorized(w http.ResponseWriter, r *http.Request) {
	accept := r.Header.Get("Accept")
	isWebRequest := strings.Contains(accept, "text/html") && !strings.HasPrefix(r.URL.Path, "/api/")

	if isWebRequest {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

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

func GetAuthMethod(ctx context.Context) string {
	if method, ok := ctx.Value(AuthMethodKey).(string); ok {
		return method
	}
	return ""
}

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
