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
			authHeader := r.Header.Get("Authorization")

			// Also check cookie for web dashboard
			if authHeader == "" {
				if cookie, err := r.Cookie("token"); err == nil {
					authHeader = "Bearer " + cookie.Value
				}
			}

			if authHeader == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
				return
			}

			claims, err := jwtService.ValidateToken(parts[1])
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
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
