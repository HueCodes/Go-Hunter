package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuth_ValidToken_AuthorizationHeader(t *testing.T) {
	jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

	userID := uuid.New()
	orgID := uuid.New()
	email := "test@example.com"
	role := "owner"

	token, err := jwtService.GenerateToken(userID, orgID, email, role)
	require.NoError(t, err)

	handler := Auth(jwtService)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify context values are set
		assert.Equal(t, userID, GetUserID(r.Context()))
		assert.Equal(t, orgID, GetOrganizationID(r.Context()))
		assert.Equal(t, email, GetUserEmail(r.Context()))
		assert.Equal(t, role, GetUserRole(r.Context()))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "OK", rec.Body.String())
}

func TestAuth_ValidToken_Cookie(t *testing.T) {
	jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

	userID := uuid.New()
	orgID := uuid.New()
	token, err := jwtService.GenerateToken(userID, orgID, "test@example.com", "admin")
	require.NoError(t, err)

	handler := Auth(jwtService)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, userID, GetUserID(r.Context()))
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{
		Name:  "token",
		Value: token,
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuth_ValidToken_XAuthTokenHeader(t *testing.T) {
	jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

	userID := uuid.New()
	orgID := uuid.New()
	token, err := jwtService.GenerateToken(userID, orgID, "test@example.com", "member")
	require.NoError(t, err)

	handler := Auth(jwtService)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, userID, GetUserID(r.Context()))
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-Auth-Token", token)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuth_NoToken_APIRequest(t *testing.T) {
	jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

	handler := Auth(jwtService)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Accept", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Unauthorized")
}

func TestAuth_NoToken_WebRequest(t *testing.T) {
	jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

	handler := Auth(jwtService)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.Header.Set("Accept", "text/html")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should redirect to login
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "/login", rec.Header().Get("Location"))
}

func TestAuth_InvalidToken(t *testing.T) {
	jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

	handler := Auth(jwtService)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuth_ExpiredToken(t *testing.T) {
	// Create service with 1 nanosecond expiration
	jwtService := auth.NewJWTService("test-secret", 1*time.Nanosecond)

	userID := uuid.New()
	orgID := uuid.New()
	token, err := jwtService.GenerateToken(userID, orgID, "test@example.com", "owner")
	require.NoError(t, err)

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	handler := Auth(jwtService)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for expired token")
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuth_TokenFromDifferentSecret(t *testing.T) {
	jwtService1 := auth.NewJWTService("secret-1", 24*time.Hour)
	jwtService2 := auth.NewJWTService("secret-2", 24*time.Hour)

	userID := uuid.New()
	orgID := uuid.New()

	// Generate token with service1
	token, err := jwtService1.GenerateToken(userID, orgID, "test@example.com", "owner")
	require.NoError(t, err)

	// Try to validate with service2 (different secret)
	handler := Auth(jwtService2)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for token with different secret")
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGetUserID_FromContext(t *testing.T) {
	userID := uuid.New()
	ctx := context.WithValue(context.Background(), UserIDKey, userID)

	result := GetUserID(ctx)
	assert.Equal(t, userID, result)
}

func TestGetUserID_NotInContext(t *testing.T) {
	ctx := context.Background()

	result := GetUserID(ctx)
	assert.Equal(t, uuid.Nil, result)
}

func TestGetOrganizationID_FromContext(t *testing.T) {
	orgID := uuid.New()
	ctx := context.WithValue(context.Background(), OrganizationIDKey, orgID)

	result := GetOrganizationID(ctx)
	assert.Equal(t, orgID, result)
}

func TestGetOrganizationID_NotInContext(t *testing.T) {
	ctx := context.Background()

	result := GetOrganizationID(ctx)
	assert.Equal(t, uuid.Nil, result)
}

func TestGetUserEmail_FromContext(t *testing.T) {
	email := "test@example.com"
	ctx := context.WithValue(context.Background(), UserEmailKey, email)

	result := GetUserEmail(ctx)
	assert.Equal(t, email, result)
}

func TestGetUserEmail_NotInContext(t *testing.T) {
	ctx := context.Background()

	result := GetUserEmail(ctx)
	assert.Equal(t, "", result)
}

func TestGetUserRole_FromContext(t *testing.T) {
	role := "admin"
	ctx := context.WithValue(context.Background(), UserRoleKey, role)

	result := GetUserRole(ctx)
	assert.Equal(t, role, result)
}

func TestGetUserRole_NotInContext(t *testing.T) {
	ctx := context.Background()

	result := GetUserRole(ctx)
	assert.Equal(t, "", result)
}

func TestRequireRole_HasRole(t *testing.T) {
	jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

	userID := uuid.New()
	orgID := uuid.New()
	token, err := jwtService.GenerateToken(userID, orgID, "test@example.com", "admin")
	require.NoError(t, err)

	authMiddleware := Auth(jwtService)
	roleMiddleware := RequireRole("admin", "owner")

	handler := authMiddleware(roleMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})))

	req := httptest.NewRequest("GET", "/api/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "OK", rec.Body.String())
}

func TestRequireRole_DoesNotHaveRole(t *testing.T) {
	jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

	userID := uuid.New()
	orgID := uuid.New()
	token, err := jwtService.GenerateToken(userID, orgID, "test@example.com", "member")
	require.NoError(t, err)

	authMiddleware := Auth(jwtService)
	roleMiddleware := RequireRole("admin", "owner")

	handler := authMiddleware(roleMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for insufficient role")
	})))

	req := httptest.NewRequest("GET", "/api/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "Forbidden")
}

func TestRequireRole_MultipleRoles(t *testing.T) {
	jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

	tests := []struct {
		name           string
		userRole       string
		requiredRoles  []string
		expectedStatus int
	}{
		{
			name:           "owner_has_access",
			userRole:       "owner",
			requiredRoles:  []string{"owner", "admin"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "admin_has_access",
			userRole:       "admin",
			requiredRoles:  []string{"owner", "admin"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "member_denied",
			userRole:       "member",
			requiredRoles:  []string{"owner", "admin"},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userID := uuid.New()
			orgID := uuid.New()
			token, err := jwtService.GenerateToken(userID, orgID, "test@example.com", tt.userRole)
			require.NoError(t, err)

			authMiddleware := Auth(jwtService)
			roleMiddleware := RequireRole(tt.requiredRoles...)

			handler := authMiddleware(roleMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})))

			req := httptest.NewRequest("GET", "/api/test", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
		})
	}
}
