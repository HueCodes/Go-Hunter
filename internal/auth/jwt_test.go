package auth_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTService_GenerateToken(t *testing.T) {
	jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

	userID := uuid.New()
	orgID := uuid.New()
	email := "test@example.com"
	role := "owner"

	t.Run("generates valid token", func(t *testing.T) {
		token, err := jwtService.GenerateToken(userID, orgID, email, role)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Should be parseable
		claims, err := jwtService.ValidateToken(token)
		require.NoError(t, err)
		assert.Equal(t, userID, claims.UserID)
		assert.Equal(t, orgID, claims.OrganizationID)
		assert.Equal(t, email, claims.Email)
		assert.Equal(t, role, claims.Role)
	})

	t.Run("token contains correct issuer", func(t *testing.T) {
		token, err := jwtService.GenerateToken(userID, orgID, email, role)
		require.NoError(t, err)

		claims, err := jwtService.ValidateToken(token)
		require.NoError(t, err)
		assert.Equal(t, "go-hunter", claims.Issuer)
	})

	t.Run("token contains correct subject", func(t *testing.T) {
		token, err := jwtService.GenerateToken(userID, orgID, email, role)
		require.NoError(t, err)

		claims, err := jwtService.ValidateToken(token)
		require.NoError(t, err)
		assert.Equal(t, userID.String(), claims.Subject)
	})
}

func TestJWTService_ValidateToken(t *testing.T) {
	userID := uuid.New()
	orgID := uuid.New()
	email := "test@example.com"
	role := "admin"

	t.Run("validates correct token", func(t *testing.T) {
		jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

		token, err := jwtService.GenerateToken(userID, orgID, email, role)
		require.NoError(t, err)

		claims, err := jwtService.ValidateToken(token)
		require.NoError(t, err)
		assert.Equal(t, userID, claims.UserID)
	})

	t.Run("rejects expired token", func(t *testing.T) {
		// Create service with very short expiry
		jwtService := auth.NewJWTService("test-secret", 1*time.Millisecond)

		token, err := jwtService.GenerateToken(userID, orgID, email, role)
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(10 * time.Millisecond)

		_, err = jwtService.ValidateToken(token)
		assert.Equal(t, auth.ErrExpiredToken, err)
	})

	t.Run("rejects tampered token", func(t *testing.T) {
		jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

		token, err := jwtService.GenerateToken(userID, orgID, email, role)
		require.NoError(t, err)

		// Tamper with the token
		tamperedToken := token + "tampered"

		_, err = jwtService.ValidateToken(tamperedToken)
		assert.Equal(t, auth.ErrInvalidToken, err)
	})

	t.Run("rejects token signed with different secret", func(t *testing.T) {
		jwtService1 := auth.NewJWTService("secret-1", 24*time.Hour)
		jwtService2 := auth.NewJWTService("secret-2", 24*time.Hour)

		token, err := jwtService1.GenerateToken(userID, orgID, email, role)
		require.NoError(t, err)

		_, err = jwtService2.ValidateToken(token)
		assert.Equal(t, auth.ErrInvalidToken, err)
	})

	t.Run("rejects malformed token", func(t *testing.T) {
		jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

		_, err := jwtService.ValidateToken("not-a-valid-jwt")
		assert.Equal(t, auth.ErrInvalidToken, err)
	})

	t.Run("rejects empty token", func(t *testing.T) {
		jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

		_, err := jwtService.ValidateToken("")
		assert.Equal(t, auth.ErrInvalidToken, err)
	})
}

func TestJWTService_DifferentRoles(t *testing.T) {
	jwtService := auth.NewJWTService("test-secret", 24*time.Hour)

	userID := uuid.New()
	orgID := uuid.New()
	email := "test@example.com"

	roles := []string{"owner", "admin", "member"}

	for _, role := range roles {
		t.Run("handles "+role+" role", func(t *testing.T) {
			token, err := jwtService.GenerateToken(userID, orgID, email, role)
			require.NoError(t, err)

			claims, err := jwtService.ValidateToken(token)
			require.NoError(t, err)
			assert.Equal(t, role, claims.Role)
		})
	}
}
