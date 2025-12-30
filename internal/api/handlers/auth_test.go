package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/hugh/go-hunter/internal/api/dto"
	"github.com/hugh/go-hunter/internal/api/handlers"
	"github.com/hugh/go-hunter/internal/auth"
	"github.com/hugh/go-hunter/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupAuthTestRouter(t *testing.T) (*chi.Mux, *testutil.TestSetup) {
	tc := testutil.NewTestContext(t)

	authService := auth.NewService(tc.DB, tc.JWTService)
	handler := handlers.NewAuthHandler(authService)

	r := chi.NewRouter()
	r.Post("/api/v1/auth/register", handler.Register)
	r.Post("/api/v1/auth/login", handler.Login)
	r.Post("/api/v1/auth/logout", handler.Logout)

	return r, tc
}

func TestAuthHandler_Register(t *testing.T) {
	router, tc := setupAuthTestRouter(t)
	defer tc.Cleanup()

	t.Run("successful registration", func(t *testing.T) {
		body := map[string]string{
			"email":    "newuser@example.com",
			"password": "securepassword123",
			"name":     "New User",
			"org_name": "New Org",
		}

		req := testutil.UnauthenticatedRequest(t, "POST", "/api/v1/auth/register", body)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusCreated, rr.Code)

		var resp dto.AuthResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Token)
		assert.Equal(t, "newuser@example.com", resp.User.Email)
		assert.Equal(t, "New User", resp.User.Name)
		assert.Equal(t, "owner", resp.User.Role)
	})

	t.Run("registration with default org name", func(t *testing.T) {
		body := map[string]string{
			"email":    "anotheruser@example.com",
			"password": "securepassword123",
			"name":     "Another User",
		}

		req := testutil.UnauthenticatedRequest(t, "POST", "/api/v1/auth/register", body)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusCreated, rr.Code)

		var resp dto.AuthResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Contains(t, resp.User.OrgName, "Another User")
	})

	t.Run("duplicate email", func(t *testing.T) {
		// First registration
		body := map[string]string{
			"email":    "duplicate@example.com",
			"password": "securepassword123",
			"name":     "First User",
		}

		req := testutil.UnauthenticatedRequest(t, "POST", "/api/v1/auth/register", body)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusCreated, rr.Code)

		// Second registration with same email
		req = testutil.UnauthenticatedRequest(t, "POST", "/api/v1/auth/register", body)
		rr = httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusConflict, rr.Code)
	})

	t.Run("missing email", func(t *testing.T) {
		body := map[string]string{
			"password": "securepassword123",
			"name":     "No Email User",
		}

		req := testutil.UnauthenticatedRequest(t, "POST", "/api/v1/auth/register", body)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("password too short", func(t *testing.T) {
		body := map[string]string{
			"email":    "shortpw@example.com",
			"password": "short",
			"name":     "Short PW User",
		}

		req := testutil.UnauthenticatedRequest(t, "POST", "/api/v1/auth/register", body)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("missing name", func(t *testing.T) {
		body := map[string]string{
			"email":    "noname@example.com",
			"password": "securepassword123",
		}

		req := testutil.UnauthenticatedRequest(t, "POST", "/api/v1/auth/register", body)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestAuthHandler_Login(t *testing.T) {
	router, tc := setupAuthTestRouter(t)
	defer tc.Cleanup()

	// Register a user first
	registerBody := map[string]string{
		"email":    "logintest@example.com",
		"password": "securepassword123",
		"name":     "Login Test User",
	}
	req := testutil.UnauthenticatedRequest(t, "POST", "/api/v1/auth/register", registerBody)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	t.Run("successful login", func(t *testing.T) {
		body := map[string]string{
			"email":    "logintest@example.com",
			"password": "securepassword123",
		}

		req := testutil.UnauthenticatedRequest(t, "POST", "/api/v1/auth/login", body)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.AuthResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Token)
		assert.Equal(t, "logintest@example.com", resp.User.Email)

		// Check cookie is set
		cookies := rr.Result().Cookies()
		var tokenCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "token" {
				tokenCookie = c
				break
			}
		}
		require.NotNil(t, tokenCookie)
		assert.Equal(t, resp.Token, tokenCookie.Value)
		assert.True(t, tokenCookie.HttpOnly)
	})

	t.Run("wrong password", func(t *testing.T) {
		body := map[string]string{
			"email":    "logintest@example.com",
			"password": "wrongpassword",
		}

		req := testutil.UnauthenticatedRequest(t, "POST", "/api/v1/auth/login", body)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("non-existent user", func(t *testing.T) {
		body := map[string]string{
			"email":    "nonexistent@example.com",
			"password": "anypassword",
		}

		req := testutil.UnauthenticatedRequest(t, "POST", "/api/v1/auth/login", body)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("missing email", func(t *testing.T) {
		body := map[string]string{
			"password": "securepassword123",
		}

		req := testutil.UnauthenticatedRequest(t, "POST", "/api/v1/auth/login", body)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("missing password", func(t *testing.T) {
		body := map[string]string{
			"email": "logintest@example.com",
		}

		req := testutil.UnauthenticatedRequest(t, "POST", "/api/v1/auth/login", body)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestAuthHandler_Logout(t *testing.T) {
	router, tc := setupAuthTestRouter(t)
	defer tc.Cleanup()

	t.Run("successful logout", func(t *testing.T) {
		req := testutil.UnauthenticatedRequest(t, "POST", "/api/v1/auth/logout", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		// Check cookie is cleared
		cookies := rr.Result().Cookies()
		var tokenCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "token" {
				tokenCookie = c
				break
			}
		}
		require.NotNil(t, tokenCookie)
		assert.Empty(t, tokenCookie.Value)
		assert.Equal(t, -1, tokenCookie.MaxAge) // Expired
	})
}
