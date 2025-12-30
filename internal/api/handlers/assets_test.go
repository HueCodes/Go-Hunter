package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/api/dto"
	"github.com/hugh/go-hunter/internal/api/handlers"
	"github.com/hugh/go-hunter/internal/api/middleware"
	"github.com/hugh/go-hunter/internal/database/models"
	"github.com/hugh/go-hunter/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupAssetTestRouter(t *testing.T) (*chi.Mux, *testutil.TestSetup) {
	tc := testutil.NewTestContext(t)

	r := chi.NewRouter()
	r.Use(middleware.Auth(tc.JWTService))

	handler := handlers.NewAssetHandler(tc.DB)
	r.Route("/api/v1/assets", func(r chi.Router) {
		r.Get("/", handler.List)
		r.Post("/", handler.Create)
		r.Get("/{id}", handler.Get)
		r.Delete("/{id}", handler.Delete)
	})

	return r, tc
}

func TestAssetHandler_Create(t *testing.T) {
	router, tc := setupAssetTestRouter(t)
	defer tc.Cleanup()

	tests := []struct {
		name       string
		body       map[string]interface{}
		wantStatus int
	}{
		{
			name: "create domain asset",
			body: map[string]interface{}{
				"type":  "domain",
				"value": "example.com",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "create ip asset",
			body: map[string]interface{}{
				"type":  "ip",
				"value": "192.168.1.1",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "create bucket asset with metadata",
			body: map[string]interface{}{
				"type":     "bucket",
				"value":    "my-test-bucket",
				"source":   "aws:discovery",
				"metadata": `{"region": "us-east-1"}`,
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "missing type",
			body: map[string]interface{}{
				"value": "example.com",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid type",
			body: map[string]interface{}{
				"type":  "invalid",
				"value": "example.com",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing value",
			body: map[string]interface{}{
				"type": "domain",
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := testutil.AuthenticatedRequest(t, "POST", "/api/v1/assets", tt.body, tc.Token)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusCreated {
				var resp handlers.AssetResponse
				err := json.Unmarshal(rr.Body.Bytes(), &resp)
				require.NoError(t, err)
				assert.NotEmpty(t, resp.ID)
				assert.Equal(t, tt.body["value"], resp.Value)
				assert.True(t, resp.IsActive)
			}
		})
	}
}

func TestAssetHandler_List(t *testing.T) {
	router, tc := setupAssetTestRouter(t)
	defer tc.Cleanup()

	// Create test assets
	testutil.CreateTestAsset(t, tc.DB, tc.Org.ID, models.AssetTypeDomain, "example1.com")
	testutil.CreateTestAsset(t, tc.DB, tc.Org.ID, models.AssetTypeDomain, "example2.com")
	testutil.CreateTestAsset(t, tc.DB, tc.Org.ID, models.AssetTypeIP, "192.168.1.1")

	t.Run("list all assets", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/assets", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.PaginatedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(3), resp.Total)
	})

	t.Run("filter by type", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/assets?type=domain", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.PaginatedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(2), resp.Total)
	})

	t.Run("pagination", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/assets?page=1&per_page=2", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.PaginatedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(3), resp.Total)
		assert.Equal(t, 2, resp.PerPage)
		assert.Equal(t, 2, resp.TotalPages)
	})
}

func TestAssetHandler_Get(t *testing.T) {
	router, tc := setupAssetTestRouter(t)
	defer tc.Cleanup()

	asset := testutil.CreateTestAsset(t, tc.DB, tc.Org.ID, models.AssetTypeDomain, "example.com")

	t.Run("get existing asset", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/assets/"+asset.ID.String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp handlers.AssetResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, asset.ID.String(), resp.ID)
		assert.Equal(t, "example.com", resp.Value)
	})

	t.Run("get non-existent asset", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/assets/"+uuid.New().String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("invalid uuid", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/assets/invalid-uuid", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestAssetHandler_Delete(t *testing.T) {
	router, tc := setupAssetTestRouter(t)
	defer tc.Cleanup()

	asset := testutil.CreateTestAsset(t, tc.DB, tc.Org.ID, models.AssetTypeDomain, "example.com")

	t.Run("delete existing asset", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "DELETE", "/api/v1/assets/"+asset.ID.String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		// Verify soft delete
		var updatedAsset models.Asset
		tc.DB.First(&updatedAsset, asset.ID)
		assert.False(t, updatedAsset.IsActive)
	})

	t.Run("delete non-existent asset", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "DELETE", "/api/v1/assets/"+uuid.New().String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestAssetHandler_OrgIsolation(t *testing.T) {
	router, tc := setupAssetTestRouter(t)
	defer tc.Cleanup()

	// Create asset in a different org
	otherOrg := testutil.CreateTestOrg(t, tc.DB)
	otherAsset := testutil.CreateTestAsset(t, tc.DB, otherOrg.ID, models.AssetTypeDomain, "other.com")

	t.Run("cannot access other org asset", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/assets/"+otherAsset.ID.String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("cannot delete other org asset", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "DELETE", "/api/v1/assets/"+otherAsset.ID.String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("list does not include other org assets", func(t *testing.T) {
		// Create our own asset
		testutil.CreateTestAsset(t, tc.DB, tc.Org.ID, models.AssetTypeDomain, "mine.com")

		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/assets", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.PaginatedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(1), resp.Total) // Only our asset
	})
}

func TestAssetHandler_Unauthorized(t *testing.T) {
	router, tc := setupAssetTestRouter(t)
	defer tc.Cleanup()

	t.Run("no token", func(t *testing.T) {
		req := testutil.UnauthenticatedRequest(t, "GET", "/api/v1/assets", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("invalid token", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/assets", nil, "invalid-token")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}
