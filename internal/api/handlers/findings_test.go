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

func setupFindingTestRouter(t *testing.T) (*chi.Mux, *testutil.TestSetup) {
	tc := testutil.NewTestContext(t)

	r := chi.NewRouter()
	r.Use(middleware.Auth(tc.JWTService))

	handler := handlers.NewFindingHandler(tc.DB)
	r.Route("/api/v1/findings", func(r chi.Router) {
		r.Get("/", handler.List)
		r.Get("/{id}", handler.Get)
		r.Put("/{id}/status", handler.UpdateStatus)
	})

	return r, tc
}

func TestFindingHandler_List(t *testing.T) {
	router, tc := setupFindingTestRouter(t)
	defer tc.Cleanup()

	// Create test asset and findings
	asset := testutil.CreateTestAsset(t, tc.DB, tc.Org.ID, models.AssetTypeDomain, "example.com")
	testutil.CreateTestFinding(t, tc.DB, tc.Org.ID, asset.ID, models.SeverityHigh)
	testutil.CreateTestFinding(t, tc.DB, tc.Org.ID, asset.ID, models.SeverityMedium)
	testutil.CreateTestFinding(t, tc.DB, tc.Org.ID, asset.ID, models.SeverityLow)

	t.Run("list all findings", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/findings", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.PaginatedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(3), resp.Total)
	})

	t.Run("filter by severity", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/findings?severity=high", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.PaginatedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(1), resp.Total)
	})

	t.Run("filter by status", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/findings?status=open", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.PaginatedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(3), resp.Total) // All are open by default
	})

	t.Run("filter by asset_id", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/findings?asset_id="+asset.ID.String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.PaginatedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(3), resp.Total)
	})

	t.Run("pagination", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/findings?page=1&per_page=2", nil, tc.Token)
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

func TestFindingHandler_Get(t *testing.T) {
	router, tc := setupFindingTestRouter(t)
	defer tc.Cleanup()

	asset := testutil.CreateTestAsset(t, tc.DB, tc.Org.ID, models.AssetTypeDomain, "example.com")
	finding := testutil.CreateTestFinding(t, tc.DB, tc.Org.ID, asset.ID, models.SeverityHigh)

	t.Run("get existing finding", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/findings/"+finding.ID.String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp handlers.FindingResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, finding.ID.String(), resp.ID)
		assert.Equal(t, "high", resp.Severity)
		assert.Equal(t, "open", resp.Status)
	})

	t.Run("get non-existent finding", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/findings/"+uuid.New().String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("invalid uuid", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/findings/invalid-uuid", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestFindingHandler_UpdateStatus(t *testing.T) {
	router, tc := setupFindingTestRouter(t)
	defer tc.Cleanup()

	asset := testutil.CreateTestAsset(t, tc.DB, tc.Org.ID, models.AssetTypeDomain, "example.com")

	t.Run("acknowledge finding", func(t *testing.T) {
		finding := testutil.CreateTestFinding(t, tc.DB, tc.Org.ID, asset.ID, models.SeverityHigh)

		req := testutil.AuthenticatedRequest(t, "PUT", "/api/v1/findings/"+finding.ID.String()+"/status",
			map[string]string{"status": "acknowledged"}, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp handlers.FindingResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "acknowledged", resp.Status)
	})

	t.Run("mark as fixed", func(t *testing.T) {
		finding := testutil.CreateTestFinding(t, tc.DB, tc.Org.ID, asset.ID, models.SeverityMedium)

		req := testutil.AuthenticatedRequest(t, "PUT", "/api/v1/findings/"+finding.ID.String()+"/status",
			map[string]string{"status": "fixed"}, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp handlers.FindingResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "fixed", resp.Status)
		assert.NotZero(t, resp.ResolvedAt)
	})

	t.Run("mark as false positive", func(t *testing.T) {
		finding := testutil.CreateTestFinding(t, tc.DB, tc.Org.ID, asset.ID, models.SeverityLow)

		req := testutil.AuthenticatedRequest(t, "PUT", "/api/v1/findings/"+finding.ID.String()+"/status",
			map[string]string{"status": "false_positive"}, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp handlers.FindingResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "false_positive", resp.Status)
	})

	t.Run("reopen finding", func(t *testing.T) {
		finding := testutil.CreateTestFinding(t, tc.DB, tc.Org.ID, asset.ID, models.SeverityHigh)
		// First mark as fixed
		tc.DB.Model(&finding).Update("status", models.FindingStatusFixed)

		req := testutil.AuthenticatedRequest(t, "PUT", "/api/v1/findings/"+finding.ID.String()+"/status",
			map[string]string{"status": "open"}, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp handlers.FindingResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "open", resp.Status)
	})

	t.Run("invalid status", func(t *testing.T) {
		finding := testutil.CreateTestFinding(t, tc.DB, tc.Org.ID, asset.ID, models.SeverityHigh)

		req := testutil.AuthenticatedRequest(t, "PUT", "/api/v1/findings/"+finding.ID.String()+"/status",
			map[string]string{"status": "invalid"}, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("non-existent finding", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "PUT", "/api/v1/findings/"+uuid.New().String()+"/status",
			map[string]string{"status": "acknowledged"}, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestFindingHandler_OrgIsolation(t *testing.T) {
	router, tc := setupFindingTestRouter(t)
	defer tc.Cleanup()

	// Create finding in a different org
	otherOrg := testutil.CreateTestOrg(t, tc.DB)
	otherAsset := testutil.CreateTestAsset(t, tc.DB, otherOrg.ID, models.AssetTypeDomain, "other.com")
	otherFinding := testutil.CreateTestFinding(t, tc.DB, otherOrg.ID, otherAsset.ID, models.SeverityHigh)

	t.Run("cannot access other org finding", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/findings/"+otherFinding.ID.String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("cannot update other org finding", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "PUT", "/api/v1/findings/"+otherFinding.ID.String()+"/status",
			map[string]string{"status": "acknowledged"}, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("list does not include other org findings", func(t *testing.T) {
		// Create our own finding
		myAsset := testutil.CreateTestAsset(t, tc.DB, tc.Org.ID, models.AssetTypeDomain, "mine.com")
		testutil.CreateTestFinding(t, tc.DB, tc.Org.ID, myAsset.ID, models.SeverityHigh)

		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/findings", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.PaginatedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(1), resp.Total) // Only our finding
	})
}
