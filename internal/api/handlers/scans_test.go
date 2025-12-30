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

func setupScanTestRouter(t *testing.T) (*chi.Mux, *testutil.TestSetup) {
	tc := testutil.NewTestContext(t)

	r := chi.NewRouter()
	r.Use(middleware.Auth(tc.JWTService))

	// Pass nil for asynq client in tests (tasks won't be enqueued)
	handler := handlers.NewScanHandler(tc.DB, nil)
	r.Route("/api/v1/scans", func(r chi.Router) {
		r.Get("/", handler.List)
		r.Post("/", handler.Create)
		r.Get("/{id}", handler.Get)
		r.Post("/{id}/cancel", handler.Cancel)
	})

	return r, tc
}

func TestScanHandler_Create(t *testing.T) {
	router, tc := setupScanTestRouter(t)
	defer tc.Cleanup()

	// Create a test credential for discovery scans
	cred := createTestCredential(t, tc)

	tests := []struct {
		name       string
		body       map[string]interface{}
		wantStatus int
	}{
		{
			name: "create discovery scan",
			body: map[string]interface{}{
				"type":           "discovery",
				"credential_ids": []string{cred.ID.String()},
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "create vuln_check scan",
			body: map[string]interface{}{
				"type": "vuln_check",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "create port_scan",
			body: map[string]interface{}{
				"type": "port_scan",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "invalid scan type",
			body: map[string]interface{}{
				"type": "invalid",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "discovery without credentials",
			body: map[string]interface{}{
				"type": "discovery",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid credential id",
			body: map[string]interface{}{
				"type":           "discovery",
				"credential_ids": []string{"invalid-uuid"},
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "non-existent credential",
			body: map[string]interface{}{
				"type":           "discovery",
				"credential_ids": []string{uuid.New().String()},
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := testutil.AuthenticatedRequest(t, "POST", "/api/v1/scans", tt.body, tc.Token)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.wantStatus, rr.Code, "Body: %s", rr.Body.String())

			if tt.wantStatus == http.StatusCreated {
				var resp handlers.ScanResponse
				err := json.Unmarshal(rr.Body.Bytes(), &resp)
				require.NoError(t, err)
				assert.NotEmpty(t, resp.ID)
				assert.Equal(t, "pending", resp.Status)
			}
		})
	}
}

func TestScanHandler_List(t *testing.T) {
	router, tc := setupScanTestRouter(t)
	defer tc.Cleanup()

	// Create test scans
	testutil.CreateTestScan(t, tc.DB, tc.Org.ID, models.ScanTypeDiscovery)
	testutil.CreateTestScan(t, tc.DB, tc.Org.ID, models.ScanTypePortScan)
	scan3 := testutil.CreateTestScan(t, tc.DB, tc.Org.ID, models.ScanTypeVulnCheck)
	tc.DB.Model(&scan3).Update("status", models.ScanStatusCompleted)

	t.Run("list all scans", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/scans", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.PaginatedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(3), resp.Total)
	})

	t.Run("filter by status", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/scans?status=pending", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.PaginatedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(2), resp.Total)
	})

	t.Run("filter by type", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/scans?type=discovery", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.PaginatedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(1), resp.Total)
	})

	t.Run("pagination", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/scans?page=1&per_page=2", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.PaginatedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(3), resp.Total)
		assert.Equal(t, 2, resp.PerPage)
	})
}

func TestScanHandler_Get(t *testing.T) {
	router, tc := setupScanTestRouter(t)
	defer tc.Cleanup()

	scan := testutil.CreateTestScan(t, tc.DB, tc.Org.ID, models.ScanTypeDiscovery)

	t.Run("get existing scan", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/scans/"+scan.ID.String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp handlers.ScanResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, scan.ID.String(), resp.ID)
		assert.Equal(t, "discovery", resp.Type)
		assert.Equal(t, "pending", resp.Status)
	})

	t.Run("get non-existent scan", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/scans/"+uuid.New().String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("invalid uuid", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/scans/invalid-uuid", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestScanHandler_Cancel(t *testing.T) {
	router, tc := setupScanTestRouter(t)
	defer tc.Cleanup()

	t.Run("cancel pending scan", func(t *testing.T) {
		scan := testutil.CreateTestScan(t, tc.DB, tc.Org.ID, models.ScanTypeDiscovery)

		req := testutil.AuthenticatedRequest(t, "POST", "/api/v1/scans/"+scan.ID.String()+"/cancel", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp handlers.ScanResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "cancelled", resp.Status)
		assert.NotZero(t, resp.CompletedAt)
	})

	t.Run("cancel running scan", func(t *testing.T) {
		scan := testutil.CreateTestScan(t, tc.DB, tc.Org.ID, models.ScanTypePortScan)
		tc.DB.Model(&scan).Update("status", models.ScanStatusRunning)

		req := testutil.AuthenticatedRequest(t, "POST", "/api/v1/scans/"+scan.ID.String()+"/cancel", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp handlers.ScanResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "cancelled", resp.Status)
	})

	t.Run("cannot cancel completed scan", func(t *testing.T) {
		scan := testutil.CreateTestScan(t, tc.DB, tc.Org.ID, models.ScanTypeVulnCheck)
		tc.DB.Model(&scan).Update("status", models.ScanStatusCompleted)

		req := testutil.AuthenticatedRequest(t, "POST", "/api/v1/scans/"+scan.ID.String()+"/cancel", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("cannot cancel failed scan", func(t *testing.T) {
		scan := testutil.CreateTestScan(t, tc.DB, tc.Org.ID, models.ScanTypeDiscovery)
		tc.DB.Model(&scan).Update("status", models.ScanStatusFailed)

		req := testutil.AuthenticatedRequest(t, "POST", "/api/v1/scans/"+scan.ID.String()+"/cancel", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("non-existent scan", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "POST", "/api/v1/scans/"+uuid.New().String()+"/cancel", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestScanHandler_OrgIsolation(t *testing.T) {
	router, tc := setupScanTestRouter(t)
	defer tc.Cleanup()

	// Create scan in a different org
	otherOrg := testutil.CreateTestOrg(t, tc.DB)
	otherScan := testutil.CreateTestScan(t, tc.DB, otherOrg.ID, models.ScanTypeDiscovery)

	t.Run("cannot access other org scan", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/scans/"+otherScan.ID.String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("cannot cancel other org scan", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "POST", "/api/v1/scans/"+otherScan.ID.String()+"/cancel", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("list does not include other org scans", func(t *testing.T) {
		// Create our own scan
		testutil.CreateTestScan(t, tc.DB, tc.Org.ID, models.ScanTypePortScan)

		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/scans", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.PaginatedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(1), resp.Total) // Only our scan
	})
}

// Helper to create a test credential
func createTestCredential(t *testing.T, tc *testutil.TestSetup) *models.CloudCredential {
	t.Helper()

	cred := &models.CloudCredential{
		Base: models.Base{
			ID: uuid.New(),
		},
		OrganizationID: tc.Org.ID,
		Name:           "Test AWS",
		Provider:       models.ProviderAWS,
		EncryptedData:  []byte("encrypted"),
		IsActive:       true,
	}

	if err := tc.DB.Create(cred).Error; err != nil {
		t.Fatalf("failed to create test credential: %v", err)
	}

	return cred
}
