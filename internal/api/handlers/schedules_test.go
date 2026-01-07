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

func setupScheduleTestRouter(t *testing.T) (*chi.Mux, *testutil.TestSetup) {
	tc := testutil.NewTestContext(t)

	r := chi.NewRouter()
	r.Use(middleware.Auth(tc.JWTService))

	// Pass nil for asynq client in tests (tasks won't be enqueued)
	handler := handlers.NewScheduleHandler(tc.DB, nil)
	r.Route("/api/v1/schedules", func(r chi.Router) {
		r.Get("/", handler.List)
		r.Post("/", handler.Create)
		r.Get("/{id}", handler.Get)
		r.Put("/{id}", handler.Update)
		r.Delete("/{id}", handler.Delete)
		r.Post("/{id}/trigger", handler.Trigger)
	})

	return r, tc
}

func TestScheduleHandler_Create(t *testing.T) {
	router, tc := setupScheduleTestRouter(t)
	defer tc.Cleanup()

	tests := []struct {
		name       string
		body       map[string]interface{}
		wantStatus int
	}{
		{
			name: "create discovery schedule",
			body: map[string]interface{}{
				"name":      "Daily Discovery",
				"cron_expr": "0 2 * * *",
				"scan_type": "discovery",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "create port_scan schedule",
			body: map[string]interface{}{
				"name":      "Weekly Port Scan",
				"cron_expr": "0 3 * * 0",
				"scan_type": "port_scan",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "create vuln_check schedule",
			body: map[string]interface{}{
				"name":      "Monthly Vuln Check",
				"cron_expr": "0 0 1 * *",
				"scan_type": "vuln_check",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "missing name",
			body: map[string]interface{}{
				"cron_expr": "0 2 * * *",
				"scan_type": "discovery",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing cron expression",
			body: map[string]interface{}{
				"name":      "Test Schedule",
				"scan_type": "discovery",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid cron expression",
			body: map[string]interface{}{
				"name":      "Invalid Schedule",
				"cron_expr": "invalid",
				"scan_type": "discovery",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing scan type",
			body: map[string]interface{}{
				"name":      "Test Schedule",
				"cron_expr": "0 2 * * *",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid scan type",
			body: map[string]interface{}{
				"name":      "Test Schedule",
				"cron_expr": "0 2 * * *",
				"scan_type": "invalid_type",
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := testutil.AuthenticatedRequest(t, "POST", "/api/v1/schedules", tt.body, tc.Token)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.wantStatus, rr.Code, "Body: %s", rr.Body.String())

			if tt.wantStatus == http.StatusCreated {
				var resp handlers.ScheduleResponse
				err := json.Unmarshal(rr.Body.Bytes(), &resp)
				require.NoError(t, err)
				assert.NotEmpty(t, resp.ID)
				assert.Equal(t, tt.body["name"], resp.Name)
				assert.Equal(t, tt.body["cron_expr"], resp.CronExpr)
				assert.Equal(t, tt.body["scan_type"], resp.ScanType)
				assert.True(t, resp.IsEnabled)
				assert.NotZero(t, resp.NextRunAt)
			}
		})
	}
}

func TestScheduleHandler_List(t *testing.T) {
	router, tc := setupScheduleTestRouter(t)
	defer tc.Cleanup()

	// Create test schedules
	testutil.CreateTestSchedule(t, tc.DB, tc.Org.ID, "Schedule 1", "0 1 * * *", models.ScanTypeDiscovery)
	testutil.CreateTestSchedule(t, tc.DB, tc.Org.ID, "Schedule 2", "0 2 * * *", models.ScanTypePortScan)
	sched3 := testutil.CreateTestSchedule(t, tc.DB, tc.Org.ID, "Schedule 3", "0 3 * * *", models.ScanTypeVulnCheck)
	tc.DB.Model(&sched3).Update("is_enabled", false)

	t.Run("list all schedules", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/schedules", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp []handlers.ScheduleResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Len(t, resp, 3)
	})
}

func TestScheduleHandler_Get(t *testing.T) {
	router, tc := setupScheduleTestRouter(t)
	defer tc.Cleanup()

	schedule := testutil.CreateTestSchedule(t, tc.DB, tc.Org.ID, "Test Schedule", "0 2 * * *", models.ScanTypeDiscovery)

	t.Run("get existing schedule", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/schedules/"+schedule.ID.String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp handlers.ScheduleResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, schedule.ID.String(), resp.ID)
		assert.Equal(t, "Test Schedule", resp.Name)
		assert.Equal(t, "0 2 * * *", resp.CronExpr)
		assert.Equal(t, "discovery", resp.ScanType)
	})

	t.Run("get non-existent schedule", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/schedules/"+uuid.New().String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("invalid uuid", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/schedules/invalid-uuid", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestScheduleHandler_Update(t *testing.T) {
	router, tc := setupScheduleTestRouter(t)
	defer tc.Cleanup()

	schedule := testutil.CreateTestSchedule(t, tc.DB, tc.Org.ID, "Original Name", "0 1 * * *", models.ScanTypeDiscovery)

	t.Run("update name", func(t *testing.T) {
		body := map[string]interface{}{
			"name": "Updated Name",
		}
		req := testutil.AuthenticatedRequest(t, "PUT", "/api/v1/schedules/"+schedule.ID.String(), body, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp handlers.ScheduleResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "Updated Name", resp.Name)
	})

	t.Run("update cron expression", func(t *testing.T) {
		body := map[string]interface{}{
			"cron_expr": "0 5 * * *",
		}
		req := testutil.AuthenticatedRequest(t, "PUT", "/api/v1/schedules/"+schedule.ID.String(), body, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp handlers.ScheduleResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "0 5 * * *", resp.CronExpr)
	})

	t.Run("disable schedule", func(t *testing.T) {
		body := map[string]interface{}{
			"is_enabled": false,
		}
		req := testutil.AuthenticatedRequest(t, "PUT", "/api/v1/schedules/"+schedule.ID.String(), body, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp handlers.ScheduleResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.False(t, resp.IsEnabled)
	})

	t.Run("invalid cron expression", func(t *testing.T) {
		body := map[string]interface{}{
			"cron_expr": "invalid",
		}
		req := testutil.AuthenticatedRequest(t, "PUT", "/api/v1/schedules/"+schedule.ID.String(), body, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("non-existent schedule", func(t *testing.T) {
		body := map[string]interface{}{
			"name": "New Name",
		}
		req := testutil.AuthenticatedRequest(t, "PUT", "/api/v1/schedules/"+uuid.New().String(), body, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestScheduleHandler_Delete(t *testing.T) {
	router, tc := setupScheduleTestRouter(t)
	defer tc.Cleanup()

	t.Run("delete existing schedule", func(t *testing.T) {
		schedule := testutil.CreateTestSchedule(t, tc.DB, tc.Org.ID, "To Delete", "0 2 * * *", models.ScanTypeDiscovery)

		req := testutil.AuthenticatedRequest(t, "DELETE", "/api/v1/schedules/"+schedule.ID.String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp dto.SuccessResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "Schedule deleted", resp.Message)

		// Verify deletion
		req = testutil.AuthenticatedRequest(t, "GET", "/api/v1/schedules/"+schedule.ID.String(), nil, tc.Token)
		rr = httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("delete non-existent schedule", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "DELETE", "/api/v1/schedules/"+uuid.New().String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestScheduleHandler_Trigger(t *testing.T) {
	router, tc := setupScheduleTestRouter(t)
	defer tc.Cleanup()

	t.Run("trigger schedule creates scan", func(t *testing.T) {
		schedule := testutil.CreateTestSchedule(t, tc.DB, tc.Org.ID, "Test Trigger", "0 2 * * *", models.ScanTypeDiscovery)

		req := testutil.AuthenticatedRequest(t, "POST", "/api/v1/schedules/"+schedule.ID.String()+"/trigger", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "Scan triggered", resp["message"])
		assert.NotEmpty(t, resp["scan_id"])

		// Verify last_run_at was updated
		var updatedSchedule models.ScheduledScan
		err = tc.DB.First(&updatedSchedule, schedule.ID).Error
		require.NoError(t, err)
		assert.NotNil(t, updatedSchedule.LastRunAt)
		assert.NotNil(t, updatedSchedule.LastScanID)
	})

	t.Run("trigger non-existent schedule", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "POST", "/api/v1/schedules/"+uuid.New().String()+"/trigger", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestScheduleHandler_OrgIsolation(t *testing.T) {
	router, tc := setupScheduleTestRouter(t)
	defer tc.Cleanup()

	// Create schedule in a different org
	otherOrg := testutil.CreateTestOrg(t, tc.DB)
	otherSchedule := testutil.CreateTestSchedule(t, tc.DB, otherOrg.ID, "Other Org Schedule", "0 2 * * *", models.ScanTypeDiscovery)

	t.Run("cannot access other org schedule", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/schedules/"+otherSchedule.ID.String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("cannot update other org schedule", func(t *testing.T) {
		body := map[string]interface{}{
			"name": "Hacked Name",
		}
		req := testutil.AuthenticatedRequest(t, "PUT", "/api/v1/schedules/"+otherSchedule.ID.String(), body, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("cannot delete other org schedule", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "DELETE", "/api/v1/schedules/"+otherSchedule.ID.String(), nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("cannot trigger other org schedule", func(t *testing.T) {
		req := testutil.AuthenticatedRequest(t, "POST", "/api/v1/schedules/"+otherSchedule.ID.String()+"/trigger", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("list does not include other org schedules", func(t *testing.T) {
		// Create our own schedule
		testutil.CreateTestSchedule(t, tc.DB, tc.Org.ID, "Our Schedule", "0 3 * * *", models.ScanTypePortScan)

		req := testutil.AuthenticatedRequest(t, "GET", "/api/v1/schedules", nil, tc.Token)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp []handlers.ScheduleResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Len(t, resp, 1) // Only our schedule
		assert.Equal(t, "Our Schedule", resp[0].Name)
	})
}
