package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hugh/go-hunter/internal/api/handlers"
	"github.com/hugh/go-hunter/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthHandler_Health(t *testing.T) {
	t.Run("returns healthy when DB is up and no Redis configured", func(t *testing.T) {
		db := testutil.SetupTestDB(t)
		defer testutil.CleanupTestDB(t, db)

		handler := handlers.NewHealthHandler(db, nil)

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rr := httptest.NewRecorder()

		handler.Health(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

		var resp handlers.HealthResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, "healthy", resp.Status)
		assert.Equal(t, "healthy", resp.Services["database"])
		_, hasRedis := resp.Services["redis"]
		assert.False(t, hasRedis, "redis should not appear in services when client is nil")
	})

	t.Run("returns unhealthy when DB is closed", func(t *testing.T) {
		db := testutil.SetupTestDB(t)
		// Close the DB to simulate it being down
		sqlDB, err := db.DB()
		require.NoError(t, err)
		sqlDB.Close()

		handler := handlers.NewHealthHandler(db, nil)

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rr := httptest.NewRecorder()

		handler.Health(rr, req)

		assert.Equal(t, http.StatusServiceUnavailable, rr.Code)

		var resp handlers.HealthResponse
		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, "unhealthy", resp.Status)
		assert.Equal(t, "unhealthy", resp.Services["database"])
	})
}

func TestHealthHandler_Ready(t *testing.T) {
	t.Run("returns 200 when DB is up and no Redis configured", func(t *testing.T) {
		db := testutil.SetupTestDB(t)
		defer testutil.CleanupTestDB(t, db)

		handler := handlers.NewHealthHandler(db, nil)

		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rr := httptest.NewRecorder()

		handler.Ready(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "ok", rr.Body.String())
	})

	t.Run("returns 503 when DB is closed", func(t *testing.T) {
		db := testutil.SetupTestDB(t)
		// Close the DB to simulate it being down
		sqlDB, err := db.DB()
		require.NoError(t, err)
		sqlDB.Close()

		handler := handlers.NewHealthHandler(db, nil)

		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rr := httptest.NewRecorder()

		handler.Ready(rr, req)

		assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
		assert.Contains(t, rr.Body.String(), "database not ready")
	})
}
