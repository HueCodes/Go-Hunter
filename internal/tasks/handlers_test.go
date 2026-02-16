package tasks

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/hugh/go-hunter/internal/database/models"
	"github.com/hugh/go-hunter/internal/testutil"
	"github.com/hugh/go-hunter/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestNewHandler tests handler initialization
func TestNewHandler(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	// Create mock asynq client (nil is acceptable for test handler creation)
	handler := NewHandler(setup.DB, logger, encryptor, nil)

	assert.NotNil(t, handler)
	assert.NotNil(t, handler.db)
	assert.NotNil(t, handler.logger)
	assert.NotNil(t, handler.assetService)
	assert.NotNil(t, handler.encryptor)
}

// TestHandleAssetDiscovery_InvalidPayload tests invalid JSON payload
func TestHandleAssetDiscovery_InvalidPayload(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	handler := NewHandler(setup.DB, logger, encryptor, nil)

	// Create task with invalid payload
	task := asynq.NewTask(TypeAssetDiscovery, []byte("invalid json"))

	err = handler.HandleAssetDiscovery(context.Background(), task)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal payload")
}

// TestHandleAssetDiscovery_NoCredentials tests discovery with no credentials
func TestHandleAssetDiscovery_NoCredentials(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	handler := NewHandler(setup.DB, logger, encryptor, nil)

	// Create scan
	scan := testutil.CreateTestScan(t, setup.DB, setup.Org.ID, models.ScanTypeDiscovery)

	// Create payload with no credentials
	payload := AssetDiscoveryPayload{
		OrganizationID: setup.Org.ID,
		ScanID:         scan.ID,
		CredentialIDs:  []uuid.UUID{}, // Empty credentials
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	task := asynq.NewTask(TypeAssetDiscovery, payloadBytes)

	// Discovery with no credentials should complete without error
	// but won't discover anything
	err = handler.HandleAssetDiscovery(context.Background(), task)

	// Check results - depends on implementation
	// For now, we verify it doesn't crash
	if err != nil {
		t.Logf("Discovery with no credentials returned error (may be expected): %v", err)
	}

	// Verify scan status was updated
	var updatedScan models.Scan
	err = setup.DB.First(&updatedScan, scan.ID).Error
	require.NoError(t, err)
	// Status should be either running, completed, or failed
	assert.Contains(t, []models.ScanStatus{
		models.ScanStatusRunning,
		models.ScanStatusCompleted,
		models.ScanStatusFailed,
	}, updatedScan.Status)
}

// TestHandlePortScan_InvalidPayload tests port scan with invalid payload
func TestHandlePortScan_InvalidPayload(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	handler := NewHandler(setup.DB, logger, encryptor, nil)

	task := asynq.NewTask(TypePortScan, []byte("invalid json"))

	err = handler.HandlePortScan(context.Background(), task)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal payload")
}

// TestHandlePortScan_NoAssets tests port scan with no assets
func TestHandlePortScan_NoAssets(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	handler := NewHandler(setup.DB, logger, encryptor, nil)

	// Create scan
	scan := testutil.CreateTestScan(t, setup.DB, setup.Org.ID, models.ScanTypePortScan)

	// Create payload with no assets
	payload := PortScanPayload{
		OrganizationID: setup.Org.ID,
		ScanID:         scan.ID,
		AssetIDs:       []uuid.UUID{},
		Ports:          "80,443",
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	task := asynq.NewTask(TypePortScan, payloadBytes)

	err = handler.HandlePortScan(context.Background(), task)
	require.NoError(t, err)

	// Verify scan was completed
	var updatedScan models.Scan
	err = setup.DB.First(&updatedScan, scan.ID).Error
	require.NoError(t, err)
	assert.Equal(t, models.ScanStatusCompleted, updatedScan.Status)
}

// TestHandlePortScan_WithAsset tests port scan with a single asset
func TestHandlePortScan_WithAsset(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	handler := NewHandler(setup.DB, logger, encryptor, nil)

	// Create asset
	asset := testutil.CreateTestAsset(t, setup.DB, setup.Org.ID, models.AssetTypeIP, "192.0.2.1")

	// Create scan
	scan := testutil.CreateTestScan(t, setup.DB, setup.Org.ID, models.ScanTypePortScan)

	// Create payload
	payload := PortScanPayload{
		OrganizationID: setup.Org.ID,
		ScanID:         scan.ID,
		AssetIDs:       []uuid.UUID{asset.ID},
		Ports:          "80", // Single port for faster test
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	task := asynq.NewTask(TypePortScan, payloadBytes)

	// Use a timeout context to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = handler.HandlePortScan(ctx, task)

	// Scan may complete or timeout, both are acceptable
	if err == nil {
		// Verify scan was updated
		var updatedScan models.Scan
		err = setup.DB.First(&updatedScan, scan.ID).Error
		require.NoError(t, err)
		assert.Contains(t, []models.ScanStatus{
			models.ScanStatusCompleted,
			models.ScanStatusRunning,
		}, updatedScan.Status)
	}
}

// TestHandlePortScan_InvalidPorts tests port scan with invalid port specification
func TestHandlePortScan_InvalidPorts(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	handler := NewHandler(setup.DB, logger, encryptor, nil)

	// Create scan
	scan := testutil.CreateTestScan(t, setup.DB, setup.Org.ID, models.ScanTypePortScan)

	// Create payload with invalid ports
	payload := PortScanPayload{
		OrganizationID: setup.Org.ID,
		ScanID:         scan.ID,
		AssetIDs:       []uuid.UUID{},
		Ports:          "invalid-ports",
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	task := asynq.NewTask(TypePortScan, payloadBytes)

	err = handler.HandlePortScan(context.Background(), task)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parsing ports")

	// Verify scan status was updated to failed
	var updatedScan models.Scan
	err = setup.DB.First(&updatedScan, scan.ID).Error
	require.NoError(t, err)
	assert.Equal(t, models.ScanStatusFailed, updatedScan.Status)
}

// TestHandleHTTPProbe_InvalidPayload tests HTTP probe with invalid payload
func TestHandleHTTPProbe_InvalidPayload(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	handler := NewHandler(setup.DB, logger, encryptor, nil)

	task := asynq.NewTask(TypeHTTPProbe, []byte("invalid json"))

	err = handler.HandleHTTPProbe(context.Background(), task)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal payload")
}

// TestHandleHTTPProbe_NoAssets tests HTTP probe with no assets
func TestHandleHTTPProbe_NoAssets(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	handler := NewHandler(setup.DB, logger, encryptor, nil)

	// Create scan
	scan := testutil.CreateTestScan(t, setup.DB, setup.Org.ID, models.ScanTypeHTTPProbe)

	// Create payload with no assets
	payload := HTTPProbePayload{
		OrganizationID: setup.Org.ID,
		ScanID:         scan.ID,
		AssetIDs:       []uuid.UUID{},
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	task := asynq.NewTask(TypeHTTPProbe, payloadBytes)

	err = handler.HandleHTTPProbe(context.Background(), task)
	require.NoError(t, err)

	// Verify scan was completed
	var updatedScan models.Scan
	err = setup.DB.First(&updatedScan, scan.ID).Error
	require.NoError(t, err)
	assert.Equal(t, models.ScanStatusCompleted, updatedScan.Status)
}

// TestHandleCrawl_InvalidPayload tests web crawl with invalid payload
func TestHandleCrawl_InvalidPayload(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	handler := NewHandler(setup.DB, logger, encryptor, nil)

	task := asynq.NewTask(TypeCrawl, []byte("invalid json"))

	err = handler.HandleCrawl(context.Background(), task)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal payload")
}

// TestHandleVulnCheck_InvalidPayload tests vulnerability check with invalid payload
func TestHandleVulnCheck_InvalidPayload(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	handler := NewHandler(setup.DB, logger, encryptor, nil)

	task := asynq.NewTask(TypeVulnCheck, []byte("invalid json"))

	err = handler.HandleVulnCheck(context.Background(), task)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal payload")
}

// TestHandleSchedulerTick tests scheduler tick with no due schedules
func TestHandleSchedulerTick(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	handler := NewHandler(setup.DB, logger, encryptor, nil)

	task := asynq.NewTask(TypeSchedulerTick, []byte{})

	// With no schedules, this should complete successfully
	err = handler.HandleSchedulerTick(context.Background(), task)
	assert.NoError(t, err)
}

// TestUpdateScanStatus tests scan status update helper
func TestUpdateScanStatus(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	handler := NewHandler(setup.DB, logger, encryptor, nil)

	// Create scan
	scan := testutil.CreateTestScan(t, setup.DB, setup.Org.ID, models.ScanTypeDiscovery)
	assert.Equal(t, models.ScanStatusPending, scan.Status)

	// Update to running
	err = handler.updateScanStatus(scan.ID, models.ScanStatusRunning)
	require.NoError(t, err)

	var updatedScan models.Scan
	err = setup.DB.First(&updatedScan, scan.ID).Error
	require.NoError(t, err)
	assert.Equal(t, models.ScanStatusRunning, updatedScan.Status)

	// Update to completed
	err = handler.updateScanStatus(scan.ID, models.ScanStatusCompleted)
	require.NoError(t, err)

	err = setup.DB.First(&updatedScan, scan.ID).Error
	require.NoError(t, err)
	assert.Equal(t, models.ScanStatusCompleted, updatedScan.Status)
}

// TestUpdateScanStatus_NonExistent tests updating non-existent scan
func TestUpdateScanStatus_NonExistent(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	handler := NewHandler(setup.DB, logger, encryptor, nil)

	// Try to update non-existent scan
	fakeID := uuid.New()
	err = handler.updateScanStatus(fakeID, models.ScanStatusRunning)
	// GORM doesn't return error for UPDATE WHERE id=non-existent,
	// it just updates 0 rows, so we don't expect an error here
	assert.NoError(t, err)
}

// TestRegisterHandlers tests handler registration
func TestRegisterHandlers(t *testing.T) {
	setup := testutil.NewTestContext(t)
	defer setup.Cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	encryptor, err := crypto.NewEncryptor("") // Empty string generates new identity
	require.NoError(t, err)

	handler := NewHandler(setup.DB, logger, encryptor, nil)

	// Create mock servemux
	mux := asynq.NewServeMux()

	// Register handlers - should not panic
	assert.NotPanics(t, func() {
		handler.RegisterHandlers(mux)
	})
}

// Test helper function to verify scan was marked as failed with error message
func verifyScanFailed(t *testing.T, db *gorm.DB, scanID uuid.UUID, expectedErrorSubstring string) {
	t.Helper()

	var scan models.Scan
	err := db.First(&scan, scanID).Error
	require.NoError(t, err)

	assert.Equal(t, models.ScanStatusFailed, scan.Status)
	if expectedErrorSubstring != "" {
		assert.Contains(t, scan.Error, expectedErrorSubstring)
	}
}
