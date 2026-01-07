package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/auth"
	"github.com/hugh/go-hunter/internal/database/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestDB creates an in-memory SQLite database for testing
func SetupTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}

	// Run migrations
	err = db.AutoMigrate(
		&models.Organization{},
		&models.User{},
		&models.CloudCredential{},
		&models.Asset{},
		&models.Scan{},
		&models.Finding{},
		&models.ScheduledScan{},
	)
	if err != nil {
		t.Fatalf("failed to migrate test database: %v", err)
	}

	return db
}

// CleanupTestDB closes the test database connection
func CleanupTestDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	if err != nil {
		t.Logf("warning: failed to get sql.DB: %v", err)
		return
	}
	sqlDB.Close()
}

// TestOrg creates a test organization
func CreateTestOrg(t *testing.T, db *gorm.DB) *models.Organization {
	t.Helper()

	org := &models.Organization{
		Base: models.Base{
			ID: uuid.New(),
		},
		Name: "Test Organization",
		Slug: "test-org-" + uuid.New().String()[:8],
		Plan: "free",
	}

	if err := db.Create(org).Error; err != nil {
		t.Fatalf("failed to create test organization: %v", err)
	}

	return org
}

// TestUser creates a test user with the given organization
func CreateTestUser(t *testing.T, db *gorm.DB, org *models.Organization) *models.User {
	t.Helper()

	hash, err := auth.HashPassword("testpassword123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	user := &models.User{
		Base: models.Base{
			ID: uuid.New(),
		},
		Email:          "test-" + uuid.New().String()[:8] + "@example.com",
		PasswordHash:   hash,
		Name:           "Test User",
		OrganizationID: org.ID,
		Role:           "owner",
		IsActive:       true,
	}

	if err := db.Create(user).Error; err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	user.Organization = org
	return user
}

// TestJWTService creates a JWT service for testing
func CreateTestJWTService() *auth.JWTService {
	return auth.NewJWTService("test-secret-key-for-testing", 24*time.Hour)
}

// GenerateTestToken generates a valid JWT token for the given user
func GenerateTestToken(t *testing.T, jwtService *auth.JWTService, user *models.User) string {
	t.Helper()

	token, err := jwtService.GenerateToken(user.ID, user.OrganizationID, user.Email, user.Role)
	if err != nil {
		t.Fatalf("failed to generate test token: %v", err)
	}

	return token
}

// AuthenticatedRequest creates an HTTP request with authentication
func AuthenticatedRequest(t *testing.T, method, path string, body interface{}, token string) *http.Request {
	t.Helper()

	var reqBody *bytes.Buffer
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	return req
}

// UnauthenticatedRequest creates an HTTP request without authentication
func UnauthenticatedRequest(t *testing.T, method, path string, body interface{}) *http.Request {
	t.Helper()
	return AuthenticatedRequest(t, method, path, body, "")
}

// AssertStatus checks if the response has the expected status code
func AssertStatus(t *testing.T, rr *httptest.ResponseRecorder, expected int) {
	t.Helper()
	if rr.Code != expected {
		t.Errorf("expected status %d, got %d. Body: %s", expected, rr.Code, rr.Body.String())
	}
}

// AssertJSON compares two JSON structures
func AssertJSON(t *testing.T, expected, actual interface{}) {
	t.Helper()

	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("failed to marshal expected: %v", err)
	}

	actualJSON, err := json.Marshal(actual)
	if err != nil {
		t.Fatalf("failed to marshal actual: %v", err)
	}

	if string(expectedJSON) != string(actualJSON) {
		t.Errorf("JSON mismatch:\nexpected: %s\nactual: %s", expectedJSON, actualJSON)
	}
}

// ParseJSONResponse parses the response body into the given struct
func ParseJSONResponse(t *testing.T, rr *httptest.ResponseRecorder, v interface{}) {
	t.Helper()

	if err := json.Unmarshal(rr.Body.Bytes(), v); err != nil {
		t.Fatalf("failed to parse response body: %v. Body: %s", err, rr.Body.String())
	}
}

// CreateTestAsset creates a test asset
func CreateTestAsset(t *testing.T, db *gorm.DB, orgID uuid.UUID, assetType models.AssetType, value string) *models.Asset {
	t.Helper()

	now := time.Now().Unix()
	asset := &models.Asset{
		Base: models.Base{
			ID: uuid.New(),
		},
		OrganizationID: orgID,
		Type:           assetType,
		Value:          value,
		Source:         "manual",
		DiscoveredAt:   now,
		LastSeenAt:     now,
		IsActive:       true,
		Metadata:       "{}",
	}

	if err := db.Create(asset).Error; err != nil {
		t.Fatalf("failed to create test asset: %v", err)
	}

	return asset
}

// CreateTestScan creates a test scan
func CreateTestScan(t *testing.T, db *gorm.DB, orgID uuid.UUID, scanType models.ScanType) *models.Scan {
	t.Helper()

	scan := &models.Scan{
		Base: models.Base{
			ID: uuid.New(),
		},
		OrganizationID: orgID,
		Type:           scanType,
		Status:         models.ScanStatusPending,
		Config:         "{}",
	}

	if err := db.Create(scan).Error; err != nil {
		t.Fatalf("failed to create test scan: %v", err)
	}

	return scan
}

// CreateTestFinding creates a test finding
func CreateTestFinding(t *testing.T, db *gorm.DB, orgID, assetID uuid.UUID, severity models.Severity) *models.Finding {
	t.Helper()

	now := time.Now().Unix()
	finding := &models.Finding{
		Base: models.Base{
			ID: uuid.New(),
		},
		OrganizationID: orgID,
		AssetID:        assetID,
		Title:          "Test Finding",
		Description:    "Test finding description",
		Severity:       severity,
		Status:         models.FindingStatusOpen,
		Type:           "test_finding",
		Category:       "test",
		FirstSeenAt:    now,
		LastSeenAt:     now,
		Hash:           uuid.New().String(), // Unique hash
		RawData:        "{}",
		References:     "[]",
	}

	if err := db.Create(finding).Error; err != nil {
		t.Fatalf("failed to create test finding: %v", err)
	}

	return finding
}

// TestContext creates a context with a timeout for tests
func TestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// CreateTestSchedule creates a test scheduled scan
func CreateTestSchedule(t *testing.T, db *gorm.DB, orgID uuid.UUID, name, cronExpr string, scanType models.ScanType) *models.ScheduledScan {
	t.Helper()

	now := time.Now()
	schedule := &models.ScheduledScan{
		Base: models.Base{
			ID: uuid.New(),
		},
		OrganizationID: orgID,
		Name:           name,
		CronExpr:       cronExpr,
		ScanType:       scanType,
		IsEnabled:      true,
		NextRunAt:      now.Add(time.Hour).Unix(),
		Config:         "{}",
	}

	if err := db.Create(schedule).Error; err != nil {
		t.Fatalf("failed to create test schedule: %v", err)
	}

	return schedule
}

// TestSetup holds all the common test dependencies
type TestSetup struct {
	DB         *gorm.DB
	JWTService *auth.JWTService
	Org        *models.Organization
	User       *models.User
	Token      string
}

// NewTestContext creates a complete test setup with DB, org, user, and token
func NewTestContext(t *testing.T) *TestSetup {
	t.Helper()

	db := SetupTestDB(t)
	jwtService := CreateTestJWTService()
	org := CreateTestOrg(t, db)
	user := CreateTestUser(t, db, org)
	token := GenerateTestToken(t, jwtService, user)

	return &TestSetup{
		DB:         db,
		JWTService: jwtService,
		Org:        org,
		User:       user,
		Token:      token,
	}
}

// Cleanup closes the test database
func (ts *TestSetup) Cleanup() {
	if ts.DB != nil {
		sqlDB, err := ts.DB.DB()
		if err == nil {
			sqlDB.Close()
		}
	}
}
