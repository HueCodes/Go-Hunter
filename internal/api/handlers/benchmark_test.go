package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/api/dto"
	"github.com/hugh/go-hunter/internal/database/models"
)

// BenchmarkJSONSerialization benchmarks JSON encoding of common response types
func BenchmarkJSONSerialization(b *testing.B) {
	b.Run("ErrorResponse", func(b *testing.B) {
		resp := dto.ErrorResponse{
			Error: "Something went wrong",
			Details: map[string]string{
				"field1": "error1",
				"field2": "error2",
			},
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(resp)
		}
	})

	b.Run("SuccessResponse", func(b *testing.B) {
		resp := dto.SuccessResponse{Message: "Operation completed successfully"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(resp)
		}
	})

	b.Run("SingleAssetResponse", func(b *testing.B) {
		parentID := uuid.New().String()
		credID := uuid.New().String()
		resp := AssetResponse{
			ID:           uuid.New().String(),
			Type:         "domain",
			Value:        "example.com",
			Source:       "manual",
			Metadata:     `{"region":"us-east-1","tags":["production","web"]}`,
			ParentID:     &parentID,
			CredentialID: &credID,
			IsActive:     true,
			DiscoveredAt: time.Now().Unix(),
			LastSeenAt:   time.Now().Unix(),
			CreatedAt:    time.Now().Format(time.RFC3339),
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(resp)
		}
	})

	b.Run("SingleFindingResponse", func(b *testing.B) {
		scanID := uuid.New().String()
		resp := FindingResponse{
			ID:          uuid.New().String(),
			AssetID:     uuid.New().String(),
			ScanID:      &scanID,
			Title:       "Open Port 22/tcp (ssh)",
			Description: "Port 22/tcp is open on 192.168.1.1, identified as ssh service.",
			Severity:    "low",
			Status:      "open",
			Type:        "open_port",
			Category:    "network",
			Evidence:    `{"host":"192.168.1.1","port":22,"protocol":"tcp","service":"ssh"}`,
			Port:        22,
			Protocol:    "tcp",
			Service:     "ssh",
			Banner:      "SSH-2.0-OpenSSH_8.0",
			Remediation: "Ensure SSH is using key-based authentication.",
			References:  `["https://example.com/security"]`,
			FirstSeenAt: time.Now().Unix(),
			LastSeenAt:  time.Now().Unix(),
			CreatedAt:   time.Now().Format(time.RFC3339),
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(resp)
		}
	})

	b.Run("PaginatedAssetsResponse", func(b *testing.B) {
		assets := make([]AssetResponse, 20)
		for i := 0; i < 20; i++ {
			assets[i] = AssetResponse{
				ID:           uuid.New().String(),
				Type:         "domain",
				Value:        "example" + string(rune('0'+i)) + ".com",
				Source:       "manual",
				IsActive:     true,
				DiscoveredAt: time.Now().Unix(),
				LastSeenAt:   time.Now().Unix(),
				CreatedAt:    time.Now().Format(time.RFC3339),
			}
		}
		resp := dto.PaginatedResponse{
			Data:       assets,
			Total:      100,
			Page:       1,
			PerPage:    20,
			TotalPages: 5,
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(resp)
		}
	})

	b.Run("PaginatedFindingsResponse", func(b *testing.B) {
		findings := make([]FindingResponse, 20)
		for i := 0; i < 20; i++ {
			findings[i] = FindingResponse{
				ID:          uuid.New().String(),
				AssetID:     uuid.New().String(),
				Title:       "Open Port " + string(rune('0'+i)) + "/tcp",
				Severity:    "medium",
				Status:      "open",
				Type:        "open_port",
				Category:    "network",
				Port:        22 + i,
				Protocol:    "tcp",
				FirstSeenAt: time.Now().Unix(),
				LastSeenAt:  time.Now().Unix(),
				CreatedAt:   time.Now().Format(time.RFC3339),
			}
		}
		resp := dto.PaginatedResponse{
			Data:       findings,
			Total:      500,
			Page:       1,
			PerPage:    20,
			TotalPages: 25,
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(resp)
		}
	})

	b.Run("AuthResponse", func(b *testing.B) {
		resp := dto.AuthResponse{
			Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzIn0.abc123",
			User: dto.UserDTO{
				ID:             uuid.New().String(),
				Email:          "user@example.com",
				Name:           "Test User",
				Role:           "admin",
				OrganizationID: uuid.New().String(),
				OrgName:        "Test Organization",
			},
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(resp)
		}
	})
}

// BenchmarkRequestParsing benchmarks JSON decoding of common request types
func BenchmarkRequestParsing(b *testing.B) {
	b.Run("LoginRequest", func(b *testing.B) {
		jsonData := []byte(`{"email":"user@example.com","password":"securepassword123"}`)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var req dto.LoginRequest
			_ = json.Unmarshal(jsonData, &req)
		}
	})

	b.Run("RegisterRequest", func(b *testing.B) {
		jsonData := []byte(`{"email":"newuser@example.com","password":"securepassword123","name":"New User","org_name":"My Organization"}`)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var req dto.RegisterRequest
			_ = json.Unmarshal(jsonData, &req)
		}
	})

	b.Run("CreateAssetRequest", func(b *testing.B) {
		parentID := uuid.New().String()
		jsonData, _ := json.Marshal(CreateAssetRequest{
			Type:     "domain",
			Value:    "example.com",
			Source:   "manual",
			Metadata: `{"region":"us-east-1"}`,
			ParentID: &parentID,
		})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var req CreateAssetRequest
			_ = json.Unmarshal(jsonData, &req)
		}
	})

	b.Run("UpdateStatusRequest", func(b *testing.B) {
		jsonData := []byte(`{"status":"fixed"}`)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var req UpdateStatusRequest
			_ = json.Unmarshal(jsonData, &req)
		}
	})

	b.Run("LoginRequestWithDecoder", func(b *testing.B) {
		jsonData := `{"email":"user@example.com","password":"securepassword123"}`
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var req dto.LoginRequest
			reader := strings.NewReader(jsonData)
			_ = json.NewDecoder(reader).Decode(&req)
		}
	})
}

// BenchmarkRequestValidation benchmarks request validation
func BenchmarkRequestValidation(b *testing.B) {
	b.Run("LoginRequestValid", func(b *testing.B) {
		req := dto.LoginRequest{
			Email:    "user@example.com",
			Password: "securepassword123",
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = req.Validate()
		}
	})

	b.Run("LoginRequestInvalid", func(b *testing.B) {
		req := dto.LoginRequest{
			Email:    "",
			Password: "",
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = req.Validate()
		}
	})

	b.Run("RegisterRequestValid", func(b *testing.B) {
		req := dto.RegisterRequest{
			Email:    "user@example.com",
			Password: "securepassword123",
			Name:     "Test User",
			OrgName:  "Test Organization",
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = req.Validate()
		}
	})

	b.Run("RegisterRequestInvalid", func(b *testing.B) {
		req := dto.RegisterRequest{
			Email:    "invalid-email",
			Password: "short",
			Name:     "",
			OrgName:  strings.Repeat("x", 200), // Too long
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = req.Validate()
		}
	})

	b.Run("CreateAssetRequestValid", func(b *testing.B) {
		req := CreateAssetRequest{
			Type:   "domain",
			Value:  "example.com",
			Source: "manual",
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = req.Validate()
		}
	})

	b.Run("CreateAssetRequestWithParentID", func(b *testing.B) {
		parentID := uuid.New().String()
		req := CreateAssetRequest{
			Type:     "subdomain",
			Value:    "sub.example.com",
			Source:   "dns_enum",
			ParentID: &parentID,
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = req.Validate()
		}
	})

	b.Run("UpdateStatusRequestValid", func(b *testing.B) {
		req := UpdateStatusRequest{Status: "fixed"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = req.Validate()
		}
	})

	b.Run("UpdateStatusRequestInvalid", func(b *testing.B) {
		req := UpdateStatusRequest{Status: "invalid_status"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = req.Validate()
		}
	})
}

// BenchmarkWriteJSON benchmarks the writeJSON helper function
func BenchmarkWriteJSON(b *testing.B) {
	b.Run("SmallResponse", func(b *testing.B) {
		resp := dto.SuccessResponse{Message: "OK"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			writeJSON(w, http.StatusOK, resp)
		}
	})

	b.Run("MediumResponse", func(b *testing.B) {
		resp := AssetResponse{
			ID:           uuid.New().String(),
			Type:         "domain",
			Value:        "example.com",
			Source:       "manual",
			IsActive:     true,
			DiscoveredAt: time.Now().Unix(),
			LastSeenAt:   time.Now().Unix(),
			CreatedAt:    time.Now().Format(time.RFC3339),
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			writeJSON(w, http.StatusOK, resp)
		}
	})

	b.Run("LargeResponse", func(b *testing.B) {
		assets := make([]AssetResponse, 50)
		for i := 0; i < 50; i++ {
			assets[i] = AssetResponse{
				ID:           uuid.New().String(),
				Type:         "domain",
				Value:        "example" + string(rune('0'+i%10)) + ".com",
				Source:       "manual",
				IsActive:     true,
				DiscoveredAt: time.Now().Unix(),
				LastSeenAt:   time.Now().Unix(),
				CreatedAt:    time.Now().Format(time.RFC3339),
			}
		}
		resp := dto.PaginatedResponse{
			Data:       assets,
			Total:      500,
			Page:       1,
			PerPage:    50,
			TotalPages: 10,
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			writeJSON(w, http.StatusOK, resp)
		}
	})
}

// BenchmarkPaginationParams benchmarks pagination parameter handling
func BenchmarkPaginationParams(b *testing.B) {
	b.Run("Normalize", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			p := dto.PaginationParams{Page: 0, PerPage: 0}
			p.Normalize()
		}
	})

	b.Run("NormalizeWithValidValues", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			p := dto.PaginationParams{Page: 5, PerPage: 25}
			p.Normalize()
		}
	})

	b.Run("Offset", func(b *testing.B) {
		p := dto.PaginationParams{Page: 5, PerPage: 20}
		p.Normalize()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = p.Offset()
		}
	})
}

// BenchmarkModelConversion benchmarks model to response conversions
func BenchmarkModelConversion(b *testing.B) {
	b.Run("AssetToResponse", func(b *testing.B) {
		parentID := uuid.New()
		credentialID := uuid.New()
		asset := &models.Asset{
			Type:           models.AssetTypeDomain,
			Value:          "example.com",
			Source:         "manual",
			Metadata:       `{"region":"us-east-1"}`,
			ParentID:       &parentID,
			CredentialID:   &credentialID,
			IsActive:       true,
			DiscoveredAt:   time.Now().Unix(),
			LastSeenAt:     time.Now().Unix(),
		}
		asset.ID = uuid.New()
		asset.CreatedAt = time.Now()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = assetToResponse(asset)
		}
	})

	b.Run("FindingToResponse", func(b *testing.B) {
		finding := &models.Finding{
			AssetID:     uuid.New(),
			ScanID:      uuid.New(),
			Title:       "Open Port 22/tcp (ssh)",
			Description: "Port 22/tcp is open on 192.168.1.1",
			Severity:    models.SeverityLow,
			Status:      models.FindingStatusOpen,
			Type:        "open_port",
			Category:    "network",
			Evidence:    `{"host":"192.168.1.1","port":22}`,
			Port:        22,
			Protocol:    "tcp",
			Service:     "ssh",
			Banner:      "SSH-2.0-OpenSSH_8.0",
			Remediation: "Use key-based authentication",
			References:  `["https://example.com"]`,
			FirstSeenAt: time.Now().Unix(),
			LastSeenAt:  time.Now().Unix(),
		}
		finding.ID = uuid.New()
		finding.CreatedAt = time.Now()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = findingToResponse(finding)
		}
	})

	b.Run("MultipleAssetsToResponse", func(b *testing.B) {
		assets := make([]models.Asset, 20)
		for i := 0; i < 20; i++ {
			assets[i] = models.Asset{
				Type:         models.AssetTypeDomain,
				Value:        "example.com",
				Source:       "manual",
				IsActive:     true,
				DiscoveredAt: time.Now().Unix(),
				LastSeenAt:   time.Now().Unix(),
			}
			assets[i].ID = uuid.New()
			assets[i].CreatedAt = time.Now()
		}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			response := make([]AssetResponse, len(assets))
			for j, asset := range assets {
				response[j] = assetToResponse(&asset)
			}
		}
	})

	b.Run("MultipleFindingsToResponse", func(b *testing.B) {
		findings := make([]models.Finding, 20)
		for i := 0; i < 20; i++ {
			findings[i] = models.Finding{
				AssetID:     uuid.New(),
				ScanID:      uuid.New(),
				Title:       "Open Port",
				Severity:    models.SeverityMedium,
				Status:      models.FindingStatusOpen,
				Type:        "open_port",
				Port:        22 + i,
				Protocol:    "tcp",
				FirstSeenAt: time.Now().Unix(),
				LastSeenAt:  time.Now().Unix(),
			}
			findings[i].ID = uuid.New()
			findings[i].CreatedAt = time.Now()
		}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			response := make([]FindingResponse, len(findings))
			for j, finding := range findings {
				response[j] = findingToResponse(&finding)
			}
		}
	})
}

// BenchmarkHTTPResponseWrite benchmarks full HTTP response writing
func BenchmarkHTTPResponseWrite(b *testing.B) {
	b.Run("JSONEncoderSmall", func(b *testing.B) {
		resp := dto.SuccessResponse{Message: "OK"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var buf bytes.Buffer
			_ = json.NewEncoder(&buf).Encode(resp)
		}
	})

	b.Run("JSONEncoderLarge", func(b *testing.B) {
		assets := make([]AssetResponse, 50)
		for i := 0; i < 50; i++ {
			assets[i] = AssetResponse{
				ID:           uuid.New().String(),
				Type:         "domain",
				Value:        "example.com",
				Source:       "manual",
				IsActive:     true,
				DiscoveredAt: time.Now().Unix(),
				LastSeenAt:   time.Now().Unix(),
				CreatedAt:    time.Now().Format(time.RFC3339),
			}
		}
		resp := dto.PaginatedResponse{
			Data:       assets,
			Total:      500,
			Page:       1,
			PerPage:    50,
			TotalPages: 10,
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var buf bytes.Buffer
			_ = json.NewEncoder(&buf).Encode(resp)
		}
	})
}

// BenchmarkParallelJSONSerialization benchmarks JSON serialization with parallelism
func BenchmarkParallelJSONSerialization(b *testing.B) {
	assets := make([]AssetResponse, 20)
	for i := 0; i < 20; i++ {
		assets[i] = AssetResponse{
			ID:           uuid.New().String(),
			Type:         "domain",
			Value:        "example.com",
			Source:       "manual",
			IsActive:     true,
			DiscoveredAt: time.Now().Unix(),
			LastSeenAt:   time.Now().Unix(),
			CreatedAt:    time.Now().Format(time.RFC3339),
		}
	}
	resp := dto.PaginatedResponse{
		Data:       assets,
		Total:      100,
		Page:       1,
		PerPage:    20,
		TotalPages: 5,
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = json.Marshal(resp)
		}
	})
}

// BenchmarkParallelRequestParsing benchmarks request parsing with parallelism
func BenchmarkParallelRequestParsing(b *testing.B) {
	jsonData := []byte(`{"email":"user@example.com","password":"securepassword123","name":"Test User","org_name":"Test Org"}`)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var req dto.RegisterRequest
			_ = json.Unmarshal(jsonData, &req)
			_ = req.Validate()
		}
	})
}
