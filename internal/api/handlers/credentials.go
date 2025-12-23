package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/api/dto"
	"github.com/hugh/go-hunter/internal/api/middleware"
	"github.com/hugh/go-hunter/internal/assets"
	"github.com/hugh/go-hunter/internal/database/models"
)

type CredentialHandler struct {
	service *assets.Service
}

func NewCredentialHandler(service *assets.Service) *CredentialHandler {
	return &CredentialHandler{service: service}
}

// CreateCredentialRequest represents the request to create a credential
type CreateCredentialRequest struct {
	Name     string                 `json:"name"`
	Provider string                 `json:"provider"`
	Data     map[string]interface{} `json:"data"`
}

func (r CreateCredentialRequest) Validate() map[string]string {
	errors := make(map[string]string)
	if r.Name == "" {
		errors["name"] = "Name is required"
	}
	if r.Provider == "" {
		errors["provider"] = "Provider is required"
	}
	validProviders := map[string]bool{
		"aws": true, "gcp": true, "azure": true,
		"digitalocean": true, "cloudflare": true,
	}
	if !validProviders[r.Provider] {
		errors["provider"] = "Invalid provider"
	}
	if r.Data == nil || len(r.Data) == 0 {
		errors["data"] = "Credential data is required"
	}
	return errors
}

// CredentialResponse represents a credential in API responses (no secrets)
type CredentialResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Provider   string `json:"provider"`
	IsActive   bool   `json:"is_active"`
	LastUsed   int64  `json:"last_used,omitempty"`
	CreatedAt  string `json:"created_at"`
}

// Create handles POST /api/v1/credentials
func (h *CredentialHandler) Create(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	var req CreateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	if errors := req.Validate(); len(errors) > 0 {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Validation failed", Details: errors})
		return
	}

	// Convert data map to appropriate credential struct
	credData, err := convertCredentialData(models.CloudProvider(req.Provider), req.Data)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: err.Error()})
		return
	}

	cred, err := h.service.CreateCredential(r.Context(), orgID, req.Name, models.CloudProvider(req.Provider), credData)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to create credential"})
		return
	}

	writeJSON(w, http.StatusCreated, CredentialResponse{
		ID:        cred.ID.String(),
		Name:      cred.Name,
		Provider:  string(cred.Provider),
		IsActive:  cred.IsActive,
		CreatedAt: cred.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

// List handles GET /api/v1/credentials
func (h *CredentialHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	creds, err := h.service.ListCredentials(r.Context(), orgID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to list credentials"})
		return
	}

	response := make([]CredentialResponse, len(creds))
	for i, cred := range creds {
		response[i] = CredentialResponse{
			ID:        cred.ID.String(),
			Name:      cred.Name,
			Provider:  string(cred.Provider),
			IsActive:  cred.IsActive,
			LastUsed:  cred.LastUsed,
			CreatedAt: cred.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// Delete handles DELETE /api/v1/credentials/:id
func (h *CredentialHandler) Delete(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	credIDStr := chi.URLParam(r, "id")

	credID, err := uuid.Parse(credIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid credential ID"})
		return
	}

	if err := h.service.DeleteCredential(r.Context(), orgID, credID); err != nil {
		writeJSON(w, http.StatusNotFound, dto.ErrorResponse{Error: "Credential not found"})
		return
	}

	writeJSON(w, http.StatusOK, dto.SuccessResponse{Message: "Credential deleted"})
}

// Test handles POST /api/v1/credentials/:id/test
func (h *CredentialHandler) Test(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	credIDStr := chi.URLParam(r, "id")

	credID, err := uuid.Parse(credIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid credential ID"})
		return
	}

	if err := h.service.ValidateCredential(r.Context(), orgID, credID); err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, dto.SuccessResponse{Message: "Credential is valid"})
}

// convertCredentialData converts a map to the appropriate credential struct
func convertCredentialData(provider models.CloudProvider, data map[string]interface{}) (interface{}, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	switch provider {
	case models.ProviderAWS:
		var cred assets.AWSCredential
		if err := json.Unmarshal(jsonData, &cred); err != nil {
			return nil, err
		}
		return cred, nil

	case models.ProviderGCP:
		var cred assets.GCPCredential
		if err := json.Unmarshal(jsonData, &cred); err != nil {
			return nil, err
		}
		return cred, nil

	case models.ProviderAzure:
		var cred assets.AzureCredential
		if err := json.Unmarshal(jsonData, &cred); err != nil {
			return nil, err
		}
		return cred, nil

	case models.ProviderDigitalOcean:
		var cred assets.DigitalOceanCredential
		if err := json.Unmarshal(jsonData, &cred); err != nil {
			return nil, err
		}
		return cred, nil

	case models.ProviderCloudflare:
		var cred assets.CloudflareCredential
		if err := json.Unmarshal(jsonData, &cred); err != nil {
			return nil, err
		}
		return cred, nil

	default:
		return nil, nil
	}
}
