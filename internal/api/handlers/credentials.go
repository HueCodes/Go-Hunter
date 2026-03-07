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
	apperrors "github.com/hugh/go-hunter/pkg/errors"
)

type CredentialHandler struct {
	service *assets.Service
}

func NewCredentialHandler(service *assets.Service) *CredentialHandler {
	return &CredentialHandler{service: service}
}

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
	if len(r.Data) == 0 {
		errors["data"] = "Credential data is required"
	}
	return errors
}

type CredentialResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	IsActive  bool   `json:"is_active"`
	LastUsed  int64  `json:"last_used,omitempty"`
	CreatedAt string `json:"created_at"`
}

func (h *CredentialHandler) Create(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	var req CreateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid request body"))
		return
	}

	if errs := req.Validate(); len(errs) > 0 {
		apperrors.WriteHTTP(w, r, apperrors.Validation(errs))
		return
	}

	credData, err := convertCredentialData(models.CloudProvider(req.Provider), req.Data)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid credential data format"))
		return
	}

	cred, err := h.service.CreateCredential(r.Context(), orgID, req.Name, models.CloudProvider(req.Provider), credData)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to create credential", err))
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

func (h *CredentialHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	creds, err := h.service.ListCredentials(r.Context(), orgID)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to list credentials", err))
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

func (h *CredentialHandler) Delete(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	credIDStr := chi.URLParam(r, "id")

	credID, err := uuid.Parse(credIDStr)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid credential ID"))
		return
	}

	if err := h.service.DeleteCredential(r.Context(), orgID, credID); err != nil {
		apperrors.WriteHTTP(w, r, apperrors.NotFound("Credential"))
		return
	}

	writeJSON(w, http.StatusOK, dto.SuccessResponse{Message: "Credential deleted"})
}

func (h *CredentialHandler) Test(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	credIDStr := chi.URLParam(r, "id")

	credID, err := uuid.Parse(credIDStr)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid credential ID"))
		return
	}

	if err := h.service.ValidateCredential(r.Context(), orgID, credID); err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Credential validation failed"))
		return
	}

	writeJSON(w, http.StatusOK, dto.SuccessResponse{Message: "Credential is valid"})
}

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
