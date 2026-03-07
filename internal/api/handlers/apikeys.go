package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/api/dto"
	"github.com/hugh/go-hunter/internal/api/middleware"
	"github.com/hugh/go-hunter/internal/auth"
	apperrors "github.com/hugh/go-hunter/pkg/errors"
)

type APIKeyHandler struct {
	service *auth.APIKeyService
}

func NewAPIKeyHandler(service *auth.APIKeyService) *APIKeyHandler {
	return &APIKeyHandler{service: service}
}

type CreateAPIKeyRequest struct {
	Name          string `json:"name"`
	ExpiresInDays int    `json:"expires_in_days,omitempty"`
}

func (r CreateAPIKeyRequest) Validate() map[string]string {
	errs := make(map[string]string)
	if r.Name == "" {
		errs["name"] = "Name is required"
	}
	if len(r.Name) > 100 {
		errs["name"] = "Name must be 100 characters or less"
	}
	if r.ExpiresInDays < 0 {
		errs["expires_in_days"] = "Must be positive"
	}
	if r.ExpiresInDays > 365 {
		errs["expires_in_days"] = "Must be 365 days or less"
	}
	return errs
}

type APIKeyResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	KeyPrefix  string `json:"key_prefix"`
	Role       string `json:"role"`
	IsActive   bool   `json:"is_active"`
	LastUsedAt int64  `json:"last_used_at,omitempty"`
	ExpiresAt  int64  `json:"expires_at,omitempty"`
	CreatedAt  string `json:"created_at"`
}

type CreateAPIKeyResponse struct {
	APIKeyResponse
	Key string `json:"key"`
}

func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	userID := middleware.GetUserID(r.Context())
	userRole := middleware.GetUserRole(r.Context())

	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid request body"))
		return
	}

	if errs := req.Validate(); len(errs) > 0 {
		apperrors.WriteHTTP(w, r, apperrors.Validation(errs))
		return
	}

	result, err := h.service.Create(r.Context(), auth.CreateAPIKeyInput{
		Name:           req.Name,
		UserID:         userID,
		OrganizationID: orgID,
		Role:           userRole,
		ExpiresInDays:  req.ExpiresInDays,
	})
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to create API key", err))
		return
	}

	writeJSON(w, http.StatusCreated, CreateAPIKeyResponse{
		APIKeyResponse: APIKeyResponse{
			ID:        result.Key.ID.String(),
			Name:      result.Key.Name,
			KeyPrefix: result.Key.KeyPrefix,
			Role:      result.Key.Role,
			IsActive:  result.Key.IsActive,
			ExpiresAt: result.Key.ExpiresAt,
			CreatedAt: result.Key.CreatedAt.Format(time.RFC3339),
		},
		Key: result.RawKey,
	})
}

func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	keys, err := h.service.List(r.Context(), orgID)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to list API keys", err))
		return
	}

	response := make([]APIKeyResponse, len(keys))
	for i, k := range keys {
		response[i] = APIKeyResponse{
			ID:         k.ID.String(),
			Name:       k.Name,
			KeyPrefix:  k.KeyPrefix,
			Role:       k.Role,
			IsActive:   k.IsActive,
			LastUsedAt: k.LastUsedAt,
			ExpiresAt:  k.ExpiresAt,
			CreatedAt:  k.CreatedAt.Format(time.RFC3339),
		}
	}

	writeJSON(w, http.StatusOK, response)
}

func (h *APIKeyHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	keyIDStr := chi.URLParam(r, "id")

	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid API key ID"))
		return
	}

	if err := h.service.Revoke(r.Context(), orgID, keyID); err != nil {
		if err == auth.ErrAPIKeyNotFound {
			apperrors.WriteHTTP(w, r, apperrors.NotFound("API key"))
			return
		}
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to revoke API key", err))
		return
	}

	writeJSON(w, http.StatusOK, dto.SuccessResponse{Message: "API key revoked"})
}

func (h *APIKeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	keyIDStr := chi.URLParam(r, "id")

	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid API key ID"))
		return
	}

	if err := h.service.Delete(r.Context(), orgID, keyID); err != nil {
		if err == auth.ErrAPIKeyNotFound {
			apperrors.WriteHTTP(w, r, apperrors.NotFound("API key"))
			return
		}
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to delete API key", err))
		return
	}

	writeJSON(w, http.StatusOK, dto.SuccessResponse{Message: "API key deleted"})
}
