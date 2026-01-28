package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/api/dto"
	"github.com/hugh/go-hunter/internal/api/middleware"
	"github.com/hugh/go-hunter/internal/database/models"
	"gorm.io/gorm"
)

type AssetHandler struct {
	db *gorm.DB
}

func NewAssetHandler(db *gorm.DB) *AssetHandler {
	return &AssetHandler{db: db}
}

// CreateAssetRequest represents the request to create an asset
type CreateAssetRequest struct {
	Type     string  `json:"type"`
	Value    string  `json:"value"`
	Source   string  `json:"source,omitempty"`
	Metadata string  `json:"metadata,omitempty"`
	ParentID *string `json:"parent_id,omitempty"`
}

func (r CreateAssetRequest) Validate() map[string]string {
	errors := make(map[string]string)
	if r.Type == "" {
		errors["type"] = "Type is required"
	}
	validTypes := map[string]bool{
		"domain": true, "subdomain": true, "ip": true, "cidr": true,
		"bucket": true, "container": true, "endpoint": true,
	}
	if !validTypes[r.Type] {
		errors["type"] = "Invalid asset type"
	}
	if r.Value == "" {
		errors["value"] = "Value is required"
	}
	if r.ParentID != nil && *r.ParentID != "" {
		if _, err := uuid.Parse(*r.ParentID); err != nil {
			errors["parent_id"] = "Invalid parent ID format"
		}
	}
	return errors
}

// AssetResponse represents an asset in API responses
type AssetResponse struct {
	ID           string  `json:"id"`
	Type         string  `json:"type"`
	Value        string  `json:"value"`
	Source       string  `json:"source,omitempty"`
	Metadata     string  `json:"metadata,omitempty"`
	ParentID     *string `json:"parent_id,omitempty"`
	CredentialID *string `json:"credential_id,omitempty"`
	IsActive     bool    `json:"is_active"`
	DiscoveredAt int64   `json:"discovered_at"`
	LastSeenAt   int64   `json:"last_seen_at"`
	CreatedAt    string  `json:"created_at"`
}

func assetToResponse(asset *models.Asset) AssetResponse {
	resp := AssetResponse{
		ID:           asset.ID.String(),
		Type:         string(asset.Type),
		Value:        asset.Value,
		Source:       asset.Source,
		Metadata:     asset.Metadata,
		IsActive:     asset.IsActive,
		DiscoveredAt: asset.DiscoveredAt,
		LastSeenAt:   asset.LastSeenAt,
		CreatedAt:    asset.CreatedAt.Format(time.RFC3339),
	}
	if asset.ParentID != nil {
		s := asset.ParentID.String()
		resp.ParentID = &s
	}
	if asset.CredentialID != nil && *asset.CredentialID != uuid.Nil {
		s := asset.CredentialID.String()
		resp.CredentialID = &s
	}
	return resp
}

// List handles GET /api/v1/assets
func (h *AssetHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	// Parse pagination
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	pagination := dto.PaginationParams{Page: page, PerPage: perPage}
	pagination.Normalize()

	// Parse filters
	assetType := r.URL.Query().Get("type")
	isActive := r.URL.Query().Get("is_active")

	// Build query
	query := h.db.Model(&models.Asset{}).Where("organization_id = ?", orgID)

	if assetType != "" {
		query = query.Where("type = ?", assetType)
	}
	if isActive != "" {
		active := isActive == "true"
		query = query.Where("is_active = ?", active)
	}

	// Get total count
	var total int64
	if err := query.Count(&total).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to count assets"})
		return
	}

	// Get paginated results
	var assets []models.Asset
	if err := query.
		Order("created_at DESC").
		Offset(pagination.Offset()).
		Limit(pagination.PerPage).
		Find(&assets).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to list assets"})
		return
	}

	// Convert to response
	response := make([]AssetResponse, len(assets))
	for i, asset := range assets {
		response[i] = assetToResponse(&asset)
	}

	totalPages := int(total) / pagination.PerPage
	if int(total)%pagination.PerPage > 0 {
		totalPages++
	}

	writeJSON(w, http.StatusOK, dto.PaginatedResponse{
		Data:       response,
		Total:      total,
		Page:       pagination.Page,
		PerPage:    pagination.PerPage,
		TotalPages: totalPages,
	})
}

// Create handles POST /api/v1/assets
func (h *AssetHandler) Create(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	var req CreateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	if errors := req.Validate(); len(errors) > 0 {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Validation failed", Details: errors})
		return
	}

	now := time.Now().Unix()
	source := req.Source
	if source == "" {
		source = "manual"
	}
	metadata := req.Metadata
	if metadata == "" {
		metadata = "{}"
	}

	asset := models.Asset{
		OrganizationID: orgID,
		Type:           models.AssetType(req.Type),
		Value:          req.Value,
		Source:         source,
		Metadata:       metadata,
		DiscoveredAt:   now,
		LastSeenAt:     now,
		IsActive:       true,
	}

	if req.ParentID != nil && *req.ParentID != "" {
		parentID, _ := uuid.Parse(*req.ParentID)
		// Verify parent exists and belongs to same org
		var parent models.Asset
		if err := h.db.Where("id = ? AND organization_id = ?", parentID, orgID).First(&parent).Error; err != nil {
			writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Parent asset not found"})
			return
		}
		asset.ParentID = &parentID
	}

	if err := h.db.Create(&asset).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to create asset"})
		return
	}

	writeJSON(w, http.StatusCreated, assetToResponse(&asset))
}

// Get handles GET /api/v1/assets/:id
func (h *AssetHandler) Get(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	assetIDStr := chi.URLParam(r, "id")

	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid asset ID"})
		return
	}

	var asset models.Asset
	if err := h.db.Where("id = ? AND organization_id = ?", assetID, orgID).First(&asset).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			writeJSON(w, http.StatusNotFound, dto.ErrorResponse{Error: "Asset not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to get asset"})
		return
	}

	writeJSON(w, http.StatusOK, assetToResponse(&asset))
}

// Delete handles DELETE /api/v1/assets/:id
func (h *AssetHandler) Delete(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	assetIDStr := chi.URLParam(r, "id")

	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid asset ID"})
		return
	}

	// Soft delete by setting is_active to false
	result := h.db.Model(&models.Asset{}).
		Where("id = ? AND organization_id = ?", assetID, orgID).
		Update("is_active", false)

	if result.Error != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to delete asset"})
		return
	}

	if result.RowsAffected == 0 {
		writeJSON(w, http.StatusNotFound, dto.ErrorResponse{Error: "Asset not found"})
		return
	}

	writeJSON(w, http.StatusOK, dto.SuccessResponse{Message: "Asset deleted"})
}
