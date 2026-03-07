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
	apperrors "github.com/hugh/go-hunter/pkg/errors"
	"gorm.io/gorm"
)

type AssetHandler struct {
	db *gorm.DB
}

func NewAssetHandler(db *gorm.DB) *AssetHandler {
	return &AssetHandler{db: db}
}

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

type AssetResponse struct {
	ID           string  `json:"id"`
	Type         string  `json:"type"`
	Value        string  `json:"value"`
	Source       string  `json:"source,omitempty"`
	Metadata     string  `json:"metadata,omitempty"`
	Tags         string  `json:"tags,omitempty"`
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
		Tags:         asset.Tags,
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

func (h *AssetHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	pagination := dto.PaginationParams{Page: page, PerPage: perPage}
	pagination.Normalize()

	assetType := r.URL.Query().Get("type")
	isActive := r.URL.Query().Get("is_active")
	tagKey := r.URL.Query().Get("tag_key")
	tagValue := r.URL.Query().Get("tag_value")

	query := h.db.Model(&models.Asset{}).Where("organization_id = ?", orgID)

	if assetType != "" {
		query = query.Where("type = ?", assetType)
	}
	if isActive != "" {
		active := isActive == "true"
		query = query.Where("is_active = ?", active)
	}
	if tagKey != "" && tagValue != "" {
		query = query.Where("tags->>? = ?", tagKey, tagValue)
	} else if tagKey != "" {
		query = query.Where("jsonb_exists(tags::jsonb, ?)", tagKey)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to count assets", err))
		return
	}

	var assets []models.Asset
	if err := query.
		Order("created_at DESC").
		Offset(pagination.Offset()).
		Limit(pagination.PerPage).
		Find(&assets).Error; err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to list assets", err))
		return
	}

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

func (h *AssetHandler) Create(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	var req CreateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid request body"))
		return
	}

	if errs := req.Validate(); len(errs) > 0 {
		apperrors.WriteHTTP(w, r, apperrors.Validation(errs))
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
		var parent models.Asset
		if err := h.db.Where("id = ? AND organization_id = ?", parentID, orgID).First(&parent).Error; err != nil {
			apperrors.WriteHTTP(w, r, apperrors.NotFound("Parent asset"))
			return
		}
		asset.ParentID = &parentID
	}

	if err := h.db.Create(&asset).Error; err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to create asset", err))
		return
	}

	writeJSON(w, http.StatusCreated, assetToResponse(&asset))
}

func (h *AssetHandler) Get(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	assetIDStr := chi.URLParam(r, "id")

	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid asset ID"))
		return
	}

	var asset models.Asset
	if err := h.db.Where("id = ? AND organization_id = ?", assetID, orgID).First(&asset).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			apperrors.WriteHTTP(w, r, apperrors.NotFound("Asset"))
			return
		}
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to get asset", err))
		return
	}

	writeJSON(w, http.StatusOK, assetToResponse(&asset))
}

func (h *AssetHandler) Delete(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	assetIDStr := chi.URLParam(r, "id")

	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid asset ID"))
		return
	}

	result := h.db.Model(&models.Asset{}).
		Where("id = ? AND organization_id = ?", assetID, orgID).
		Update("is_active", false)

	if result.Error != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to delete asset", result.Error))
		return
	}

	if result.RowsAffected == 0 {
		apperrors.WriteHTTP(w, r, apperrors.NotFound("Asset"))
		return
	}

	writeJSON(w, http.StatusOK, dto.SuccessResponse{Message: "Asset deleted"})
}

type UpdateTagsRequest struct {
	Tags map[string]string `json:"tags"`
}

func (h *AssetHandler) UpdateTags(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	assetIDStr := chi.URLParam(r, "id")

	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid asset ID"))
		return
	}

	var req UpdateTagsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid request body"))
		return
	}

	tagsJSON, err := json.Marshal(req.Tags)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid tags format"))
		return
	}

	var asset models.Asset
	if err := h.db.Where("id = ? AND organization_id = ?", assetID, orgID).First(&asset).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			apperrors.WriteHTTP(w, r, apperrors.NotFound("Asset"))
			return
		}
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to get asset", err))
		return
	}

	if err := h.db.Model(&asset).Update("tags", string(tagsJSON)).Error; err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to update tags", err))
		return
	}

	asset.Tags = string(tagsJSON)
	writeJSON(w, http.StatusOK, assetToResponse(&asset))
}
