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

type FindingHandler struct {
	db *gorm.DB
}

func NewFindingHandler(db *gorm.DB) *FindingHandler {
	return &FindingHandler{db: db}
}

type FindingResponse struct {
	ID             string  `json:"id"`
	AssetID        string  `json:"asset_id"`
	ScanID         *string `json:"scan_id,omitempty"`
	Title          string  `json:"title"`
	Description    string  `json:"description,omitempty"`
	Severity       string  `json:"severity"`
	Status         string  `json:"status"`
	Type           string  `json:"type,omitempty"`
	Category       string  `json:"category,omitempty"`
	Evidence       string  `json:"evidence,omitempty"`
	Port           int     `json:"port,omitempty"`
	Protocol       string  `json:"protocol,omitempty"`
	Service        string  `json:"service,omitempty"`
	Banner         string  `json:"banner,omitempty"`
	Remediation    string  `json:"remediation,omitempty"`
	References     string  `json:"references,omitempty"`
	FirstSeenAt    int64   `json:"first_seen_at"`
	LastSeenAt     int64   `json:"last_seen_at"`
	ResolvedAt     int64   `json:"resolved_at,omitempty"`
	AcknowledgedAt int64   `json:"acknowledged_at,omitempty"`
	CreatedAt      string  `json:"created_at"`
}

func findingToResponse(finding *models.Finding) FindingResponse {
	resp := FindingResponse{
		ID:          finding.ID.String(),
		AssetID:     finding.AssetID.String(),
		Title:       finding.Title,
		Description: finding.Description,
		Severity:    string(finding.Severity),
		Status:      string(finding.Status),
		Type:        finding.Type,
		Category:    finding.Category,
		Evidence:    finding.Evidence,
		Port:        finding.Port,
		Protocol:    finding.Protocol,
		Service:     finding.Service,
		Banner:      finding.Banner,
		Remediation: finding.Remediation,
		References:  finding.References,
		FirstSeenAt: finding.FirstSeenAt,
		LastSeenAt:  finding.LastSeenAt,
		ResolvedAt:  finding.ResolvedAt,
		CreatedAt:   finding.CreatedAt.Format(time.RFC3339),
	}
	if finding.ScanID != uuid.Nil {
		s := finding.ScanID.String()
		resp.ScanID = &s
	}
	return resp
}

func (h *FindingHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	pagination := dto.PaginationParams{Page: page, PerPage: perPage}
	pagination.Normalize()

	severity := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")
	assetID := r.URL.Query().Get("asset_id")
	findingType := r.URL.Query().Get("type")

	query := h.db.WithContext(r.Context()).Model(&models.Finding{}).Where("organization_id = ?", orgID)

	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if assetID != "" {
		if id, err := uuid.Parse(assetID); err == nil {
			query = query.Where("asset_id = ?", id)
		}
	}
	if findingType != "" {
		query = query.Where("type = ?", findingType)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to count findings", err))
		return
	}

	var findings []models.Finding
	if err := query.
		Order("severity DESC, created_at DESC").
		Offset(pagination.Offset()).
		Limit(pagination.PerPage).
		Find(&findings).Error; err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to list findings", err))
		return
	}

	response := make([]FindingResponse, len(findings))
	for i, finding := range findings {
		response[i] = findingToResponse(&finding)
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

func (h *FindingHandler) Get(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	findingIDStr := chi.URLParam(r, "id")

	findingID, err := uuid.Parse(findingIDStr)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid finding ID"))
		return
	}

	var finding models.Finding
	if err := h.db.WithContext(r.Context()).
		Preload("Asset").
		Where("id = ? AND organization_id = ?", findingID, orgID).
		First(&finding).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			apperrors.WriteHTTP(w, r, apperrors.NotFound("Finding"))
			return
		}
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to get finding", err))
		return
	}

	writeJSON(w, http.StatusOK, findingToResponse(&finding))
}

type UpdateStatusRequest struct {
	Status string `json:"status"`
}

func (r UpdateStatusRequest) Validate() map[string]string {
	errors := make(map[string]string)
	validStatuses := map[string]bool{
		"open": true, "acknowledged": true, "fixed": true,
		"false_positive": true, "accepted": true,
	}
	if !validStatuses[r.Status] {
		errors["status"] = "Invalid status. Must be one of: open, acknowledged, fixed, false_positive, accepted"
	}
	return errors
}

func (h *FindingHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	userID := middleware.GetUserID(r.Context())
	findingIDStr := chi.URLParam(r, "id")

	findingID, err := uuid.Parse(findingIDStr)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid finding ID"))
		return
	}

	var req UpdateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid request body"))
		return
	}

	if errs := req.Validate(); len(errs) > 0 {
		apperrors.WriteHTTP(w, r, apperrors.Validation(errs))
		return
	}

	var finding models.Finding
	if err := h.db.WithContext(r.Context()).Where("id = ? AND organization_id = ?", findingID, orgID).First(&finding).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			apperrors.WriteHTTP(w, r, apperrors.NotFound("Finding"))
			return
		}
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to get finding", err))
		return
	}

	updates := map[string]interface{}{
		"status":     models.FindingStatus(req.Status),
		"updated_at": time.Now(),
	}

	newStatus := models.FindingStatus(req.Status)

	if newStatus == models.FindingStatusFixed || newStatus == models.FindingStatusFalsePositive || newStatus == models.FindingStatusAccepted {
		updates["resolved_at"] = time.Now().Unix()
		updates["resolved_by"] = userID
	} else if newStatus == models.FindingStatusOpen {
		updates["resolved_at"] = 0
		updates["resolved_by"] = nil
	}

	if err := h.db.WithContext(r.Context()).Model(&finding).Updates(updates).Error; err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to update finding status", err))
		return
	}

	h.db.WithContext(r.Context()).First(&finding, findingID)

	writeJSON(w, http.StatusOK, findingToResponse(&finding))
}
