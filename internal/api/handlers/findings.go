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

type FindingHandler struct {
	db *gorm.DB
}

func NewFindingHandler(db *gorm.DB) *FindingHandler {
	return &FindingHandler{db: db}
}

// FindingResponse represents a finding in API responses
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

// List handles GET /api/v1/findings
func (h *FindingHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	// Parse pagination
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	pagination := dto.PaginationParams{Page: page, PerPage: perPage}
	pagination.Normalize()

	// Parse filters
	severity := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")
	assetID := r.URL.Query().Get("asset_id")
	findingType := r.URL.Query().Get("type")

	// Build query
	query := h.db.Model(&models.Finding{}).Where("organization_id = ?", orgID)

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

	// Get total count
	var total int64
	if err := query.Count(&total).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to count findings"})
		return
	}

	// Get paginated results
	var findings []models.Finding
	if err := query.
		Order("severity DESC, created_at DESC").
		Offset(pagination.Offset()).
		Limit(pagination.PerPage).
		Find(&findings).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to list findings"})
		return
	}

	// Convert to response
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

// Get handles GET /api/v1/findings/:id
func (h *FindingHandler) Get(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	findingIDStr := chi.URLParam(r, "id")

	findingID, err := uuid.Parse(findingIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid finding ID"})
		return
	}

	var finding models.Finding
	if err := h.db.
		Preload("Asset").
		Where("id = ? AND organization_id = ?", findingID, orgID).
		First(&finding).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			writeJSON(w, http.StatusNotFound, dto.ErrorResponse{Error: "Finding not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to get finding"})
		return
	}

	writeJSON(w, http.StatusOK, findingToResponse(&finding))
}

// UpdateStatusRequest represents the request to update finding status
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

// UpdateStatus handles PUT /api/v1/findings/:id/status
func (h *FindingHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	userID := middleware.GetUserID(r.Context())
	findingIDStr := chi.URLParam(r, "id")

	findingID, err := uuid.Parse(findingIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid finding ID"})
		return
	}

	var req UpdateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	if errors := req.Validate(); len(errors) > 0 {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Validation failed", Details: errors})
		return
	}

	// Get current finding
	var finding models.Finding
	if err := h.db.Where("id = ? AND organization_id = ?", findingID, orgID).First(&finding).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			writeJSON(w, http.StatusNotFound, dto.ErrorResponse{Error: "Finding not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to get finding"})
		return
	}

	// Build updates
	updates := map[string]interface{}{
		"status":     models.FindingStatus(req.Status),
		"updated_at": time.Now(),
	}

	newStatus := models.FindingStatus(req.Status)

	// Track status-specific timestamps
	if newStatus == models.FindingStatusFixed || newStatus == models.FindingStatusFalsePositive || newStatus == models.FindingStatusAccepted {
		updates["resolved_at"] = time.Now().Unix()
		updates["resolved_by"] = userID
	} else if newStatus == models.FindingStatusOpen {
		// Reopening - clear resolved fields
		updates["resolved_at"] = 0
		updates["resolved_by"] = nil
	}

	if err := h.db.Model(&finding).Updates(updates).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to update finding status"})
		return
	}

	// Reload finding
	h.db.First(&finding, findingID)

	writeJSON(w, http.StatusOK, findingToResponse(&finding))
}
