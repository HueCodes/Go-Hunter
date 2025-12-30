package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/hugh/go-hunter/internal/api/dto"
	"github.com/hugh/go-hunter/internal/api/middleware"
	"github.com/hugh/go-hunter/internal/database/models"
	"github.com/hugh/go-hunter/internal/tasks"
	"gorm.io/gorm"
)

type ScanHandler struct {
	db          *gorm.DB
	asynqClient *asynq.Client
}

func NewScanHandler(db *gorm.DB, asynqClient *asynq.Client) *ScanHandler {
	return &ScanHandler{db: db, asynqClient: asynqClient}
}

// CreateScanRequest represents the request to create a scan
type CreateScanRequest struct {
	Type           string   `json:"type"`
	TargetAssetIDs []string `json:"target_asset_ids,omitempty"`
	CredentialIDs  []string `json:"credential_ids,omitempty"`
	Config         string   `json:"config,omitempty"`
}

func (r CreateScanRequest) Validate() map[string]string {
	errors := make(map[string]string)
	validTypes := map[string]bool{
		"discovery": true, "port_scan": true, "http_probe": true,
		"crawl": true, "vuln_check": true, "full": true,
	}
	if !validTypes[r.Type] {
		errors["type"] = "Invalid scan type"
	}

	// Validate UUIDs
	for i, id := range r.TargetAssetIDs {
		if _, err := uuid.Parse(id); err != nil {
			errors["target_asset_ids"] = "Invalid asset ID at index " + strconv.Itoa(i)
			break
		}
	}
	for i, id := range r.CredentialIDs {
		if _, err := uuid.Parse(id); err != nil {
			errors["credential_ids"] = "Invalid credential ID at index " + strconv.Itoa(i)
			break
		}
	}

	// Discovery requires credentials
	if r.Type == "discovery" && len(r.CredentialIDs) == 0 {
		errors["credential_ids"] = "Discovery scan requires at least one credential"
	}

	return errors
}

// ScanResponse represents a scan in API responses
type ScanResponse struct {
	ID             string   `json:"id"`
	Type           string   `json:"type"`
	Status         string   `json:"status"`
	TargetAssetIDs []string `json:"target_asset_ids,omitempty"`
	CredentialIDs  []string `json:"credential_ids,omitempty"`
	StartedAt      int64    `json:"started_at,omitempty"`
	CompletedAt    int64    `json:"completed_at,omitempty"`
	Error          string   `json:"error,omitempty"`
	AssetsScanned  int      `json:"assets_scanned"`
	FindingsCount  int      `json:"findings_count"`
	PortsOpen      int      `json:"ports_open"`
	ServicesFound  int      `json:"services_found"`
	Config         string   `json:"config,omitempty"`
	TaskID         string   `json:"task_id,omitempty"`
	CreatedAt      string   `json:"created_at"`
}

func scanToResponse(scan *models.Scan) ScanResponse {
	targetIDs := make([]string, len(scan.TargetAssetIDs))
	for i, id := range scan.TargetAssetIDs {
		targetIDs[i] = id.String()
	}
	credIDs := make([]string, len(scan.CredentialIDs))
	for i, id := range scan.CredentialIDs {
		credIDs[i] = id.String()
	}

	return ScanResponse{
		ID:             scan.ID.String(),
		Type:           string(scan.Type),
		Status:         string(scan.Status),
		TargetAssetIDs: targetIDs,
		CredentialIDs:  credIDs,
		StartedAt:      scan.StartedAt,
		CompletedAt:    scan.CompletedAt,
		Error:          scan.Error,
		AssetsScanned:  scan.AssetsScanned,
		FindingsCount:  scan.FindingsCount,
		PortsOpen:      scan.PortsOpen,
		ServicesFound:  scan.ServicesFound,
		Config:         scan.Config,
		TaskID:         scan.TaskID,
		CreatedAt:      scan.CreatedAt.Format(time.RFC3339),
	}
}

// List handles GET /api/v1/scans
func (h *ScanHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	// Parse pagination
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	pagination := dto.PaginationParams{Page: page, PerPage: perPage}
	pagination.Normalize()

	// Parse filters
	status := r.URL.Query().Get("status")
	scanType := r.URL.Query().Get("type")

	// Build query
	query := h.db.Model(&models.Scan{}).Where("organization_id = ?", orgID)

	if status != "" {
		query = query.Where("status = ?", status)
	}
	if scanType != "" {
		query = query.Where("type = ?", scanType)
	}

	// Get total count
	var total int64
	if err := query.Count(&total).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to count scans"})
		return
	}

	// Get paginated results
	var scans []models.Scan
	if err := query.
		Order("created_at DESC").
		Offset(pagination.Offset()).
		Limit(pagination.PerPage).
		Find(&scans).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to list scans"})
		return
	}

	// Convert to response
	response := make([]ScanResponse, len(scans))
	for i, scan := range scans {
		response[i] = scanToResponse(&scan)
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

// Create handles POST /api/v1/scans
func (h *ScanHandler) Create(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	var req CreateScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	if errors := req.Validate(); len(errors) > 0 {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Validation failed", Details: errors})
		return
	}

	// Convert string IDs to UUIDs
	targetAssetIDs := make([]uuid.UUID, len(req.TargetAssetIDs))
	for i, id := range req.TargetAssetIDs {
		targetAssetIDs[i], _ = uuid.Parse(id)
	}
	credentialIDs := make([]uuid.UUID, len(req.CredentialIDs))
	for i, id := range req.CredentialIDs {
		credentialIDs[i], _ = uuid.Parse(id)
	}

	// Verify credentials belong to org
	if len(credentialIDs) > 0 {
		var count int64
		h.db.Model(&models.CloudCredential{}).
			Where("id IN ? AND organization_id = ?", credentialIDs, orgID).
			Count(&count)
		if count != int64(len(credentialIDs)) {
			writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "One or more credentials not found"})
			return
		}
	}

	// Verify assets belong to org
	if len(targetAssetIDs) > 0 {
		var count int64
		h.db.Model(&models.Asset{}).
			Where("id IN ? AND organization_id = ?", targetAssetIDs, orgID).
			Count(&count)
		if count != int64(len(targetAssetIDs)) {
			writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "One or more assets not found"})
			return
		}
	}

	config := req.Config
	if config == "" {
		config = "{}"
	}

	// Create scan record
	scan := models.Scan{
		OrganizationID: orgID,
		Type:           models.ScanType(req.Type),
		Status:         models.ScanStatusPending,
		TargetAssetIDs: targetAssetIDs,
		CredentialIDs:  credentialIDs,
		Config:         config,
	}

	if err := h.db.Create(&scan).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to create scan"})
		return
	}

	// Enqueue task based on scan type
	var task *asynq.Task
	var err error

	switch scan.Type {
	case models.ScanTypeDiscovery:
		task, err = tasks.NewAssetDiscoveryTask(tasks.AssetDiscoveryPayload{
			ScanID:         scan.ID,
			OrganizationID: orgID,
			CredentialIDs:  credentialIDs,
		})
	case models.ScanTypePortScan:
		task, err = tasks.NewPortScanTask(tasks.PortScanPayload{
			ScanID:         scan.ID,
			OrganizationID: orgID,
			AssetIDs:       targetAssetIDs,
			Ports:          "1-1000",
			RateLimit:      1000,
		})
	case models.ScanTypeHTTPProbe:
		task, err = tasks.NewHTTPProbeTask(tasks.HTTPProbePayload{
			ScanID:         scan.ID,
			OrganizationID: orgID,
			AssetIDs:       targetAssetIDs,
			Ports:          []int{80, 443, 8080, 8443},
			FollowRedirect: true,
		})
	case models.ScanTypeCrawl:
		task, err = tasks.NewCrawlTask(tasks.CrawlPayload{
			ScanID:         scan.ID,
			OrganizationID: orgID,
			AssetIDs:       targetAssetIDs,
			MaxDepth:       3,
			MaxPages:       100,
		})
	case models.ScanTypeVulnCheck:
		task, err = tasks.NewVulnCheckTask(tasks.VulnCheckPayload{
			ScanID:         scan.ID,
			OrganizationID: orgID,
			AssetIDs:       targetAssetIDs,
			CheckTypes:     []string{}, // Run all checks
		})
	case models.ScanTypeFull:
		// For full scan, start with discovery
		task, err = tasks.NewAssetDiscoveryTask(tasks.AssetDiscoveryPayload{
			ScanID:         scan.ID,
			OrganizationID: orgID,
			CredentialIDs:  credentialIDs,
		})
	}

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to create scan task"})
		return
	}

	// Enqueue task if asynq client is available
	if h.asynqClient != nil {
		info, err := h.asynqClient.Enqueue(task)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to enqueue scan task"})
			return
		}
		// Update scan with task ID
		h.db.Model(&scan).Update("task_id", info.ID)
		scan.TaskID = info.ID
	}

	writeJSON(w, http.StatusCreated, scanToResponse(&scan))
}

// Get handles GET /api/v1/scans/:id
func (h *ScanHandler) Get(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	scanIDStr := chi.URLParam(r, "id")

	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid scan ID"})
		return
	}

	var scan models.Scan
	if err := h.db.Where("id = ? AND organization_id = ?", scanID, orgID).First(&scan).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			writeJSON(w, http.StatusNotFound, dto.ErrorResponse{Error: "Scan not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to get scan"})
		return
	}

	writeJSON(w, http.StatusOK, scanToResponse(&scan))
}

// Cancel handles POST /api/v1/scans/:id/cancel
func (h *ScanHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	scanIDStr := chi.URLParam(r, "id")

	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid scan ID"})
		return
	}

	var scan models.Scan
	if err := h.db.Where("id = ? AND organization_id = ?", scanID, orgID).First(&scan).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			writeJSON(w, http.StatusNotFound, dto.ErrorResponse{Error: "Scan not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to get scan"})
		return
	}

	// Can only cancel pending or running scans
	if scan.Status != models.ScanStatusPending && scan.Status != models.ScanStatusRunning {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Can only cancel pending or running scans",
		})
		return
	}

	// Update status
	updates := map[string]interface{}{
		"status":       models.ScanStatusCancelled,
		"completed_at": time.Now().Unix(),
		"updated_at":   time.Now(),
	}

	if err := h.db.Model(&scan).Updates(updates).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to cancel scan"})
		return
	}

	scan.Status = models.ScanStatusCancelled
	scan.CompletedAt = time.Now().Unix()

	writeJSON(w, http.StatusOK, scanToResponse(&scan))
}
