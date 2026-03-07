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
	apperrors "github.com/hugh/go-hunter/pkg/errors"
	"gorm.io/gorm"
)

type ScanHandler struct {
	db          *gorm.DB
	asynqClient *asynq.Client
}

func NewScanHandler(db *gorm.DB, asynqClient *asynq.Client) *ScanHandler {
	return &ScanHandler{db: db, asynqClient: asynqClient}
}

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

	if r.Type == "discovery" && len(r.CredentialIDs) == 0 {
		errors["credential_ids"] = "Discovery scan requires at least one credential"
	}

	return errors
}

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

func (h *ScanHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	pagination := dto.PaginationParams{Page: page, PerPage: perPage}
	pagination.Normalize()

	status := r.URL.Query().Get("status")
	scanType := r.URL.Query().Get("type")

	query := h.db.Model(&models.Scan{}).Where("organization_id = ?", orgID)

	if status != "" {
		query = query.Where("status = ?", status)
	}
	if scanType != "" {
		query = query.Where("type = ?", scanType)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to count scans", err))
		return
	}

	var scans []models.Scan
	if err := query.
		Order("created_at DESC").
		Offset(pagination.Offset()).
		Limit(pagination.PerPage).
		Find(&scans).Error; err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to list scans", err))
		return
	}

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

func (h *ScanHandler) Create(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	var req CreateScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid request body"))
		return
	}

	if errs := req.Validate(); len(errs) > 0 {
		apperrors.WriteHTTP(w, r, apperrors.Validation(errs))
		return
	}

	targetAssetIDs := make([]uuid.UUID, len(req.TargetAssetIDs))
	for i, id := range req.TargetAssetIDs {
		targetAssetIDs[i], _ = uuid.Parse(id)
	}
	credentialIDs := make([]uuid.UUID, len(req.CredentialIDs))
	for i, id := range req.CredentialIDs {
		credentialIDs[i], _ = uuid.Parse(id)
	}

	if len(credentialIDs) > 0 {
		var count int64
		h.db.Model(&models.CloudCredential{}).
			Where("id IN ? AND organization_id = ?", credentialIDs, orgID).
			Count(&count)
		if count != int64(len(credentialIDs)) {
			apperrors.WriteHTTP(w, r, apperrors.BadRequest("One or more credentials not found"))
			return
		}
	}

	if len(targetAssetIDs) > 0 {
		var count int64
		h.db.Model(&models.Asset{}).
			Where("id IN ? AND organization_id = ?", targetAssetIDs, orgID).
			Count(&count)
		if count != int64(len(targetAssetIDs)) {
			apperrors.WriteHTTP(w, r, apperrors.BadRequest("One or more assets not found"))
			return
		}
	}

	scanConfig := req.Config
	if scanConfig == "" {
		scanConfig = "{}"
	}

	scan := models.Scan{
		OrganizationID: orgID,
		Type:           models.ScanType(req.Type),
		Status:         models.ScanStatusPending,
		TargetAssetIDs: targetAssetIDs,
		CredentialIDs:  credentialIDs,
		Config:         scanConfig,
	}

	if err := h.db.Create(&scan).Error; err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to create scan", err))
		return
	}

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
			CheckTypes:     []string{},
		})
	case models.ScanTypeFull:
		task, err = tasks.NewAssetDiscoveryTask(tasks.AssetDiscoveryPayload{
			ScanID:         scan.ID,
			OrganizationID: orgID,
			CredentialIDs:  credentialIDs,
		})
	}

	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to create scan task", err))
		return
	}

	if h.asynqClient != nil && task != nil {
		info, err := h.asynqClient.Enqueue(task)
		if err != nil {
			apperrors.WriteHTTP(w, r, apperrors.Unavailable("Failed to enqueue scan task — queue service unavailable"))
			return
		}
		h.db.Model(&scan).Update("task_id", info.ID)
		scan.TaskID = info.ID
	}

	writeJSON(w, http.StatusCreated, scanToResponse(&scan))
}

func (h *ScanHandler) Get(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	scanIDStr := chi.URLParam(r, "id")

	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid scan ID"))
		return
	}

	var scan models.Scan
	if err := h.db.Where("id = ? AND organization_id = ?", scanID, orgID).First(&scan).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			apperrors.WriteHTTP(w, r, apperrors.NotFound("Scan"))
			return
		}
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to get scan", err))
		return
	}

	writeJSON(w, http.StatusOK, scanToResponse(&scan))
}

func (h *ScanHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	scanIDStr := chi.URLParam(r, "id")

	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid scan ID"))
		return
	}

	var scan models.Scan
	if err := h.db.Where("id = ? AND organization_id = ?", scanID, orgID).First(&scan).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			apperrors.WriteHTTP(w, r, apperrors.NotFound("Scan"))
			return
		}
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to get scan", err))
		return
	}

	if scan.Status != models.ScanStatusPending && scan.Status != models.ScanStatusRunning {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Can only cancel pending or running scans"))
		return
	}

	updates := map[string]interface{}{
		"status":       models.ScanStatusCancelled,
		"completed_at": time.Now().Unix(),
		"updated_at":   time.Now(),
	}

	if err := h.db.Model(&scan).Updates(updates).Error; err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to cancel scan", err))
		return
	}

	scan.Status = models.ScanStatusCancelled
	scan.CompletedAt = time.Now().Unix()

	writeJSON(w, http.StatusOK, scanToResponse(&scan))
}
