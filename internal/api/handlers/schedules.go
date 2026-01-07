package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/hugh/go-hunter/internal/api/dto"
	"github.com/hugh/go-hunter/internal/api/middleware"
	"github.com/hugh/go-hunter/internal/database/models"
	"github.com/hugh/go-hunter/internal/tasks"
	"github.com/hugh/go-hunter/pkg/util"
	"gorm.io/gorm"
)

type ScheduleHandler struct {
	db          *gorm.DB
	asynqClient *asynq.Client
}

func NewScheduleHandler(db *gorm.DB, asynqClient *asynq.Client) *ScheduleHandler {
	return &ScheduleHandler{db: db, asynqClient: asynqClient}
}

// CreateScheduleRequest represents the request to create a scheduled scan
type CreateScheduleRequest struct {
	Name           string      `json:"name"`
	CronExpr       string      `json:"cron_expr"`
	ScanType       string      `json:"scan_type"`
	TargetAssetIDs []uuid.UUID `json:"target_asset_ids,omitempty"`
	CredentialIDs  []uuid.UUID `json:"credential_ids,omitempty"`
	Config         string      `json:"config,omitempty"`
}

func (r CreateScheduleRequest) Validate() map[string]string {
	errors := make(map[string]string)
	if r.Name == "" {
		errors["name"] = "Name is required"
	}
	if r.CronExpr == "" {
		errors["cron_expr"] = "Cron expression is required"
	} else if err := util.ValidateCronExpr(r.CronExpr); err != nil {
		errors["cron_expr"] = err.Error()
	}
	if r.ScanType == "" {
		errors["scan_type"] = "Scan type is required"
	}
	validTypes := map[string]bool{
		"discovery": true, "port_scan": true, "http_probe": true,
		"crawl": true, "vuln_check": true, "full": true,
	}
	if !validTypes[r.ScanType] {
		errors["scan_type"] = "Invalid scan type"
	}
	return errors
}

// UpdateScheduleRequest represents the request to update a scheduled scan
type UpdateScheduleRequest struct {
	Name           *string      `json:"name,omitempty"`
	CronExpr       *string      `json:"cron_expr,omitempty"`
	IsEnabled      *bool        `json:"is_enabled,omitempty"`
	TargetAssetIDs *[]uuid.UUID `json:"target_asset_ids,omitempty"`
	CredentialIDs  *[]uuid.UUID `json:"credential_ids,omitempty"`
	Config         *string      `json:"config,omitempty"`
}

// ScheduleResponse represents a scheduled scan in API responses
type ScheduleResponse struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	CronExpr       string      `json:"cron_expr"`
	ScanType       string      `json:"scan_type"`
	IsEnabled      bool        `json:"is_enabled"`
	TargetAssetIDs []uuid.UUID `json:"target_asset_ids,omitempty"`
	CredentialIDs  []uuid.UUID `json:"credential_ids,omitempty"`
	NextRunAt      int64       `json:"next_run_at"`
	LastRunAt      *int64      `json:"last_run_at,omitempty"`
	LastScanID     *string     `json:"last_scan_id,omitempty"`
	CreatedAt      string      `json:"created_at"`
	UpdatedAt      string      `json:"updated_at"`
}

func toScheduleResponse(s models.ScheduledScan) ScheduleResponse {
	resp := ScheduleResponse{
		ID:             s.ID.String(),
		Name:           s.Name,
		CronExpr:       s.CronExpr,
		ScanType:       string(s.ScanType),
		IsEnabled:      s.IsEnabled,
		TargetAssetIDs: s.TargetAssetIDs,
		CredentialIDs:  s.CredentialIDs,
		NextRunAt:      s.NextRunAt,
		LastRunAt:      s.LastRunAt,
		CreatedAt:      s.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      s.UpdatedAt.Format(time.RFC3339),
	}
	if s.LastScanID != nil {
		id := s.LastScanID.String()
		resp.LastScanID = &id
	}
	return resp
}

// Create creates a new scheduled scan
func (h *ScheduleHandler) Create(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	if orgID == uuid.Nil {
		writeJSON(w, http.StatusUnauthorized, dto.ErrorResponse{Error: "Unauthorized"})
		return
	}

	var req CreateScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	if errors := req.Validate(); len(errors) > 0 {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Validation failed", Details: errors})
		return
	}

	// Calculate next run time
	nextRun, err := util.NextCronTime(req.CronExpr, time.Now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid cron expression"})
		return
	}

	schedule := models.ScheduledScan{
		OrganizationID: orgID,
		Name:           req.Name,
		CronExpr:       req.CronExpr,
		ScanType:       models.ScanType(req.ScanType),
		IsEnabled:      true,
		TargetAssetIDs: req.TargetAssetIDs,
		CredentialIDs:  req.CredentialIDs,
		NextRunAt:      nextRun.Unix(),
		Config:         req.Config,
	}

	if err := h.db.Create(&schedule).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to create schedule"})
		return
	}

	writeJSON(w, http.StatusCreated, toScheduleResponse(schedule))
}

// List returns all scheduled scans for the organization
func (h *ScheduleHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	if orgID == uuid.Nil {
		writeJSON(w, http.StatusUnauthorized, dto.ErrorResponse{Error: "Unauthorized"})
		return
	}

	var schedules []models.ScheduledScan
	if err := h.db.Where("organization_id = ?", orgID).
		Order("created_at DESC").
		Find(&schedules).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to fetch schedules"})
		return
	}

	response := make([]ScheduleResponse, len(schedules))
	for i, s := range schedules {
		response[i] = toScheduleResponse(s)
	}

	writeJSON(w, http.StatusOK, response)
}

// Get returns a specific scheduled scan
func (h *ScheduleHandler) Get(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	if orgID == uuid.Nil {
		writeJSON(w, http.StatusUnauthorized, dto.ErrorResponse{Error: "Unauthorized"})
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid schedule ID"})
		return
	}

	var schedule models.ScheduledScan
	if err := h.db.Where("id = ? AND organization_id = ?", id, orgID).
		First(&schedule).Error; err != nil {
		writeJSON(w, http.StatusNotFound, dto.ErrorResponse{Error: "Schedule not found"})
		return
	}

	writeJSON(w, http.StatusOK, toScheduleResponse(schedule))
}

// Update updates a scheduled scan
func (h *ScheduleHandler) Update(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	if orgID == uuid.Nil {
		writeJSON(w, http.StatusUnauthorized, dto.ErrorResponse{Error: "Unauthorized"})
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid schedule ID"})
		return
	}

	var schedule models.ScheduledScan
	if err := h.db.Where("id = ? AND organization_id = ?", id, orgID).
		First(&schedule).Error; err != nil {
		writeJSON(w, http.StatusNotFound, dto.ErrorResponse{Error: "Schedule not found"})
		return
	}

	var req UpdateScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	// Apply updates
	if req.Name != nil {
		schedule.Name = *req.Name
	}
	if req.CronExpr != nil {
		if err := util.ValidateCronExpr(*req.CronExpr); err != nil {
			writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid cron expression"})
			return
		}
		schedule.CronExpr = *req.CronExpr
		// Recalculate next run time
		nextRun, _ := util.NextCronTime(*req.CronExpr, time.Now())
		schedule.NextRunAt = nextRun.Unix()
	}
	if req.IsEnabled != nil {
		schedule.IsEnabled = *req.IsEnabled
	}
	if req.TargetAssetIDs != nil {
		schedule.TargetAssetIDs = *req.TargetAssetIDs
	}
	if req.CredentialIDs != nil {
		schedule.CredentialIDs = *req.CredentialIDs
	}
	if req.Config != nil {
		schedule.Config = *req.Config
	}

	if err := h.db.Save(&schedule).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to update schedule"})
		return
	}

	writeJSON(w, http.StatusOK, toScheduleResponse(schedule))
}

// Delete soft-deletes a scheduled scan
func (h *ScheduleHandler) Delete(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	if orgID == uuid.Nil {
		writeJSON(w, http.StatusUnauthorized, dto.ErrorResponse{Error: "Unauthorized"})
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid schedule ID"})
		return
	}

	result := h.db.Where("id = ? AND organization_id = ?", id, orgID).
		Delete(&models.ScheduledScan{})
	if result.Error != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to delete schedule"})
		return
	}
	if result.RowsAffected == 0 {
		writeJSON(w, http.StatusNotFound, dto.ErrorResponse{Error: "Schedule not found"})
		return
	}

	writeJSON(w, http.StatusOK, dto.SuccessResponse{Message: "Schedule deleted"})
}

// Trigger manually triggers a scheduled scan to run immediately
func (h *ScheduleHandler) Trigger(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	if orgID == uuid.Nil {
		writeJSON(w, http.StatusUnauthorized, dto.ErrorResponse{Error: "Unauthorized"})
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid schedule ID"})
		return
	}

	var schedule models.ScheduledScan
	if err := h.db.Where("id = ? AND organization_id = ?", id, orgID).
		First(&schedule).Error; err != nil {
		writeJSON(w, http.StatusNotFound, dto.ErrorResponse{Error: "Schedule not found"})
		return
	}

	// Create a scan from the schedule
	scan := models.Scan{
		OrganizationID: schedule.OrganizationID,
		Type:           schedule.ScanType,
		Status:         models.ScanStatusPending,
		TargetAssetIDs: schedule.TargetAssetIDs,
		CredentialIDs:  schedule.CredentialIDs,
		Config:         schedule.Config,
	}

	if err := h.db.Create(&scan).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Failed to create scan"})
		return
	}

	// Enqueue the task
	if h.asynqClient != nil {
		task, err := createScanTask(scan)
		if err == nil {
			info, err := h.asynqClient.Enqueue(task)
			if err == nil {
				_ = h.db.Model(&scan).Update("task_id", info.ID)
			}
		}
	}

	// Update schedule's last run info
	now := time.Now().Unix()
	_ = h.db.Model(&schedule).Updates(map[string]interface{}{
		"last_run_at":  now,
		"last_scan_id": scan.ID,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Scan triggered",
		"scan_id": scan.ID.String(),
	})
}

// createScanTask creates an asynq task for a scan
func createScanTask(scan models.Scan) (*asynq.Task, error) {
	switch scan.Type {
	case models.ScanTypeDiscovery:
		return tasks.NewAssetDiscoveryTask(tasks.AssetDiscoveryPayload{
			ScanID:         scan.ID,
			OrganizationID: scan.OrganizationID,
			CredentialIDs:  scan.CredentialIDs,
		})
	case models.ScanTypePortScan:
		return tasks.NewPortScanTask(tasks.PortScanPayload{
			ScanID:         scan.ID,
			OrganizationID: scan.OrganizationID,
			AssetIDs:       scan.TargetAssetIDs,
		})
	case models.ScanTypeHTTPProbe:
		return tasks.NewHTTPProbeTask(tasks.HTTPProbePayload{
			ScanID:         scan.ID,
			OrganizationID: scan.OrganizationID,
			AssetIDs:       scan.TargetAssetIDs,
		})
	case models.ScanTypeCrawl:
		return tasks.NewCrawlTask(tasks.CrawlPayload{
			ScanID:         scan.ID,
			OrganizationID: scan.OrganizationID,
			AssetIDs:       scan.TargetAssetIDs,
		})
	case models.ScanTypeVulnCheck:
		return tasks.NewVulnCheckTask(tasks.VulnCheckPayload{
			ScanID:         scan.ID,
			OrganizationID: scan.OrganizationID,
			AssetIDs:       scan.TargetAssetIDs,
		})
	default:
		return nil, nil
	}
}
