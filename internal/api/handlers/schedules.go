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
	apperrors "github.com/hugh/go-hunter/pkg/errors"
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

type UpdateScheduleRequest struct {
	Name           *string      `json:"name,omitempty"`
	CronExpr       *string      `json:"cron_expr,omitempty"`
	IsEnabled      *bool        `json:"is_enabled,omitempty"`
	TargetAssetIDs *[]uuid.UUID `json:"target_asset_ids,omitempty"`
	CredentialIDs  *[]uuid.UUID `json:"credential_ids,omitempty"`
	Config         *string      `json:"config,omitempty"`
}

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

func (h *ScheduleHandler) Create(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	var req CreateScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid request body"))
		return
	}

	if errs := req.Validate(); len(errs) > 0 {
		apperrors.WriteHTTP(w, r, apperrors.Validation(errs))
		return
	}

	nextRun, err := util.NextCronTime(req.CronExpr, time.Now())
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid cron expression"))
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
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to create schedule", err))
		return
	}

	writeJSON(w, http.StatusCreated, toScheduleResponse(schedule))
}

func (h *ScheduleHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	var schedules []models.ScheduledScan
	if err := h.db.Where("organization_id = ?", orgID).
		Order("created_at DESC").
		Find(&schedules).Error; err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to fetch schedules", err))
		return
	}

	response := make([]ScheduleResponse, len(schedules))
	for i, s := range schedules {
		response[i] = toScheduleResponse(s)
	}

	writeJSON(w, http.StatusOK, response)
}

func (h *ScheduleHandler) Get(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid schedule ID"))
		return
	}

	var schedule models.ScheduledScan
	if err := h.db.Where("id = ? AND organization_id = ?", id, orgID).
		First(&schedule).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			apperrors.WriteHTTP(w, r, apperrors.NotFound("Schedule"))
			return
		}
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to get schedule", err))
		return
	}

	writeJSON(w, http.StatusOK, toScheduleResponse(schedule))
}

func (h *ScheduleHandler) Update(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid schedule ID"))
		return
	}

	var schedule models.ScheduledScan
	if err := h.db.Where("id = ? AND organization_id = ?", id, orgID).
		First(&schedule).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			apperrors.WriteHTTP(w, r, apperrors.NotFound("Schedule"))
			return
		}
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to get schedule", err))
		return
	}

	var req UpdateScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid request body"))
		return
	}

	if req.Name != nil {
		schedule.Name = *req.Name
	}
	if req.CronExpr != nil {
		if err := util.ValidateCronExpr(*req.CronExpr); err != nil {
			apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid cron expression"))
			return
		}
		schedule.CronExpr = *req.CronExpr
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
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to update schedule", err))
		return
	}

	writeJSON(w, http.StatusOK, toScheduleResponse(schedule))
}

func (h *ScheduleHandler) Delete(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid schedule ID"))
		return
	}

	result := h.db.Where("id = ? AND organization_id = ?", id, orgID).
		Delete(&models.ScheduledScan{})
	if result.Error != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to delete schedule", result.Error))
		return
	}
	if result.RowsAffected == 0 {
		apperrors.WriteHTTP(w, r, apperrors.NotFound("Schedule"))
		return
	}

	writeJSON(w, http.StatusOK, dto.SuccessResponse{Message: "Schedule deleted"})
}

func (h *ScheduleHandler) Trigger(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid schedule ID"))
		return
	}

	var schedule models.ScheduledScan
	if err := h.db.Where("id = ? AND organization_id = ?", id, orgID).
		First(&schedule).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			apperrors.WriteHTTP(w, r, apperrors.NotFound("Schedule"))
			return
		}
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to get schedule", err))
		return
	}

	scan := models.Scan{
		OrganizationID: schedule.OrganizationID,
		Type:           schedule.ScanType,
		Status:         models.ScanStatusPending,
		TargetAssetIDs: schedule.TargetAssetIDs,
		CredentialIDs:  schedule.CredentialIDs,
		Config:         schedule.Config,
	}

	if err := h.db.Create(&scan).Error; err != nil {
		apperrors.WriteHTTP(w, r, apperrors.Internal("Failed to create scan", err))
		return
	}

	if h.asynqClient != nil {
		task, err := createScanTask(scan)
		if err == nil && task != nil {
			info, err := h.asynqClient.Enqueue(task)
			if err == nil {
				_ = h.db.Model(&scan).Update("task_id", info.ID)
			}
		}
	}

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
