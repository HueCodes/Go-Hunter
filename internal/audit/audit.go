package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/api/middleware"
	"github.com/hugh/go-hunter/internal/database/models"
	"gorm.io/gorm"
)

const (
	ActionLogin              = "auth.login"
	ActionLoginFailed        = "auth.login_failed"
	ActionLogout             = "auth.logout"
	ActionRegister           = "auth.register"
	ActionUserCreated        = "user.created"
	ActionCredentialCreated  = "credential.created"  // #nosec G101 -- Not a credential, this is an audit event name
	ActionCredentialDeleted  = "credential.deleted"  // #nosec G101 -- Not a credential, this is an audit event name
	ActionCredentialTested   = "credential.tested"   // #nosec G101 -- Not a credential, this is an audit event name
	ActionScanCreated        = "scan.created"
	ActionScanCancelled      = "scan.cancelled"
	ActionAPIKeyCreated      = "apikey.created"
	ActionAPIKeyRevoked      = "apikey.revoked"
	ActionAPIKeyDeleted      = "apikey.deleted"
	ActionFindingUpdated     = "finding.status_updated"
	ActionScheduleCreated    = "schedule.created"
	ActionScheduleUpdated    = "schedule.updated"
	ActionScheduleDeleted    = "schedule.deleted"
	ActionScheduleTriggered  = "schedule.triggered"
)

type Logger struct {
	db *gorm.DB
}

func NewLogger(db *gorm.DB) *Logger {
	return &Logger{db: db}
}

type Event struct {
	Action       string
	ResourceType string
	ResourceID   string
	Details      map[string]interface{}
}

func (l *Logger) Log(ctx context.Context, event Event) {
	orgID := middleware.GetOrganizationID(ctx)
	userID := middleware.GetUserID(ctx)
	authMethod := middleware.GetAuthMethod(ctx)

	entry := models.AuditLog{
		OrganizationID: orgID,
		Action:         event.Action,
		ResourceType:   event.ResourceType,
		ResourceID:     event.ResourceID,
		AuthMethod:     authMethod,
	}

	if userID != uuid.Nil {
		entry.UserID = &userID
	}

	if event.Details != nil {
		detailsJSON, _ := json.Marshal(event.Details)
		entry.Details = string(detailsJSON)
	}

	if err := l.db.Create(&entry).Error; err != nil {
		slog.ErrorContext(ctx, "failed to write audit log", "error", err, "action", event.Action)
	}
}

func (l *Logger) LogHTTP(r *http.Request, event Event) {
	orgID := middleware.GetOrganizationID(r.Context())
	userID := middleware.GetUserID(r.Context())
	authMethod := middleware.GetAuthMethod(r.Context())

	ip := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = forwarded
	}

	entry := models.AuditLog{
		OrganizationID: orgID,
		Action:         event.Action,
		ResourceType:   event.ResourceType,
		ResourceID:     event.ResourceID,
		IPAddress:      ip,
		UserAgent:      r.UserAgent(),
		AuthMethod:     authMethod,
	}

	if userID != uuid.Nil {
		entry.UserID = &userID
	}

	if event.Details != nil {
		detailsJSON, _ := json.Marshal(event.Details)
		entry.Details = string(detailsJSON)
	}

	if err := l.db.Create(&entry).Error; err != nil {
		slog.ErrorContext(r.Context(), "failed to write audit log", "error", err, "action", event.Action)
	}
}

func (l *Logger) List(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]models.AuditLog, int64, error) {
	var logs []models.AuditLog
	var total int64

	query := l.db.Model(&models.AuditLog{}).Where("organization_id = ?", orgID)
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	if err := query.Order("created_at DESC").
		Limit(limit).Offset(offset).
		Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}
