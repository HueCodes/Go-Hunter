package models

import "github.com/google/uuid"

// ScheduledScan represents a recurring scan schedule
type ScheduledScan struct {
	Base
	OrganizationID uuid.UUID `gorm:"type:uuid;index;not null" json:"organization_id"`
	Name           string    `gorm:"size:255;not null" json:"name"`
	CronExpr       string    `gorm:"size:100;not null" json:"cron_expr"` // e.g., "0 2 * * *" (2 AM daily)
	ScanType       ScanType  `gorm:"not null" json:"scan_type"`
	IsEnabled      bool      `gorm:"default:true;index" json:"is_enabled"`

	// Scope
	TargetAssetIDs []uuid.UUID `gorm:"type:uuid[];serializer:json" json:"target_asset_ids,omitempty"`
	CredentialIDs  []uuid.UUID `gorm:"type:uuid[];serializer:json" json:"credential_ids,omitempty"`

	// Timing (Unix timestamps, UTC)
	NextRunAt  int64      `gorm:"index" json:"next_run_at"`
	LastRunAt  *int64     `json:"last_run_at,omitempty"`
	LastScanID *uuid.UUID `gorm:"type:uuid" json:"last_scan_id,omitempty"`

	// Configuration (JSON)
	Config string `gorm:"type:jsonb;default:'{}'" json:"config,omitempty"`

	// Relationships
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"-"`
	LastScan     *Scan         `gorm:"foreignKey:LastScanID" json:"-"`
}

func (ScheduledScan) TableName() string {
	return "scheduled_scans"
}
