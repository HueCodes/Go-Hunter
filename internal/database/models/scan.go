package models

import "github.com/google/uuid"

type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
)

type ScanType string

const (
	ScanTypeDiscovery   ScanType = "discovery"   // Asset discovery from cloud
	ScanTypePortScan    ScanType = "port_scan"
	ScanTypeHTTPProbe   ScanType = "http_probe"
	ScanTypeCrawl       ScanType = "crawl"
	ScanTypeVulnCheck   ScanType = "vuln_check"
	ScanTypeFull        ScanType = "full" // All of the above
)

type Scan struct {
	Base
	OrganizationID uuid.UUID  `gorm:"type:uuid;index;not null" json:"organization_id"`
	Type           ScanType   `gorm:"not null" json:"type"`
	Status         ScanStatus `gorm:"not null;index;default:'pending'" json:"status"`

	// Scope
	TargetAssetIDs []uuid.UUID `gorm:"type:uuid[];serializer:json" json:"target_asset_ids,omitempty"`
	CredentialIDs  []uuid.UUID `gorm:"type:uuid[];serializer:json" json:"credential_ids,omitempty"`

	// Execution
	StartedAt   int64  `json:"started_at,omitempty"`
	CompletedAt int64  `json:"completed_at,omitempty"`
	Error       string `json:"error,omitempty"`

	// Stats
	AssetsScanned  int `gorm:"default:0" json:"assets_scanned"`
	FindingsCount  int `gorm:"default:0" json:"findings_count"`
	PortsOpen      int `gorm:"default:0" json:"ports_open"`
	ServicesFound  int `gorm:"default:0" json:"services_found"`

	// Configuration (JSON)
	Config string `gorm:"type:jsonb;default:'{}'" json:"config,omitempty"`

	// Asynq task ID for tracking
	TaskID string `gorm:"index" json:"task_id,omitempty"`

	// Relationships
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"-"`
	Findings     []Finding     `gorm:"foreignKey:ScanID" json:"-"`
}

func (Scan) TableName() string {
	return "scans"
}
