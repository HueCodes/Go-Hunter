package models

import "github.com/google/uuid"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type FindingStatus string

const (
	FindingStatusOpen          FindingStatus = "open"
	FindingStatusAcknowledged  FindingStatus = "acknowledged"
	FindingStatusFixed         FindingStatus = "fixed"
	FindingStatusFalsePositive FindingStatus = "false_positive"
	FindingStatusAccepted      FindingStatus = "accepted" // Risk accepted
)

type Finding struct {
	Base
	OrganizationID uuid.UUID `gorm:"type:uuid;index;not null" json:"organization_id"`
	AssetID        uuid.UUID `gorm:"type:uuid;index;not null" json:"asset_id"`
	ScanID         uuid.UUID `gorm:"type:uuid;index" json:"scan_id,omitempty"`

	// Finding details
	Title       string        `gorm:"not null" json:"title"`
	Description string        `json:"description,omitempty"`
	Severity    Severity      `gorm:"not null;index" json:"severity"`
	Status      FindingStatus `gorm:"not null;index;default:'open'" json:"status"`

	// Categorization
	Type     string `gorm:"index" json:"type"`  // open_port, exposed_bucket, xss, etc.
	Category string `json:"category,omitempty"` // network, cloud, web, etc.

	// Evidence
	Evidence string `gorm:"type:text" json:"evidence,omitempty"`
	RawData  string `gorm:"type:jsonb;default:'{}'" json:"raw_data,omitempty"`

	// Port-specific (if applicable)
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // tcp, udp
	Service  string `json:"service,omitempty"`  // http, ssh, mysql, etc.
	Banner   string `json:"banner,omitempty"`

	// Remediation
	Remediation string `gorm:"type:text" json:"remediation,omitempty"`
	References  string `gorm:"type:jsonb;default:'[]'" json:"references,omitempty"` // JSON array of URLs

	// Tracking
	FirstSeenAt int64      `json:"first_seen_at"`
	LastSeenAt  int64      `json:"last_seen_at"`
	ResolvedAt  int64      `json:"resolved_at,omitempty"`
	ResolvedBy  *uuid.UUID `gorm:"type:uuid" json:"resolved_by,omitempty"`

	// Deduplication hash
	Hash string `gorm:"uniqueIndex" json:"-"`

	// Relationships
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"-"`
	Asset        *Asset        `gorm:"foreignKey:AssetID" json:"asset,omitempty"`
	Scan         *Scan         `gorm:"foreignKey:ScanID" json:"-"`
}

func (Finding) TableName() string {
	return "findings"
}
