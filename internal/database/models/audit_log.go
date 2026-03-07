package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AuditLog struct {
	ID             uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
	OrganizationID uuid.UUID  `gorm:"type:uuid;index;not null" json:"organization_id"`
	UserID         *uuid.UUID `gorm:"type:uuid;index" json:"user_id,omitempty"`
	Action         string     `gorm:"not null;index" json:"action"`
	ResourceType   string     `gorm:"not null" json:"resource_type"`
	ResourceID     string     `json:"resource_id,omitempty"`
	Details        string     `gorm:"type:text" json:"details,omitempty"`
	IPAddress      string     `json:"ip_address,omitempty"`
	UserAgent      string     `json:"user_agent,omitempty"`
	AuthMethod     string     `json:"auth_method,omitempty"`
	CreatedAt      time.Time  `gorm:"index" json:"created_at"`
}

func (AuditLog) TableName() string {
	return "audit_logs"
}

func (a *AuditLog) BeforeCreate(tx *gorm.DB) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	return nil
}
