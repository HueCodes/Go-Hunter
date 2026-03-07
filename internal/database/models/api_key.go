package models

import "github.com/google/uuid"

type APIKey struct {
	Base
	Name           string    `gorm:"not null" json:"name"`
	KeyHash        string    `gorm:"not null;uniqueIndex" json:"-"`
	KeyPrefix      string    `gorm:"not null;size:8" json:"key_prefix"`
	UserID         uuid.UUID `gorm:"type:uuid;index;not null" json:"user_id"`
	OrganizationID uuid.UUID `gorm:"type:uuid;index;not null" json:"organization_id"`
	Role           string    `gorm:"default:'member'" json:"role"`
	IsActive       bool      `gorm:"default:true" json:"is_active"`
	LastUsedAt     int64     `json:"last_used_at,omitempty"`
	ExpiresAt      int64     `json:"expires_at,omitempty"`

	User         *User         `gorm:"foreignKey:UserID" json:"-"`
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"-"`
}

func (APIKey) TableName() string {
	return "api_keys"
}
