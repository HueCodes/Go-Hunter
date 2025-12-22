package models

import "github.com/google/uuid"

type User struct {
	Base
	Email          string    `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash   string    `gorm:"not null" json:"-"`
	Name           string    `json:"name"`
	OrganizationID uuid.UUID `gorm:"type:uuid;index" json:"organization_id"`
	Role           string    `gorm:"default:'member'" json:"role"` // owner, admin, member
	IsActive       bool      `gorm:"default:true" json:"is_active"`
	EmailVerified  bool      `gorm:"default:false" json:"email_verified"`

	// For magic links (future)
	MagicLinkToken   string `gorm:"index" json:"-"`
	MagicLinkExpires int64  `json:"-"`

	// Relationships
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
}

func (User) TableName() string {
	return "users"
}
