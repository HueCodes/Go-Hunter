package models

import "github.com/google/uuid"

type Organization struct {
	Base
	Name        string `gorm:"not null" json:"name"`
	Slug        string `gorm:"uniqueIndex;not null" json:"slug"`
	Plan        string `gorm:"default:'free'" json:"plan"` // free, pro, enterprise
	MaxUsers    int    `gorm:"default:5" json:"max_users"`
	MaxAssets   int    `gorm:"default:100" json:"max_assets"`
	MaxScansDay int    `gorm:"default:10" json:"max_scans_day"`

	// Relationships
	Users            []User            `gorm:"foreignKey:OrganizationID" json:"-"`
	CloudCredentials []CloudCredential `gorm:"foreignKey:OrganizationID" json:"-"`
	Assets           []Asset           `gorm:"foreignKey:OrganizationID" json:"-"`
	Scans            []Scan            `gorm:"foreignKey:OrganizationID" json:"-"`
}

func (Organization) TableName() string {
	return "organizations"
}

type OrgMembership struct {
	UserID         uuid.UUID `gorm:"type:uuid;primaryKey"`
	OrganizationID uuid.UUID `gorm:"type:uuid;primaryKey"`
	Role           string    `gorm:"not null;default:'member'"` // owner, admin, member
}

func (OrgMembership) TableName() string {
	return "org_memberships"
}
