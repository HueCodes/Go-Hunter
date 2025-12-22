package models

import "github.com/google/uuid"

type AssetType string

const (
	AssetTypeDomain    AssetType = "domain"
	AssetTypeSubdomain AssetType = "subdomain"
	AssetTypeIP        AssetType = "ip"
	AssetTypeCIDR      AssetType = "cidr"
	AssetTypeBucket    AssetType = "bucket"
	AssetTypeContainer AssetType = "container"
	AssetTypeEndpoint  AssetType = "endpoint"
)

type Asset struct {
	Base
	OrganizationID uuid.UUID `gorm:"type:uuid;index;not null" json:"organization_id"`
	CredentialID   uuid.UUID `gorm:"type:uuid;index" json:"credential_id,omitempty"`

	Type  AssetType `gorm:"not null;index" json:"type"`
	Value string    `gorm:"not null" json:"value"` // domain, IP, bucket name, etc.

	// Discovery metadata
	Source       string `json:"source,omitempty"` // manual, aws_discovery, dns_enum, etc.
	DiscoveredAt int64  `json:"discovered_at"`
	LastSeenAt   int64  `json:"last_seen_at"`
	IsActive     bool   `gorm:"default:true;index" json:"is_active"`

	// Additional metadata (JSON)
	Metadata string `gorm:"type:jsonb;default:'{}'" json:"metadata,omitempty"`

	// Parent relationship (e.g., subdomain -> domain)
	ParentID *uuid.UUID `gorm:"type:uuid;index" json:"parent_id,omitempty"`

	// Relationships
	Organization *Organization    `gorm:"foreignKey:OrganizationID" json:"-"`
	Credential   *CloudCredential `gorm:"foreignKey:CredentialID" json:"-"`
	Parent       *Asset           `gorm:"foreignKey:ParentID" json:"-"`
	Children     []Asset          `gorm:"foreignKey:ParentID" json:"-"`
	Findings     []Finding        `gorm:"foreignKey:AssetID" json:"-"`
}

func (Asset) TableName() string {
	return "assets"
}

// UniqueIndex for preventing duplicates
func (Asset) UniqueConstraint() string {
	return "idx_assets_org_type_value"
}
