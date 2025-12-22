package models

import "github.com/google/uuid"

type CloudProvider string

const (
	ProviderAWS          CloudProvider = "aws"
	ProviderGCP          CloudProvider = "gcp"
	ProviderAzure        CloudProvider = "azure"
	ProviderDigitalOcean CloudProvider = "digitalocean"
	ProviderCloudflare   CloudProvider = "cloudflare"
)

type CloudCredential struct {
	Base
	OrganizationID uuid.UUID     `gorm:"type:uuid;index;not null" json:"organization_id"`
	Name           string        `gorm:"not null" json:"name"`
	Provider       CloudProvider `gorm:"not null" json:"provider"`

	// Encrypted credentials (age encrypted blob)
	EncryptedData []byte `gorm:"type:bytea;not null" json:"-"`

	// Metadata (not sensitive)
	Region   string `json:"region,omitempty"`
	IsActive bool   `gorm:"default:true" json:"is_active"`
	LastUsed int64  `json:"last_used,omitempty"`

	// Relationships
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"-"`
	Assets       []Asset       `gorm:"foreignKey:CredentialID" json:"-"`
}

func (CloudCredential) TableName() string {
	return "cloud_credentials"
}
