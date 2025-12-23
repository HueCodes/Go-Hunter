package types

import (
	"context"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/database/models"
)

// DiscoveredAsset represents an asset found during cloud discovery
type DiscoveredAsset struct {
	Type     models.AssetType
	Value    string            // IP, domain, bucket name, etc.
	Source   string            // e.g., "aws:ec2", "gcp:compute", "azure:vm"
	Metadata map[string]string // Provider-specific metadata
	ParentID *uuid.UUID        // Optional parent asset reference
}

// Provider defines the interface all cloud providers must implement
type Provider interface {
	// Name returns the provider identifier (e.g., "aws", "gcp", "azure")
	Name() models.CloudProvider

	// ValidateCredentials checks if the credentials are valid
	ValidateCredentials(ctx context.Context) error

	// Discover finds all assets using the configured credentials
	// Returns partial results if some regions/projects fail
	Discover(ctx context.Context) ([]DiscoveredAsset, error)
}

// ProviderConfig holds common configuration for providers
type ProviderConfig struct {
	RateLimitRPS    int // Requests per second limit
	TimeoutSeconds  int // Timeout for API calls
	MaxRetries      int // Maximum retry attempts
	ConcurrentScans int // Number of concurrent region/project scans
}

// DefaultProviderConfig returns sensible defaults
func DefaultProviderConfig() ProviderConfig {
	return ProviderConfig{
		RateLimitRPS:    10,
		TimeoutSeconds:  30,
		MaxRetries:      3,
		ConcurrentScans: 5,
	}
}

// DiscoveryResult wraps discovered assets with any errors encountered
type DiscoveryResult struct {
	Assets []DiscoveredAsset
	Errors []DiscoveryError
}

// DiscoveryError represents a non-fatal error during discovery
type DiscoveryError struct {
	Region   string // Region/project where error occurred
	Resource string // Resource type being discovered
	Message  string // Error description
}

// AWSCredential holds AWS authentication data
type AWSCredential struct {
	AccessKeyID     string   `json:"access_key_id"`
	SecretAccessKey string   `json:"secret_access_key"`
	AssumeRoleARN   string   `json:"assume_role_arn,omitempty"`
	ExternalID      string   `json:"external_id,omitempty"` // For cross-account assume role
	Regions         []string `json:"regions,omitempty"`     // Empty = all regions
}

// GCPCredential holds GCP authentication data
type GCPCredential struct {
	ServiceAccountJSON string   `json:"service_account_json"`
	Projects           []string `json:"projects,omitempty"` // Empty = auto-discover
}

// AzureCredential holds Azure authentication data
type AzureCredential struct {
	TenantID      string   `json:"tenant_id"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	Subscriptions []string `json:"subscriptions,omitempty"` // Empty = all subscriptions
}

// DigitalOceanCredential holds DigitalOcean authentication data
type DigitalOceanCredential struct {
	APIToken string `json:"api_token"`
}

// CloudflareCredential holds Cloudflare authentication data
type CloudflareCredential struct {
	APIToken string   `json:"api_token"`
	APIKey   string   `json:"api_key,omitempty"`  // Legacy API key (optional)
	Email    string   `json:"email,omitempty"`    // Required if using API key
	ZoneIDs  []string `json:"zone_ids,omitempty"` // Empty = all zones
}
