package assets

import (
	"github.com/hugh/go-hunter/internal/assets/types"
)

// Re-export credential types for backward compatibility
type (
	AWSCredential          = types.AWSCredential
	GCPCredential          = types.GCPCredential
	AzureCredential        = types.AzureCredential
	DigitalOceanCredential = types.DigitalOceanCredential
	CloudflareCredential   = types.CloudflareCredential
)
