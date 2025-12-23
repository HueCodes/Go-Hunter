package assets

import (
	"github.com/hugh/go-hunter/internal/assets/types"
)

// Re-export types for backward compatibility
type (
	DiscoveredAsset = types.DiscoveredAsset
	Provider        = types.Provider
	ProviderConfig  = types.ProviderConfig
	DiscoveryResult = types.DiscoveryResult
	DiscoveryError  = types.DiscoveryError
)

// DefaultProviderConfig returns sensible defaults
func DefaultProviderConfig() ProviderConfig {
	return types.DefaultProviderConfig()
}
