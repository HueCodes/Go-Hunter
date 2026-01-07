package assets

import (
	"context"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/database/models"
)

// CredentialManager defines the interface for cloud credential operations.
type CredentialManager interface {
	CreateCredential(ctx context.Context, orgID uuid.UUID, name string, provider models.CloudProvider, credData interface{}) (*models.CloudCredential, error)
	GetCredential(ctx context.Context, orgID, credID uuid.UUID) (*models.CloudCredential, error)
	ListCredentials(ctx context.Context, orgID uuid.UUID) ([]models.CloudCredential, error)
	DeleteCredential(ctx context.Context, orgID, credID uuid.UUID) error
	ValidateCredential(ctx context.Context, orgID, credID uuid.UUID) error
}

// AssetDiscoverer defines the interface for asset discovery operations.
type AssetDiscoverer interface {
	DiscoverAssets(ctx context.Context, orgID uuid.UUID, credIDs []uuid.UUID) ([]DiscoveredAsset, error)
	SaveDiscoveredAssets(ctx context.Context, orgID uuid.UUID, credID *uuid.UUID, discovered []DiscoveredAsset) (int, error)
}

// AssetService combines both credential management and asset discovery.
type AssetService interface {
	CredentialManager
	AssetDiscoverer
}

// Compile-time interface satisfaction checks
var (
	_ CredentialManager = (*Service)(nil)
	_ AssetDiscoverer   = (*Service)(nil)
	_ AssetService      = (*Service)(nil)
)
