package assets

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/assets/aws"
	"github.com/hugh/go-hunter/internal/assets/azure"
	"github.com/hugh/go-hunter/internal/assets/cloudflare"
	"github.com/hugh/go-hunter/internal/assets/digitalocean"
	"github.com/hugh/go-hunter/internal/assets/gcp"
	"github.com/hugh/go-hunter/internal/database/models"
	"github.com/hugh/go-hunter/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Service handles cloud credential management and asset discovery
type Service struct {
	db        *gorm.DB
	encryptor *crypto.Encryptor
	logger    *slog.Logger
	cfg       ProviderConfig
}

// NewService creates a new asset service
func NewService(db *gorm.DB, encryptor *crypto.Encryptor, logger *slog.Logger) *Service {
	return &Service{
		db:        db,
		encryptor: encryptor,
		logger:    logger,
		cfg:       DefaultProviderConfig(),
	}
}

// CreateCredential encrypts and stores a new cloud credential
func (s *Service) CreateCredential(ctx context.Context, orgID uuid.UUID, name string, provider models.CloudProvider, credData interface{}) (*models.CloudCredential, error) {
	// Serialize credential data to JSON
	jsonData, err := json.Marshal(credData)
	if err != nil {
		return nil, fmt.Errorf("serializing credentials: %w", err)
	}

	// Encrypt the credential data
	encrypted, err := s.encryptor.Encrypt(jsonData)
	if err != nil {
		return nil, fmt.Errorf("encrypting credentials: %w", err)
	}

	cred := &models.CloudCredential{
		OrganizationID: orgID,
		Name:           name,
		Provider:       provider,
		EncryptedData:  encrypted,
		IsActive:       true,
	}

	if err := s.db.WithContext(ctx).Create(cred).Error; err != nil {
		return nil, fmt.Errorf("saving credential: %w", err)
	}

	s.logger.Info("created credential",
		"id", cred.ID,
		"name", name,
		"provider", provider,
	)

	return cred, nil
}

// GetCredential retrieves a credential by ID (encrypted data not decrypted)
func (s *Service) GetCredential(ctx context.Context, orgID, credID uuid.UUID) (*models.CloudCredential, error) {
	var cred models.CloudCredential
	if err := s.db.WithContext(ctx).
		Where("id = ? AND organization_id = ?", credID, orgID).
		First(&cred).Error; err != nil {
		return nil, err
	}
	return &cred, nil
}

// ListCredentials returns all credentials for an organization (without decrypted data)
func (s *Service) ListCredentials(ctx context.Context, orgID uuid.UUID) ([]models.CloudCredential, error) {
	var creds []models.CloudCredential
	if err := s.db.WithContext(ctx).
		Where("organization_id = ?", orgID).
		Order("created_at DESC").
		Find(&creds).Error; err != nil {
		return nil, err
	}

	// Clear encrypted data from response
	for i := range creds {
		creds[i].EncryptedData = nil
	}

	return creds, nil
}

// DeleteCredential removes a credential
func (s *Service) DeleteCredential(ctx context.Context, orgID, credID uuid.UUID) error {
	result := s.db.WithContext(ctx).
		Where("id = ? AND organization_id = ?", credID, orgID).
		Delete(&models.CloudCredential{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ValidateCredential tests if a credential is valid
func (s *Service) ValidateCredential(ctx context.Context, orgID, credID uuid.UUID) error {
	cred, err := s.GetCredential(ctx, orgID, credID)
	if err != nil {
		return err
	}

	provider, err := s.getProvider(cred)
	if err != nil {
		return err
	}

	return provider.ValidateCredentials(ctx)
}

// DiscoverAssets runs asset discovery for the given credentials
func (s *Service) DiscoverAssets(ctx context.Context, orgID uuid.UUID, credIDs []uuid.UUID) ([]DiscoveredAsset, error) {
	var allAssets []DiscoveredAsset

	for _, credID := range credIDs {
		cred, err := s.GetCredential(ctx, orgID, credID)
		if err != nil {
			s.logger.Error("failed to get credential", "id", credID, "error", err)
			continue
		}

		if !cred.IsActive {
			s.logger.Warn("skipping inactive credential", "id", credID)
			continue
		}

		provider, err := s.getProvider(cred)
		if err != nil {
			s.logger.Error("failed to create provider", "id", credID, "error", err)
			continue
		}

		// Validate credentials first
		if err := provider.ValidateCredentials(ctx); err != nil {
			s.logger.Error("invalid credentials", "id", credID, "error", err)
			continue
		}

		// Run discovery
		assets, err := provider.Discover(ctx)
		if err != nil {
			s.logger.Error("discovery failed", "id", credID, "error", err)
			continue
		}

		allAssets = append(allAssets, assets...)

		// Update last used timestamp
		s.db.Model(cred).Update("last_used", time.Now().Unix())
	}

	return allAssets, nil
}

// SaveDiscoveredAssets stores discovered assets in the database
func (s *Service) SaveDiscoveredAssets(ctx context.Context, orgID uuid.UUID, credID *uuid.UUID, discovered []DiscoveredAsset) (int, error) {
	now := time.Now().Unix()
	saved := 0

	for _, d := range discovered {
		// Convert metadata to JSON
		metadataJSON, _ := json.Marshal(d.Metadata)

		asset := models.Asset{
			OrganizationID: orgID,
			Type:           d.Type,
			Value:          d.Value,
			Source:         d.Source,
			Metadata:       string(metadataJSON),
			DiscoveredAt:   now,
			LastSeenAt:     now,
			IsActive:       true,
			ParentID:       d.ParentID,
		}

		if credID != nil {
			asset.CredentialID = *credID
		}

		// First, try to reactivate a soft-deleted asset if it exists
		reactivated := s.db.WithContext(ctx).Unscoped().
			Model(&models.Asset{}).
			Where("organization_id = ? AND type = ? AND value = ? AND deleted_at IS NOT NULL", orgID, d.Type, d.Value).
			Updates(map[string]interface{}{
				"deleted_at":   nil,
				"last_seen_at": now,
				"source":       d.Source,
				"metadata":     string(metadataJSON),
				"is_active":    true,
			})

		if reactivated.RowsAffected > 0 {
			s.logger.Debug("reactivated soft-deleted asset",
				"type", d.Type,
				"value", d.Value,
			)
			saved++
			continue
		}

		// Upsert: update if exists, create if not
		result := s.db.WithContext(ctx).Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "organization_id"},
				{Name: "type"},
				{Name: "value"},
			},
			DoUpdates: clause.AssignmentColumns([]string{
				"last_seen_at",
				"source",
				"metadata",
				"is_active",
			}),
		}).Create(&asset)

		if result.Error != nil {
			s.logger.Error("failed to save asset",
				"type", d.Type,
				"value", d.Value,
				"error", result.Error,
			)
			continue
		}
		saved++
	}

	s.logger.Info("saved discovered assets",
		"total", len(discovered),
		"saved", saved,
	)

	return saved, nil
}

// getProvider creates a provider instance from a credential
func (s *Service) getProvider(cred *models.CloudCredential) (Provider, error) {
	// Decrypt credential data
	decrypted, err := s.encryptor.Decrypt(cred.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("decrypting credentials: %w", err)
	}

	switch cred.Provider {
	case models.ProviderAWS:
		var awsCred AWSCredential
		if err := json.Unmarshal(decrypted, &awsCred); err != nil {
			return nil, fmt.Errorf("parsing AWS credentials: %w", err)
		}
		return aws.New(awsCred, s.cfg, s.logger), nil

	case models.ProviderGCP:
		var gcpCred GCPCredential
		if err := json.Unmarshal(decrypted, &gcpCred); err != nil {
			return nil, fmt.Errorf("parsing GCP credentials: %w", err)
		}
		return gcp.New(gcpCred, s.cfg, s.logger), nil

	case models.ProviderAzure:
		var azureCred AzureCredential
		if err := json.Unmarshal(decrypted, &azureCred); err != nil {
			return nil, fmt.Errorf("parsing Azure credentials: %w", err)
		}
		return azure.New(azureCred, s.cfg, s.logger), nil

	case models.ProviderDigitalOcean:
		var doCred DigitalOceanCredential
		if err := json.Unmarshal(decrypted, &doCred); err != nil {
			return nil, fmt.Errorf("parsing DigitalOcean credentials: %w", err)
		}
		return digitalocean.New(doCred, s.cfg, s.logger), nil

	case models.ProviderCloudflare:
		var cfCred CloudflareCredential
		if err := json.Unmarshal(decrypted, &cfCred); err != nil {
			return nil, fmt.Errorf("parsing Cloudflare credentials: %w", err)
		}
		return cloudflare.New(cfCred, s.cfg, s.logger), nil

	default:
		return nil, fmt.Errorf("unsupported provider: %s", cred.Provider)
	}
}
