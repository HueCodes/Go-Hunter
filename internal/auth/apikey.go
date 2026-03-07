package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/database/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	ErrAPIKeyNotFound = errors.New("api key not found")
	ErrAPIKeyExpired  = errors.New("api key expired")
	ErrAPIKeyInactive = errors.New("api key inactive")
)

const apiKeyPrefix = "ghk_"

type APIKeyService struct {
	db *gorm.DB
}

func NewAPIKeyService(db *gorm.DB) *APIKeyService {
	return &APIKeyService{db: db}
}

type CreateAPIKeyInput struct {
	Name           string
	UserID         uuid.UUID
	OrganizationID uuid.UUID
	Role           string
	ExpiresInDays  int
}

type CreateAPIKeyResult struct {
	Key    models.APIKey
	RawKey string
}

func (s *APIKeyService) Create(ctx context.Context, input CreateAPIKeyInput) (*CreateAPIKeyResult, error) {
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return nil, err
	}
	rawKey := apiKeyPrefix + hex.EncodeToString(rawBytes)

	hash, err := bcrypt.GenerateFromPassword([]byte(rawKey), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	var expiresAt int64
	if input.ExpiresInDays > 0 {
		expiresAt = time.Now().AddDate(0, 0, input.ExpiresInDays).Unix()
	}

	role := input.Role
	if role == "" {
		role = "member"
	}

	key := models.APIKey{
		Name:           input.Name,
		KeyHash:        string(hash),
		KeyPrefix:      rawKey[:len(apiKeyPrefix)+4],
		UserID:         input.UserID,
		OrganizationID: input.OrganizationID,
		Role:           role,
		IsActive:       true,
		ExpiresAt:      expiresAt,
	}

	if err := s.db.WithContext(ctx).Create(&key).Error; err != nil {
		return nil, err
	}

	return &CreateAPIKeyResult{Key: key, RawKey: rawKey}, nil
}

func (s *APIKeyService) Validate(ctx context.Context, rawKey string) (*models.APIKey, error) {
	if len(rawKey) < len(apiKeyPrefix)+4 {
		return nil, ErrAPIKeyNotFound
	}

	prefix := rawKey[:len(apiKeyPrefix)+4]

	var keys []models.APIKey
	if err := s.db.WithContext(ctx).
		Where("key_prefix = ? AND is_active = ?", prefix, true).
		Find(&keys).Error; err != nil {
		return nil, err
	}

	for i := range keys {
		if err := bcrypt.CompareHashAndPassword([]byte(keys[i].KeyHash), []byte(rawKey)); err == nil {
			if keys[i].ExpiresAt > 0 && time.Now().Unix() > keys[i].ExpiresAt {
				return nil, ErrAPIKeyExpired
			}

			go func(id uuid.UUID) {
				s.db.Model(&models.APIKey{}).Where("id = ?", id).
					Update("last_used_at", time.Now().Unix())
			}(keys[i].ID)

			return &keys[i], nil
		}
	}

	return nil, ErrAPIKeyNotFound
}

func (s *APIKeyService) List(ctx context.Context, orgID uuid.UUID) ([]models.APIKey, error) {
	var keys []models.APIKey
	err := s.db.WithContext(ctx).
		Where("organization_id = ?", orgID).
		Order("created_at DESC").
		Find(&keys).Error
	return keys, err
}

func (s *APIKeyService) Revoke(ctx context.Context, orgID, keyID uuid.UUID) error {
	result := s.db.WithContext(ctx).
		Model(&models.APIKey{}).
		Where("id = ? AND organization_id = ?", keyID, orgID).
		Update("is_active", false)
	if result.RowsAffected == 0 {
		return ErrAPIKeyNotFound
	}
	return result.Error
}

func (s *APIKeyService) Delete(ctx context.Context, orgID, keyID uuid.UUID) error {
	result := s.db.WithContext(ctx).
		Where("id = ? AND organization_id = ?", keyID, orgID).
		Delete(&models.APIKey{})
	if result.RowsAffected == 0 {
		return ErrAPIKeyNotFound
	}
	return result.Error
}
