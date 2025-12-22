package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/database/models"
	"gorm.io/gorm"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInactiveUser       = errors.New("user is inactive")
)

type Service struct {
	db  *gorm.DB
	jwt *JWTService
}

func NewService(db *gorm.DB, jwt *JWTService) *Service {
	return &Service{db: db, jwt: jwt}
}

type RegisterInput struct {
	Email    string
	Password string
	Name     string
	OrgName  string // Optional: create new org
}

type LoginInput struct {
	Email    string
	Password string
}

type AuthResponse struct {
	Token string       `json:"token"`
	User  *models.User `json:"user"`
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (*AuthResponse, error) {
	// Check if user exists
	var existing models.User
	if err := s.db.WithContext(ctx).Where("email = ?", input.Email).First(&existing).Error; err == nil {
		return nil, ErrUserExists
	}

	// Hash password
	hash, err := HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	// Create organization
	orgSlug := generateSlug(input.OrgName)
	if input.OrgName == "" {
		input.OrgName = input.Name + "'s Team"
		orgSlug = generateSlug(input.Name)
	}

	org := models.Organization{
		Name: input.OrgName,
		Slug: orgSlug,
	}

	// Transaction: create org and user
	var user models.User
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&org).Error; err != nil {
			return err
		}

		user = models.User{
			Email:          input.Email,
			PasswordHash:   hash,
			Name:           input.Name,
			OrganizationID: org.ID,
			Role:           "owner",
			IsActive:       true,
		}

		return tx.Create(&user).Error
	})

	if err != nil {
		return nil, err
	}

	// Generate token
	token, err := s.jwt.GenerateToken(user.ID, org.ID, user.Email, user.Role)
	if err != nil {
		return nil, err
	}

	user.Organization = &org

	return &AuthResponse{
		Token: token,
		User:  &user,
	}, nil
}

func (s *Service) Login(ctx context.Context, input LoginInput) (*AuthResponse, error) {
	var user models.User
	if err := s.db.WithContext(ctx).
		Preload("Organization").
		Where("email = ?", input.Email).
		First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if !user.IsActive {
		return nil, ErrInactiveUser
	}

	if !CheckPassword(input.Password, user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}

	token, err := s.jwt.GenerateToken(user.ID, user.OrganizationID, user.Email, user.Role)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		Token: token,
		User:  &user,
	}, nil
}

func (s *Service) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).
		Preload("Organization").
		First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func generateSlug(name string) string {
	slug := strings.ToLower(name)
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = strings.ReplaceAll(slug, "'", "")
	// Add timestamp to ensure uniqueness
	return slug + "-" + time.Now().Format("0601021504")
}
