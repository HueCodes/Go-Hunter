package auth

import (
	"context"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/database/models"
)

// Authenticator defines the interface for user authentication operations.
type Authenticator interface {
	Register(ctx context.Context, input RegisterInput) (*AuthResponse, error)
	Login(ctx context.Context, input LoginInput) (*AuthResponse, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error)
}

// TokenService defines the interface for JWT token operations.
type TokenService interface {
	GenerateToken(userID, orgID uuid.UUID, email, role string) (string, error)
	ValidateToken(tokenString string) (*Claims, error)
}

// Compile-time interface satisfaction checks
var (
	_ Authenticator = (*Service)(nil)
	_ TokenService  = (*JWTService)(nil)
)
