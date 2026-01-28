package models

import (
	"database/sql/driver"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UUIDArray is a custom type for PostgreSQL UUID arrays
type UUIDArray []uuid.UUID

// Scan implements the sql.Scanner interface for reading from database
func (a *UUIDArray) Scan(value interface{}) error {
	if value == nil {
		*a = nil
		return nil
	}

	// PostgreSQL returns arrays as strings like {uuid1,uuid2,uuid3}
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("UUIDArray: expected string, got %T", value)
	}

	// Handle empty array
	if str == "{}" || str == "" {
		*a = nil
		return nil
	}

	// Remove braces and split
	str = strings.Trim(str, "{}")
	if str == "" {
		*a = nil
		return nil
	}

	parts := strings.Split(str, ",")
	result := make([]uuid.UUID, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		id, err := uuid.Parse(p)
		if err != nil {
			return fmt.Errorf("UUIDArray: failed to parse UUID %q: %w", p, err)
		}
		result = append(result, id)
	}
	*a = result
	return nil
}

// Value implements the driver.Valuer interface for writing to database
func (a UUIDArray) Value() (driver.Value, error) {
	if len(a) == 0 {
		return nil, nil
	}

	// Format as PostgreSQL array literal: {uuid1,uuid2,uuid3}
	strs := make([]string, len(a))
	for i, id := range a {
		strs[i] = id.String()
	}
	return "{" + strings.Join(strs, ",") + "}", nil
}

// Base model with UUID primary key and timestamps
type Base struct {
	ID        uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (b *Base) BeforeCreate(tx *gorm.DB) error {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	return nil
}
