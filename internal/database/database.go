package database

import (
	"fmt"
	"log/slog"

	"github.com/hugh/go-hunter/internal/database/models"
	"github.com/hugh/go-hunter/pkg/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Connect(cfg *config.DatabaseConfig, log *slog.Logger) (*gorm.DB, error) {
	gormLogger := logger.Default.LogMode(logger.Warn)
	if cfg.SSLMode == "disable" {
		gormLogger = logger.Default.LogMode(logger.Info)
	}

	db, err := gorm.Open(postgres.Open(cfg.DSN()), &gorm.Config{
		Logger: gormLogger,
	})
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("getting underlying db: %w", err)
	}

	// Connection pool settings
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)

	log.Info("connected to database", "host", cfg.Host, "database", cfg.Name)

	return db, nil
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.Organization{},
		&models.User{},
		&models.CloudCredential{},
		&models.Asset{},
		&models.Scan{},
		&models.Finding{},
	)
}
