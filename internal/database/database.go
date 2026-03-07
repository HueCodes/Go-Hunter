package database

import (
	"fmt"
	"log/slog"
	"time"

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
	maxOpen := cfg.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = 25
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 10
	}
	connMaxLifetime := cfg.ConnMaxLifetimeMin
	if connMaxLifetime <= 0 {
		connMaxLifetime = 30
	}
	connMaxIdleTime := cfg.ConnMaxIdleTimeSec
	if connMaxIdleTime <= 0 {
		connMaxIdleTime = 300
	}
	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetMaxIdleConns(maxIdle)
	sqlDB.SetConnMaxLifetime(time.Duration(connMaxLifetime) * time.Minute)
	sqlDB.SetConnMaxIdleTime(time.Duration(connMaxIdleTime) * time.Second)

	log.Info("connected to database",
		"host", cfg.Host,
		"database", cfg.Name,
		"max_open_conns", maxOpen,
		"max_idle_conns", maxIdle,
		"conn_max_lifetime_min", connMaxLifetime,
		"conn_max_idle_time_sec", connMaxIdleTime,
	)

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
		&models.APIKey{},
		&models.AuditLog{},
	)
}
