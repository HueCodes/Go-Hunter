package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server     ServerConfig
	Database   DatabaseConfig
	Redis      RedisConfig
	JWT        JWTConfig
	Encryption EncryptionConfig
	RateLimit  RateLimitConfig
}

type ServerConfig struct {
	Host              string
	Port              int
	Env               string
	RequestTimeoutSec int
	MaxBodyBytes      int64
}

type DatabaseConfig struct {
	Host               string
	Port               int
	User               string
	Password           string
	Name               string
	SSLMode            string
	MaxOpenConns       int
	MaxIdleConns       int
	ConnMaxLifetimeMin int
	ConnMaxIdleTimeSec int
}

type RedisConfig struct {
	Host     string
	Port     int
	Password string
}

type JWTConfig struct {
	Secret      string
	ExpiryHours int
}

type EncryptionConfig struct {
	Key string
}

type RateLimitConfig struct {
	Requests      int
	WindowSeconds int
}

func (d *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.Name, d.SSLMode,
	)
}

func (r *RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

func (j *JWTConfig) Expiry() time.Duration {
	return time.Duration(j.ExpiryHours) * time.Hour
}

func (s *ServerConfig) Addr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

func (s *ServerConfig) IsDevelopment() bool {
	return s.Env == "development"
}

func (s *ServerConfig) IsProduction() bool {
	return s.Env == "production"
}

func Load() (*Config, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("SERVER_HOST", "0.0.0.0")
	v.SetDefault("SERVER_PORT", 8080)
	v.SetDefault("SERVER_ENV", "development")
	v.SetDefault("SERVER_REQUEST_TIMEOUT_SEC", 30)
	v.SetDefault("SERVER_MAX_BODY_BYTES", 1048576) // 1MB
	v.SetDefault("DATABASE_HOST", "localhost")
	v.SetDefault("DATABASE_PORT", 5432)
	v.SetDefault("DATABASE_USER", "gohunter")
	v.SetDefault("DATABASE_PASSWORD", "gohunter_secret")
	v.SetDefault("DATABASE_NAME", "gohunter")
	v.SetDefault("DATABASE_SSLMODE", "disable")
	v.SetDefault("DATABASE_MAX_OPEN_CONNS", 25)
	v.SetDefault("DATABASE_MAX_IDLE_CONNS", 10)
	v.SetDefault("DATABASE_CONN_MAX_LIFETIME_MIN", 30)
	v.SetDefault("DATABASE_CONN_MAX_IDLE_TIME_SEC", 300)
	v.SetDefault("REDIS_HOST", "localhost")
	v.SetDefault("REDIS_PORT", 6379)
	v.SetDefault("REDIS_PASSWORD", "")
	v.SetDefault("JWT_SECRET", "change-me-in-production")
	v.SetDefault("JWT_EXPIRY_HOURS", 24)
	v.SetDefault("RATE_LIMIT_REQUESTS", 100)
	v.SetDefault("RATE_LIMIT_WINDOW_SECONDS", 60)

	// Load from .env file if present
	v.SetConfigName(".env")
	v.SetConfigType("env")
	v.AddConfigPath(".")
	v.AddConfigPath("/app")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	// Override with environment variables
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	cfg := &Config{
		Server: ServerConfig{
			Host:              v.GetString("SERVER_HOST"),
			Port:              v.GetInt("SERVER_PORT"),
			Env:               v.GetString("SERVER_ENV"),
			RequestTimeoutSec: v.GetInt("SERVER_REQUEST_TIMEOUT_SEC"),
			MaxBodyBytes:      v.GetInt64("SERVER_MAX_BODY_BYTES"),
		},
		Database: DatabaseConfig{
			Host:               v.GetString("DATABASE_HOST"),
			Port:               v.GetInt("DATABASE_PORT"),
			User:               v.GetString("DATABASE_USER"),
			Password:           v.GetString("DATABASE_PASSWORD"),
			Name:               v.GetString("DATABASE_NAME"),
			SSLMode:            v.GetString("DATABASE_SSLMODE"),
			MaxOpenConns:       v.GetInt("DATABASE_MAX_OPEN_CONNS"),
			MaxIdleConns:       v.GetInt("DATABASE_MAX_IDLE_CONNS"),
			ConnMaxLifetimeMin: v.GetInt("DATABASE_CONN_MAX_LIFETIME_MIN"),
			ConnMaxIdleTimeSec: v.GetInt("DATABASE_CONN_MAX_IDLE_TIME_SEC"),
		},
		Redis: RedisConfig{
			Host:     v.GetString("REDIS_HOST"),
			Port:     v.GetInt("REDIS_PORT"),
			Password: v.GetString("REDIS_PASSWORD"),
		},
		JWT: JWTConfig{
			Secret:      v.GetString("JWT_SECRET"),
			ExpiryHours: v.GetInt("JWT_EXPIRY_HOURS"),
		},
		Encryption: EncryptionConfig{
			Key: v.GetString("ENCRYPTION_KEY"),
		},
		RateLimit: RateLimitConfig{
			Requests:      v.GetInt("RATE_LIMIT_REQUESTS"),
			WindowSeconds: v.GetInt("RATE_LIMIT_WINDOW_SECONDS"),
		},
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	if cfg.Server.IsProduction() {
		if err := cfg.validateProduction(); err != nil {
			return nil, fmt.Errorf("production config validation: %w", err)
		}
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("SERVER_PORT must be between 1 and 65535, got %d", c.Server.Port)
	}
	if c.Database.Port < 1 || c.Database.Port > 65535 {
		return fmt.Errorf("DATABASE_PORT must be between 1 and 65535, got %d", c.Database.Port)
	}
	if c.Redis.Port < 1 || c.Redis.Port > 65535 {
		return fmt.Errorf("REDIS_PORT must be between 1 and 65535, got %d", c.Redis.Port)
	}
	if c.Database.Host == "" {
		return fmt.Errorf("DATABASE_HOST must not be empty")
	}
	if c.Database.Name == "" {
		return fmt.Errorf("DATABASE_NAME must not be empty")
	}
	if c.Database.User == "" {
		return fmt.Errorf("DATABASE_USER must not be empty")
	}
	validSSLModes := map[string]bool{
		"disable": true, "allow": true, "prefer": true,
		"require": true, "verify-ca": true, "verify-full": true,
	}
	if !validSSLModes[c.Database.SSLMode] {
		return fmt.Errorf("DATABASE_SSLMODE must be one of: disable, allow, prefer, require, verify-ca, verify-full")
	}
	if c.JWT.ExpiryHours < 1 {
		return fmt.Errorf("JWT_EXPIRY_HOURS must be at least 1")
	}
	if c.Server.RequestTimeoutSec < 1 {
		return fmt.Errorf("SERVER_REQUEST_TIMEOUT_SEC must be at least 1")
	}
	if c.Server.MaxBodyBytes < 1024 {
		return fmt.Errorf("SERVER_MAX_BODY_BYTES must be at least 1024")
	}
	validEnvs := map[string]bool{"development": true, "staging": true, "production": true, "test": true}
	if !validEnvs[c.Server.Env] {
		return fmt.Errorf("SERVER_ENV must be one of: development, staging, production, test")
	}
	return nil
}

func (c *Config) validateProduction() error {
	if c.JWT.Secret == "change-me-in-production" || len(c.JWT.Secret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 characters in production")
	}
	if c.Encryption.Key == "" {
		return fmt.Errorf("ENCRYPTION_KEY must be set in production")
	}
	if c.Database.Password == "gohunter_secret" {
		return fmt.Errorf("DATABASE_PASSWORD must not use default value in production")
	}
	if c.Database.SSLMode == "disable" {
		return fmt.Errorf("DATABASE_SSLMODE must not be 'disable' in production")
	}
	return nil
}
