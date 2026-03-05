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

	if cfg.Server.IsProduction() {
		if err := cfg.validateProduction(); err != nil {
			return nil, fmt.Errorf("production config validation: %w", err)
		}
	}

	return cfg, nil
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
	return nil
}
