package config

import (
	"testing"
)

func validConfig() Config {
	return Config{
		Server: ServerConfig{
			Host:              "0.0.0.0",
			Port:              8080,
			Env:               "development",
			RequestTimeoutSec: 30,
			MaxBodyBytes:      1048576,
		},
		Database: DatabaseConfig{
			Host:    "localhost",
			Port:    5432,
			User:    "gohunter",
			Name:    "gohunter",
			SSLMode: "disable",
		},
		Redis: RedisConfig{Port: 6379},
		JWT:   JWTConfig{Secret: "test-secret", ExpiryHours: 24},
	}
}

func TestValidate_Valid(t *testing.T) {
	c := validConfig()
	if err := c.validate(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidate_InvalidServerPort(t *testing.T) {
	c := validConfig()
	c.Server.Port = 0
	if err := c.validate(); err == nil {
		t.Fatal("expected error for port 0")
	}
	c.Server.Port = 70000
	if err := c.validate(); err == nil {
		t.Fatal("expected error for port 70000")
	}
}

func TestValidate_InvalidDatabasePort(t *testing.T) {
	c := validConfig()
	c.Database.Port = -1
	if err := c.validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_InvalidRedisPort(t *testing.T) {
	c := validConfig()
	c.Redis.Port = 99999
	if err := c.validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_EmptyDatabaseHost(t *testing.T) {
	c := validConfig()
	c.Database.Host = ""
	if err := c.validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_EmptyDatabaseName(t *testing.T) {
	c := validConfig()
	c.Database.Name = ""
	if err := c.validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_EmptyDatabaseUser(t *testing.T) {
	c := validConfig()
	c.Database.User = ""
	if err := c.validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_InvalidSSLMode(t *testing.T) {
	c := validConfig()
	c.Database.SSLMode = "bogus"
	if err := c.validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_InvalidEnv(t *testing.T) {
	c := validConfig()
	c.Server.Env = "invalid"
	if err := c.validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_JWTExpiryTooLow(t *testing.T) {
	c := validConfig()
	c.JWT.ExpiryHours = 0
	if err := c.validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_RequestTimeoutTooLow(t *testing.T) {
	c := validConfig()
	c.Server.RequestTimeoutSec = 0
	if err := c.validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_MaxBodyBytesTooLow(t *testing.T) {
	c := validConfig()
	c.Server.MaxBodyBytes = 512
	if err := c.validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateProduction_WeakJWTSecret(t *testing.T) {
	c := validConfig()
	c.Server.Env = "production"
	c.JWT.Secret = "short"
	if err := c.validateProduction(); err == nil {
		t.Fatal("expected error for weak JWT secret")
	}
}

func TestValidateProduction_DefaultJWTSecret(t *testing.T) {
	c := validConfig()
	c.JWT.Secret = "change-me-in-production"
	if err := c.validateProduction(); err == nil {
		t.Fatal("expected error for default JWT secret")
	}
}

func TestValidateProduction_MissingEncryptionKey(t *testing.T) {
	c := validConfig()
	c.JWT.Secret = "this-is-a-long-enough-secret-for-production-use"
	c.Encryption.Key = ""
	if err := c.validateProduction(); err == nil {
		t.Fatal("expected error for missing encryption key")
	}
}

func TestValidateProduction_DefaultPassword(t *testing.T) {
	c := validConfig()
	c.JWT.Secret = "this-is-a-long-enough-secret-for-production-use"
	c.Encryption.Key = "some-key"
	c.Database.Password = "gohunter_secret"
	if err := c.validateProduction(); err == nil {
		t.Fatal("expected error for default DB password")
	}
}

func TestValidateProduction_DisabledSSL(t *testing.T) {
	c := validConfig()
	c.JWT.Secret = "this-is-a-long-enough-secret-for-production-use"
	c.Encryption.Key = "some-key"
	c.Database.Password = "secure-pass"
	c.Database.SSLMode = "disable"
	if err := c.validateProduction(); err == nil {
		t.Fatal("expected error for disabled SSL in production")
	}
}

func TestValidateProduction_Valid(t *testing.T) {
	c := validConfig()
	c.JWT.Secret = "this-is-a-long-enough-secret-for-production-use"
	c.Encryption.Key = "some-key"
	c.Database.Password = "secure-pass"
	c.Database.SSLMode = "require"
	if err := c.validateProduction(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestDSN(t *testing.T) {
	d := DatabaseConfig{Host: "h", Port: 5432, User: "u", Password: "p", Name: "n", SSLMode: "disable"}
	want := "host=h port=5432 user=u password=p dbname=n sslmode=disable"
	if got := d.DSN(); got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}
}

func TestRedisAddr(t *testing.T) {
	r := RedisConfig{Host: "redis", Port: 6379}
	if got := r.Addr(); got != "redis:6379" {
		t.Errorf("Addr() = %q", got)
	}
}

func TestServerAddr(t *testing.T) {
	s := ServerConfig{Host: "0.0.0.0", Port: 8080}
	if got := s.Addr(); got != "0.0.0.0:8080" {
		t.Errorf("Addr() = %q", got)
	}
}

func TestIsDevelopment(t *testing.T) {
	s := ServerConfig{Env: "development"}
	if !s.IsDevelopment() {
		t.Error("expected IsDevelopment() = true")
	}
	s.Env = "production"
	if s.IsDevelopment() {
		t.Error("expected IsDevelopment() = false")
	}
}

func TestIsProduction(t *testing.T) {
	s := ServerConfig{Env: "production"}
	if !s.IsProduction() {
		t.Error("expected IsProduction() = true")
	}
	s.Env = "development"
	if s.IsProduction() {
		t.Error("expected IsProduction() = false")
	}
}

func TestJWTExpiry(t *testing.T) {
	j := JWTConfig{ExpiryHours: 24}
	if got := j.Expiry().Hours(); got != 24 {
		t.Errorf("Expiry() = %v hours, want 24", got)
	}
}
