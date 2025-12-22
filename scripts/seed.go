//go:build ignore

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/hugh/go-hunter/internal/auth"
	"github.com/hugh/go-hunter/internal/database"
	"github.com/hugh/go-hunter/pkg/config"
	"github.com/hugh/go-hunter/pkg/util"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	logger := util.NewLogger(cfg.Server.Env)

	db, err := database.Connect(&cfg.Database, logger)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	// Run migrations
	if err := database.AutoMigrate(db); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	// Create admin user
	jwtService := auth.NewJWTService(cfg.JWT.Secret, cfg.JWT.Expiry())
	authService := auth.NewService(db, jwtService)

	email := os.Getenv("ADMIN_EMAIL")
	password := os.Getenv("ADMIN_PASSWORD")
	name := os.Getenv("ADMIN_NAME")

	if email == "" {
		email = "admin@example.com"
	}
	if password == "" {
		password = "admin123!"
	}
	if name == "" {
		name = "Admin"
	}

	resp, err := authService.Register(context.Background(), auth.RegisterInput{
		Email:    email,
		Password: password,
		Name:     name,
		OrgName:  "Default Organization",
	})

	if err != nil {
		if err == auth.ErrUserExists {
			fmt.Printf("Admin user already exists: %s\n", email)
			return
		}
		log.Fatalf("failed to create admin user: %v", err)
	}

	fmt.Printf("Admin user created successfully!\n")
	fmt.Printf("Email: %s\n", resp.User.Email)
	fmt.Printf("Organization: %s\n", resp.User.Organization.Name)
	fmt.Printf("Token: %s\n", resp.Token)
}
