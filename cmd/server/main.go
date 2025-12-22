package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hugh/go-hunter/internal/api"
	"github.com/hugh/go-hunter/internal/auth"
	"github.com/hugh/go-hunter/internal/database"
	"github.com/hugh/go-hunter/internal/web"
	"github.com/hugh/go-hunter/pkg/config"
	"github.com/hugh/go-hunter/pkg/util"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

func main() {
	// Load .env file
	_ = godotenv.Load()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Initialize logger
	logger := util.NewLogger(cfg.Server.Env)
	slog.SetDefault(logger)

	logger.Info("starting Go-Hunter server",
		"env", cfg.Server.Env,
		"addr", cfg.Server.Addr(),
	)

	// Connect to database
	db, err := database.Connect(&cfg.Database, logger)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}

	// Run auto migrations in development
	if cfg.Server.IsDevelopment() {
		logger.Info("running database migrations")
		if err := database.AutoMigrate(db); err != nil {
			logger.Error("failed to run migrations", "error", err)
			os.Exit(1)
		}
	}

	// Connect to Redis
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr(),
		Password: cfg.Redis.Password,
	})
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		logger.Warn("failed to connect to Redis", "error", err)
		redisClient = nil
	}

	// Initialize services
	jwtService := auth.NewJWTService(cfg.JWT.Secret, cfg.JWT.Expiry())
	authService := auth.NewService(db, jwtService)

	// Load templates
	templates, err := web.LoadTemplates()
	if err != nil {
		logger.Error("failed to load templates", "error", err)
		os.Exit(1)
	}

	// Get static file system
	staticFS, err := web.GetStaticFS()
	if err != nil {
		logger.Error("failed to get static fs", "error", err)
		os.Exit(1)
	}

	// Create router
	router := api.NewRouter(api.RouterConfig{
		DB:          db,
		Redis:       redisClient,
		Logger:      logger,
		JWTService:  jwtService,
		AuthService: authService,
		Templates:   templates,
		StaticFS:    staticFS,
	})

	// Create HTTP server
	server := &http.Server{
		Addr:         cfg.Server.Addr(),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("server listening", "addr", cfg.Server.Addr())
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("server shutdown error", "error", err)
	}

	// Close Redis connection
	if redisClient != nil {
		redisClient.Close()
	}

	// Close database connection
	sqlDB, _ := db.DB()
	sqlDB.Close()

	logger.Info("server stopped")
}
