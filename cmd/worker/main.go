package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/hibiken/asynq"
	"github.com/hugh/go-hunter/internal/database"
	"github.com/hugh/go-hunter/internal/tasks"
	"github.com/hugh/go-hunter/pkg/config"
	"github.com/hugh/go-hunter/pkg/queue"
	"github.com/hugh/go-hunter/pkg/util"
	"github.com/joho/godotenv"
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

	logger.Info("starting Go-Hunter worker")

	// Connect to database
	db, err := database.Connect(&cfg.Database, logger)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}

	// Create Asynq server
	srv := queue.NewServer(&cfg.Redis, 10)

	// Create task handler
	handler := tasks.NewHandler(db, logger)

	// Register handlers
	mux := asynq.NewServeMux()
	handler.RegisterHandlers(mux)

	// Handle shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		logger.Info("shutting down worker...")
		srv.Shutdown()
		cancel()
	}()

	logger.Info("worker started, waiting for tasks...")

	// Start the server
	if err := srv.Run(mux); err != nil {
		logger.Error("worker error", "error", err)
	}

	// Wait for context cancellation
	<-ctx.Done()

	// Close database connection
	sqlDB, _ := db.DB()
	sqlDB.Close()

	logger.Info("worker stopped")
}
