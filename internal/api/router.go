package api

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/hibiken/asynq"
	"github.com/hugh/go-hunter/internal/api/handlers"
	"github.com/hugh/go-hunter/internal/api/middleware"
	"github.com/hugh/go-hunter/internal/assets"
	"github.com/hugh/go-hunter/internal/auth"
	"github.com/hugh/go-hunter/pkg/crypto"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type Router struct {
	chi.Router
}

type RouterConfig struct {
	DB          *gorm.DB
	Redis       *redis.Client
	Logger      *slog.Logger
	JWTService  *auth.JWTService
	AuthService *auth.Service
	Encryptor   *crypto.Encryptor
	Templates   *template.Template
	StaticFS    fs.FS
	AsynqClient *asynq.Client
}

func NewRouter(cfg RouterConfig) *Router {
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.Recovery(cfg.Logger))
	r.Use(middleware.Logging(cfg.Logger))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Initialize services
	assetService := assets.NewService(cfg.DB, cfg.Encryptor, cfg.Logger)

	// Initialize handlers
	healthHandler := handlers.NewHealthHandler(cfg.DB, cfg.Redis)
	authHandler := handlers.NewAuthHandler(cfg.AuthService)
	dashboardHandler := handlers.NewDashboardHandler(cfg.DB, cfg.AuthService, cfg.Templates)
	credentialHandler := handlers.NewCredentialHandler(assetService)
	assetHandler := handlers.NewAssetHandler(cfg.DB)
	scanHandler := handlers.NewScanHandler(cfg.DB, cfg.AsynqClient)
	findingHandler := handlers.NewFindingHandler(cfg.DB)

	// Health endpoints (no auth required)
	r.Get("/health", healthHandler.Health)
	r.Get("/ready", healthHandler.Ready)

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		// Public auth endpoints
		r.Post("/auth/register", authHandler.Register)
		r.Post("/auth/login", authHandler.Login)
		r.Post("/auth/logout", authHandler.Logout)

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(cfg.JWTService))

			// User endpoints
			r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
				userID := middleware.GetUserID(r.Context())
				user, err := cfg.AuthService.GetUserByID(r.Context(), userID)
				if err != nil {
					http.Error(w, "User not found", http.StatusNotFound)
					return
				}
				writeJSON(w, http.StatusOK, user)
			})

			// Credentials endpoints
			r.Route("/credentials", func(r chi.Router) {
				r.Get("/", credentialHandler.List)
				r.Post("/", credentialHandler.Create)
				r.Delete("/{id}", credentialHandler.Delete)
				r.Post("/{id}/test", credentialHandler.Test)
			})

			// Assets endpoints
			r.Route("/assets", func(r chi.Router) {
				r.Get("/", assetHandler.List)
				r.Post("/", assetHandler.Create)
				r.Get("/{id}", assetHandler.Get)
				r.Delete("/{id}", assetHandler.Delete)
			})

			// Scans endpoints
			r.Route("/scans", func(r chi.Router) {
				r.Get("/", scanHandler.List)
				r.Post("/", scanHandler.Create)
				r.Get("/{id}", scanHandler.Get)
				r.Post("/{id}/cancel", scanHandler.Cancel)
			})

			// Findings endpoints
			r.Route("/findings", func(r chi.Router) {
				r.Get("/", findingHandler.List)
				r.Get("/{id}", findingHandler.Get)
				r.Put("/{id}/status", findingHandler.UpdateStatus)
			})
		})
	})

	// Web dashboard routes
	r.Get("/login", dashboardHandler.Login)

	r.Group(func(r chi.Router) {
		r.Use(middleware.Auth(cfg.JWTService))
		r.Get("/", dashboardHandler.Index)
		r.Get("/dashboard", dashboardHandler.Index)
	})

	// Static files
	if cfg.StaticFS != nil {
		fileServer := http.FileServer(http.FS(cfg.StaticFS))
		r.Handle("/static/*", http.StripPrefix("/static/", fileServer))
	}

	return &Router{r}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
