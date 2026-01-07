package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type HealthHandler struct {
	db    *gorm.DB
	redis *redis.Client
}

func NewHealthHandler(db *gorm.DB, redis *redis.Client) *HealthHandler {
	return &HealthHandler{db: db, redis: redis}
}

type HealthResponse struct {
	Status   string            `json:"status"`
	Services map[string]string `json:"services"`
}

func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	services := make(map[string]string)
	status := "healthy"

	// Check database
	sqlDB, err := h.db.DB()
	if err != nil || sqlDB.Ping() != nil {
		services["database"] = "unhealthy"
		status = "unhealthy"
	} else {
		services["database"] = "healthy"
	}

	// Check Redis
	if h.redis != nil {
		if err := h.redis.Ping(r.Context()).Err(); err != nil {
			services["redis"] = "unhealthy"
			status = "unhealthy"
		} else {
			services["redis"] = "healthy"
		}
	}

	statusCode := http.StatusOK
	if status == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(HealthResponse{
		Status:   status,
		Services: services,
	})
}

func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	// Simple readiness check
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
