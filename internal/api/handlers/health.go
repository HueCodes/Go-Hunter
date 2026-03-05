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

// Health is a liveness probe. Returns unhealthy only if the database is down.
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	services := make(map[string]string)
	status := "healthy"

	// Check database
	sqlDB, err := h.db.DB()
	if err != nil || sqlDB.PingContext(r.Context()) != nil {
		services["database"] = "unhealthy"
		status = "unhealthy"
	} else {
		services["database"] = "healthy"
	}

	// Check Redis
	if h.redis != nil {
		if err := h.redis.Ping(r.Context()).Err(); err != nil {
			services["redis"] = "unhealthy"
			if status == "healthy" {
				status = "degraded"
			}
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

// Ready is a readiness probe. Returns 200 only when all dependencies are available.
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	// Database must be reachable
	sqlDB, err := h.db.DB()
	if err != nil || sqlDB.PingContext(r.Context()) != nil {
		http.Error(w, "database not ready", http.StatusServiceUnavailable)
		return
	}

	// Redis must be reachable (if configured)
	if h.redis != nil {
		if err := h.redis.Ping(r.Context()).Err(); err != nil {
			http.Error(w, "redis not ready", http.StatusServiceUnavailable)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
