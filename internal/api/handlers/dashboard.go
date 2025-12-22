package handlers

import (
	"html/template"
	"net/http"

	"github.com/hugh/go-hunter/internal/api/middleware"
	"github.com/hugh/go-hunter/internal/auth"
	"gorm.io/gorm"
)

type DashboardHandler struct {
	db          *gorm.DB
	authService *auth.Service
	templates   *template.Template
}

func NewDashboardHandler(db *gorm.DB, authService *auth.Service, templates *template.Template) *DashboardHandler {
	return &DashboardHandler{
		db:          db,
		authService: authService,
		templates:   templates,
	}
}

func (h *DashboardHandler) Index(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())

	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Get dashboard stats
	var stats struct {
		TotalAssets   int64
		TotalFindings int64
		CriticalCount int64
		HighCount     int64
		ActiveScans   int64
	}

	orgID := middleware.GetOrganizationID(r.Context())
	h.db.Table("assets").Where("organization_id = ? AND deleted_at IS NULL", orgID).Count(&stats.TotalAssets)
	h.db.Table("findings").Where("organization_id = ? AND status = 'open' AND deleted_at IS NULL", orgID).Count(&stats.TotalFindings)
	h.db.Table("findings").Where("organization_id = ? AND status = 'open' AND severity = 'critical' AND deleted_at IS NULL", orgID).Count(&stats.CriticalCount)
	h.db.Table("findings").Where("organization_id = ? AND status = 'open' AND severity = 'high' AND deleted_at IS NULL", orgID).Count(&stats.HighCount)
	h.db.Table("scans").Where("organization_id = ? AND status IN ('pending', 'running') AND deleted_at IS NULL", orgID).Count(&stats.ActiveScans)

	data := map[string]interface{}{
		"User":  user,
		"Stats": stats,
	}

	h.render(w, "dashboard.html", data)
}

func (h *DashboardHandler) Login(w http.ResponseWriter, r *http.Request) {
	h.render(w, "login.html", nil)
}

func (h *DashboardHandler) render(w http.ResponseWriter, name string, data interface{}) {
	if h.templates == nil {
		http.Error(w, "Templates not loaded", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
