package handlers

import (
	"html/template"
	"net/http"
	"time"

	"github.com/hugh/go-hunter/internal/api/middleware"
	"github.com/hugh/go-hunter/internal/auth"
	"github.com/hugh/go-hunter/internal/database/models"
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
	// If already logged in, redirect to dashboard
	if cookie, err := r.Cookie("token"); err == nil && cookie.Value != "" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	h.render(w, "login.html", map[string]interface{}{"Error": ""})
}

// LoginPost handles form-based login (POST /login)
func (h *DashboardHandler) LoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.render(w, "login.html", map[string]interface{}{"Error": "Invalid form data"})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" || password == "" {
		h.render(w, "login.html", map[string]interface{}{"Error": "Email and password are required"})
		return
	}

	resp, err := h.authService.Login(r.Context(), auth.LoginInput{
		Email:    email,
		Password: password,
	})

	if err != nil {
		errorMsg := "Invalid credentials"
		if err == auth.ErrInactiveUser {
			errorMsg = "Account is inactive"
		}
		h.render(w, "login.html", map[string]interface{}{"Error": errorMsg})
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    resp.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})

	// Redirect to dashboard
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *DashboardHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *DashboardHandler) Assets(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	orgID := middleware.GetOrganizationID(r.Context())

	var assets []models.Asset
	h.db.Where("organization_id = ? AND deleted_at IS NULL", orgID).
		Order("created_at DESC").
		Limit(100).
		Find(&assets)

	// Get counts by type
	var stats struct {
		Domains    int64
		Subdomains int64
		IPs        int64
		Total      int64
	}
	h.db.Table("assets").Where("organization_id = ? AND deleted_at IS NULL", orgID).Count(&stats.Total)
	h.db.Table("assets").Where("organization_id = ? AND type = 'domain' AND deleted_at IS NULL", orgID).Count(&stats.Domains)
	h.db.Table("assets").Where("organization_id = ? AND type = 'subdomain' AND deleted_at IS NULL", orgID).Count(&stats.Subdomains)
	h.db.Table("assets").Where("organization_id = ? AND type = 'ip' AND deleted_at IS NULL", orgID).Count(&stats.IPs)

	data := map[string]interface{}{
		"User":       user,
		"Assets":     assets,
		"Stats":      stats,
		"ActivePage": "assets",
	}

	h.render(w, "assets.html", data)
}

func (h *DashboardHandler) Findings(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	orgID := middleware.GetOrganizationID(r.Context())

	var findings []struct {
		models.Finding
		AssetValue string
	}
	h.db.Table("findings").
		Select("findings.*, assets.value as asset_value").
		Joins("LEFT JOIN assets ON assets.id = findings.asset_id").
		Where("findings.organization_id = ? AND findings.deleted_at IS NULL", orgID).
		Order("CASE findings.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END").
		Limit(100).
		Find(&findings)

	// Get counts by severity
	var stats struct {
		Critical int64
		High     int64
		Medium   int64
		Low      int64
		Info     int64
		Total    int64
	}
	h.db.Table("findings").Where("organization_id = ? AND status = 'open' AND deleted_at IS NULL", orgID).Count(&stats.Total)
	h.db.Table("findings").Where("organization_id = ? AND status = 'open' AND severity = 'critical' AND deleted_at IS NULL", orgID).Count(&stats.Critical)
	h.db.Table("findings").Where("organization_id = ? AND status = 'open' AND severity = 'high' AND deleted_at IS NULL", orgID).Count(&stats.High)
	h.db.Table("findings").Where("organization_id = ? AND status = 'open' AND severity = 'medium' AND deleted_at IS NULL", orgID).Count(&stats.Medium)
	h.db.Table("findings").Where("organization_id = ? AND status = 'open' AND severity = 'low' AND deleted_at IS NULL", orgID).Count(&stats.Low)
	h.db.Table("findings").Where("organization_id = ? AND status = 'open' AND severity = 'info' AND deleted_at IS NULL", orgID).Count(&stats.Info)

	data := map[string]interface{}{
		"User":       user,
		"Findings":   findings,
		"Stats":      stats,
		"ActivePage": "findings",
	}

	h.render(w, "findings.html", data)
}

func (h *DashboardHandler) Scans(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	orgID := middleware.GetOrganizationID(r.Context())

	var scans []models.Scan
	h.db.Where("organization_id = ? AND deleted_at IS NULL", orgID).
		Order("created_at DESC").
		Limit(50).
		Find(&scans)

	// Get counts by status
	var stats struct {
		Running   int64
		Completed int64
		Failed    int64
		Total     int64
	}
	h.db.Table("scans").Where("organization_id = ? AND deleted_at IS NULL", orgID).Count(&stats.Total)
	h.db.Table("scans").Where("organization_id = ? AND status IN ('pending', 'running') AND deleted_at IS NULL", orgID).Count(&stats.Running)
	h.db.Table("scans").Where("organization_id = ? AND status = 'completed' AND deleted_at IS NULL", orgID).Count(&stats.Completed)
	h.db.Table("scans").Where("organization_id = ? AND status = 'failed' AND deleted_at IS NULL", orgID).Count(&stats.Failed)

	data := map[string]interface{}{
		"User":       user,
		"Scans":      scans,
		"Stats":      stats,
		"ActivePage": "scans",
		"FormatTime": func(ts int64) string {
			if ts == 0 {
				return "-"
			}
			return time.Unix(ts, 0).Format("Jan 02, 15:04")
		},
	}

	h.render(w, "scans.html", data)
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
