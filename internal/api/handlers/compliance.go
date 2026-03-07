package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/hugh/go-hunter/internal/api/middleware"
	"github.com/hugh/go-hunter/internal/compliance"
	"github.com/hugh/go-hunter/internal/database/models"
	apperrors "github.com/hugh/go-hunter/pkg/errors"
	"gorm.io/gorm"
)

type ComplianceHandler struct {
	db *gorm.DB
}

func NewComplianceHandler(db *gorm.DB) *ComplianceHandler {
	return &ComplianceHandler{db: db}
}

func (h *ComplianceHandler) Frameworks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, compliance.DefaultFrameworks())
}

func (h *ComplianceHandler) Report(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	frameworkID := chi.URLParam(r, "framework")

	var findings []models.Finding
	h.db.WithContext(r.Context()).
		Where("organization_id = ?", orgID).
		Select("id, category, status").
		Find(&findings)

	infos := make([]compliance.FindingInfo, len(findings))
	for i, f := range findings {
		infos[i] = compliance.FindingInfo{
			ID:       f.ID.String(),
			Category: f.Category,
			Status:   string(f.Status),
		}
	}

	report := compliance.GenerateReport(frameworkID, infos)
	if report == nil {
		apperrors.WriteHTTP(w, r, apperrors.NotFound("Framework"))
		return
	}

	writeJSON(w, http.StatusOK, report)
}
