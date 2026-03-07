package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/hugh/go-hunter/internal/api/middleware"
	"github.com/hugh/go-hunter/internal/database/models"
	"github.com/hugh/go-hunter/internal/diff"
	apperrors "github.com/hugh/go-hunter/pkg/errors"
	"gorm.io/gorm"
)

type DiffHandler struct {
	db *gorm.DB
}

func NewDiffHandler(db *gorm.DB) *DiffHandler {
	return &DiffHandler{db: db}
}

// Diff computes the attack surface diff between two time points.
// Query params: from (unix timestamp), to (unix timestamp, defaults to now)
func (h *DiffHandler) Diff(w http.ResponseWriter, r *http.Request) {
	orgID := middleware.GetOrganizationID(r.Context())
	db := h.db.WithContext(r.Context())

	fromStr := r.URL.Query().Get("from")
	if fromStr == "" {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("'from' timestamp is required"))
		return
	}
	fromUnix, err := strconv.ParseInt(fromStr, 10, 64)
	if err != nil {
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid 'from' timestamp"))
		return
	}
	fromTime := time.Unix(fromUnix, 0)

	toTime := time.Now()
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		toUnix, err := strconv.ParseInt(toStr, 10, 64)
		if err != nil {
			apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid 'to' timestamp"))
			return
		}
		toTime = time.Unix(toUnix, 0)
	}

	// Get assets that existed at "from" time (discovered before from, last seen after from)
	var fromAssets []models.Asset
	db.Where("organization_id = ? AND discovered_at <= ? AND last_seen_at >= ?",
		orgID, fromUnix, fromUnix).
		Find(&fromAssets)

	// Get current assets at "to" time
	var toAssets []models.Asset
	db.Where("organization_id = ? AND discovered_at <= ? AND (last_seen_at >= ? OR is_active = true)",
		orgID, toTime.Unix(), toTime.Unix()).
		Find(&toAssets)

	// Get findings at "from" time
	var fromFindings []models.Finding
	db.Where("organization_id = ? AND first_seen_at <= ? AND (resolved_at = 0 OR resolved_at > ?)",
		orgID, fromUnix, fromUnix).
		Find(&fromFindings)

	// Get findings at "to" time
	var toFindings []models.Finding
	db.Where("organization_id = ? AND first_seen_at <= ? AND (resolved_at = 0 OR resolved_at > ?)",
		orgID, toTime.Unix(), toTime.Unix()).
		Find(&toFindings)

	// Convert to snapshots
	fromSnap := make([]diff.AssetSnapshot, len(fromAssets))
	for i, a := range fromAssets {
		fromSnap[i] = diff.AssetSnapshot{
			ID: a.ID.String(), Type: string(a.Type), Value: a.Value, IsActive: a.IsActive,
		}
	}
	toSnap := make([]diff.AssetSnapshot, len(toAssets))
	for i, a := range toAssets {
		toSnap[i] = diff.AssetSnapshot{
			ID: a.ID.String(), Type: string(a.Type), Value: a.Value, IsActive: a.IsActive,
		}
	}

	fromFSnap := make([]diff.FindingSnapshot, len(fromFindings))
	for i, f := range fromFindings {
		fromFSnap[i] = diff.FindingSnapshot{
			ID: f.ID.String(), AssetID: f.AssetID.String(),
			Title: f.Title, Severity: string(f.Severity), Status: string(f.Status),
		}
	}
	toFSnap := make([]diff.FindingSnapshot, len(toFindings))
	for i, f := range toFindings {
		toFSnap[i] = diff.FindingSnapshot{
			ID: f.ID.String(), AssetID: f.AssetID.String(),
			Title: f.Title, Severity: string(f.Severity), Status: string(f.Status),
		}
	}

	result := diff.Calculate(fromSnap, toSnap, fromFSnap, toFSnap, fromTime, toTime)
	writeJSON(w, http.StatusOK, result)
}
