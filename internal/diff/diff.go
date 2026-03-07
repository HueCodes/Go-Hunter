package diff

import "time"

// AssetChange represents a change to an asset between two points in time.
type AssetChange struct {
	AssetID   string `json:"asset_id"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Change    string `json:"change"` // "added", "removed", "modified"
	Field     string `json:"field,omitempty"`
	OldValue  string `json:"old_value,omitempty"`
	NewValue  string `json:"new_value,omitempty"`
}

// FindingChange represents a change to a finding.
type FindingChange struct {
	FindingID string `json:"finding_id"`
	AssetID   string `json:"asset_id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Change    string `json:"change"` // "new", "resolved", "reopened"
}

// SurfaceDiff represents the diff between two scan snapshots.
type SurfaceDiff struct {
	FromTime       time.Time       `json:"from_time"`
	ToTime         time.Time       `json:"to_time"`
	AssetsAdded    []AssetChange   `json:"assets_added"`
	AssetsRemoved  []AssetChange   `json:"assets_removed"`
	FindingsNew    []FindingChange `json:"findings_new"`
	FindingsFixed  []FindingChange `json:"findings_fixed"`
	Summary        DiffSummary     `json:"summary"`
}

// DiffSummary provides a quick overview of changes.
type DiffSummary struct {
	AssetsAdded   int `json:"assets_added"`
	AssetsRemoved int `json:"assets_removed"`
	FindingsNew   int `json:"findings_new"`
	FindingsFixed int `json:"findings_fixed"`
}

// AssetSnapshot is a simplified asset representation for diffing.
type AssetSnapshot struct {
	ID       string
	Type     string
	Value    string
	IsActive bool
}

// FindingSnapshot is a simplified finding representation for diffing.
type FindingSnapshot struct {
	ID       string
	AssetID  string
	Title    string
	Severity string
	Status   string
}

// Calculate computes the diff between two sets of asset and finding snapshots.
func Calculate(
	fromAssets, toAssets []AssetSnapshot,
	fromFindings, toFindings []FindingSnapshot,
	fromTime, toTime time.Time,
) SurfaceDiff {
	diff := SurfaceDiff{
		FromTime: fromTime,
		ToTime:   toTime,
	}

	// Build asset lookup maps
	fromAssetMap := make(map[string]AssetSnapshot, len(fromAssets))
	for _, a := range fromAssets {
		fromAssetMap[a.Value] = a
	}
	toAssetMap := make(map[string]AssetSnapshot, len(toAssets))
	for _, a := range toAssets {
		toAssetMap[a.Value] = a
	}

	// Assets added (in "to" but not in "from")
	for _, a := range toAssets {
		if _, exists := fromAssetMap[a.Value]; !exists {
			diff.AssetsAdded = append(diff.AssetsAdded, AssetChange{
				AssetID: a.ID,
				Type:    a.Type,
				Value:   a.Value,
				Change:  "added",
			})
		}
	}

	// Assets removed (in "from" but not in "to")
	for _, a := range fromAssets {
		if _, exists := toAssetMap[a.Value]; !exists {
			diff.AssetsRemoved = append(diff.AssetsRemoved, AssetChange{
				AssetID: a.ID,
				Type:    a.Type,
				Value:   a.Value,
				Change:  "removed",
			})
		}
	}

	// Build finding lookup maps by title+asset combo for deduplication
	findingKey := func(f FindingSnapshot) string {
		return f.AssetID + ":" + f.Title
	}

	fromFindingMap := make(map[string]FindingSnapshot, len(fromFindings))
	for _, f := range fromFindings {
		fromFindingMap[findingKey(f)] = f
	}
	toFindingMap := make(map[string]FindingSnapshot, len(toFindings))
	for _, f := range toFindings {
		toFindingMap[findingKey(f)] = f
	}

	// New findings (open in "to" but not in "from")
	for _, f := range toFindings {
		if f.Status != "open" {
			continue
		}
		prev, exists := fromFindingMap[findingKey(f)]
		if !exists || prev.Status != "open" {
			diff.FindingsNew = append(diff.FindingsNew, FindingChange{
				FindingID: f.ID,
				AssetID:   f.AssetID,
				Title:     f.Title,
				Severity:  f.Severity,
				Change:    "new",
			})
		}
	}

	// Fixed findings (open in "from" but resolved/absent in "to")
	for _, f := range fromFindings {
		if f.Status != "open" {
			continue
		}
		current, exists := toFindingMap[findingKey(f)]
		if !exists || current.Status != "open" {
			diff.FindingsFixed = append(diff.FindingsFixed, FindingChange{
				FindingID: f.ID,
				AssetID:   f.AssetID,
				Title:     f.Title,
				Severity:  f.Severity,
				Change:    "resolved",
			})
		}
	}

	diff.Summary = DiffSummary{
		AssetsAdded:   len(diff.AssetsAdded),
		AssetsRemoved: len(diff.AssetsRemoved),
		FindingsNew:   len(diff.FindingsNew),
		FindingsFixed: len(diff.FindingsFixed),
	}

	return diff
}
