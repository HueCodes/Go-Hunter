package notifications

import "context"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type EventType string

const (
	EventNewFinding      EventType = "finding.created"
	EventScanCompleted   EventType = "scan.completed"
	EventScanFailed      EventType = "scan.failed"
	EventAssetDiscovered EventType = "asset.discovered"
	EventAssetRemoved    EventType = "asset.removed"
)

type Notification struct {
	EventType EventType         `json:"event_type"`
	Title     string            `json:"title"`
	Message   string            `json:"message"`
	Severity  Severity          `json:"severity,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
	URL       string            `json:"url,omitempty"`
}

type Provider interface {
	Name() string
	Send(ctx context.Context, notification Notification) error
	Validate() error
}
