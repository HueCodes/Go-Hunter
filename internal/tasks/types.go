package tasks

import (
	"encoding/json"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
)

// Task type names
const (
	TypeAssetDiscovery = "scan:asset_discovery"
	TypePortScan       = "scan:port_scan"
	TypeHTTPProbe      = "scan:http_probe"
	TypeCrawl          = "scan:crawl"
	TypeVulnCheck      = "scan:vuln_check"
	TypeSchedulerTick  = "scheduler:tick"
)

// AssetDiscoveryPayload contains the data for an asset discovery task
type AssetDiscoveryPayload struct {
	ScanID         uuid.UUID   `json:"scan_id"`
	OrganizationID uuid.UUID   `json:"organization_id"`
	CredentialIDs  []uuid.UUID `json:"credential_ids"`
}

func NewAssetDiscoveryTask(payload AssetDiscoveryPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TypeAssetDiscovery, data), nil
}

// PortScanPayload contains the data for a port scan task
type PortScanPayload struct {
	ScanID         uuid.UUID   `json:"scan_id"`
	OrganizationID uuid.UUID   `json:"organization_id"`
	AssetIDs       []uuid.UUID `json:"asset_ids"`
	Ports          string      `json:"ports"` // e.g., "1-1000" or "80,443,8080"
	RateLimit      int         `json:"rate_limit"`
}

func NewPortScanTask(payload PortScanPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TypePortScan, data), nil
}

// HTTPProbePayload contains the data for an HTTP probe task
type HTTPProbePayload struct {
	ScanID         uuid.UUID   `json:"scan_id"`
	OrganizationID uuid.UUID   `json:"organization_id"`
	AssetIDs       []uuid.UUID `json:"asset_ids"`
	Ports          []int       `json:"ports"`
	FollowRedirect bool        `json:"follow_redirect"`
}

func NewHTTPProbeTask(payload HTTPProbePayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TypeHTTPProbe, data), nil
}

// CrawlPayload contains the data for a crawl task
type CrawlPayload struct {
	ScanID         uuid.UUID   `json:"scan_id"`
	OrganizationID uuid.UUID   `json:"organization_id"`
	AssetIDs       []uuid.UUID `json:"asset_ids"`
	MaxDepth       int         `json:"max_depth"`
	MaxPages       int         `json:"max_pages"`
}

func NewCrawlTask(payload CrawlPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TypeCrawl, data), nil
}

// VulnCheckPayload contains the data for a vulnerability check task
type VulnCheckPayload struct {
	ScanID         uuid.UUID   `json:"scan_id"`
	OrganizationID uuid.UUID   `json:"organization_id"`
	AssetIDs       []uuid.UUID `json:"asset_ids"`
	CheckTypes     []string    `json:"check_types"` // e.g., ["exposed_bucket", "open_ports", "outdated_ssl"]
}

func NewVulnCheckTask(payload VulnCheckPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TypeVulnCheck, data), nil
}

// SchedulerTickPayload is empty - the scheduler checks all organizations
type SchedulerTickPayload struct{}

func NewSchedulerTickTask() *asynq.Task {
	return asynq.NewTask(TypeSchedulerTick, nil)
}
