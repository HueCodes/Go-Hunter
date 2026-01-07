package scanner

import (
	"context"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/assets/types"
	"github.com/hugh/go-hunter/internal/database/models"
)

// PortScannerInterface defines the interface for port scanning operations.
type PortScannerInterface interface {
	ScanHost(ctx context.Context, host string, ports []int) []PortScanResult
	ResultsToFindings(host string, results []PortScanResult, assetID, scanID, orgID uuid.UUID) []models.Finding
}

// HTTPProberInterface defines the interface for HTTP probing operations.
type HTTPProberInterface interface {
	ProbeHost(ctx context.Context, host string, ports []int) []HTTPProbeResult
	ResultsToFindings(host string, results []HTTPProbeResult, assetID, scanID, orgID uuid.UUID) []models.Finding
}

// WebCrawlerInterface defines the interface for web crawling operations.
type WebCrawlerInterface interface {
	CrawlURL(ctx context.Context, startURL string) (*CrawlResult, error)
	ResultsToFindings(result *CrawlResult, assetID, scanID, orgID uuid.UUID) []models.Finding
	ResultsToAssets(result *CrawlResult, orgID uuid.UUID, parentAssetID *uuid.UUID) []models.Asset
}

// S3CheckerInterface defines the interface for S3 bucket security checks.
type S3CheckerInterface interface {
	CheckBucket(ctx context.Context, bucketName string, assetID, scanID, orgID uuid.UUID) ([]models.Finding, error)
}

// S3CheckerFactory creates S3Checker instances with credentials.
type S3CheckerFactory interface {
	NewChecker(creds types.AWSCredential) S3CheckerInterface
}

// Compile-time interface satisfaction checks
var (
	_ PortScannerInterface = (*PortScanner)(nil)
	_ HTTPProberInterface  = (*HTTPProber)(nil)
	_ WebCrawlerInterface  = (*WebCrawler)(nil)
	_ S3CheckerInterface   = (*S3Checker)(nil)
)
