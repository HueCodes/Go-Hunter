package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/hugh/go-hunter/internal/assets"
	"github.com/hugh/go-hunter/internal/database/models"
	"github.com/hugh/go-hunter/internal/scanner"
	"github.com/hugh/go-hunter/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Handler struct {
	db           *gorm.DB
	logger       *slog.Logger
	assetService *assets.Service
	encryptor    *crypto.Encryptor
}

func NewHandler(db *gorm.DB, logger *slog.Logger, encryptor *crypto.Encryptor) *Handler {
	return &Handler{
		db:           db,
		logger:       logger,
		assetService: assets.NewService(db, encryptor, logger),
		encryptor:    encryptor,
	}
}

func (h *Handler) RegisterHandlers(mux *asynq.ServeMux) {
	mux.HandleFunc(TypeAssetDiscovery, h.HandleAssetDiscovery)
	mux.HandleFunc(TypePortScan, h.HandlePortScan)
	mux.HandleFunc(TypeHTTPProbe, h.HandleHTTPProbe)
	mux.HandleFunc(TypeCrawl, h.HandleCrawl)
	mux.HandleFunc(TypeVulnCheck, h.HandleVulnCheck)
}

func (h *Handler) HandleAssetDiscovery(ctx context.Context, t *asynq.Task) error {
	var payload AssetDiscoveryPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	h.logger.Info("starting asset discovery",
		"scan_id", payload.ScanID,
		"org_id", payload.OrganizationID,
		"credentials", len(payload.CredentialIDs),
	)

	// Update scan status to running
	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusRunning); err != nil {
		return err
	}

	// Run discovery for all credentials
	discovered, err := h.assetService.DiscoverAssets(ctx, payload.OrganizationID, payload.CredentialIDs)
	if err != nil {
		h.logger.Error("asset discovery failed", "error", err)
		if updateErr := h.updateScanStatusWithError(payload.ScanID, models.ScanStatusFailed, err.Error()); updateErr != nil {
			h.logger.Error("failed to update scan status", "error", updateErr)
		}
		return err
	}

	// Save discovered assets to database
	savedCount, err := h.assetService.SaveDiscoveredAssets(ctx, payload.OrganizationID, nil, discovered)
	if err != nil {
		h.logger.Error("failed to save assets", "error", err)
	}

	// Update scan with results
	if err := h.updateScanWithResults(payload.ScanID, savedCount, 0); err != nil {
		h.logger.Error("failed to update scan results", "error", err)
	}

	// Mark scan as completed
	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusCompleted); err != nil {
		return err
	}

	h.logger.Info("completed asset discovery",
		"scan_id", payload.ScanID,
		"discovered", len(discovered),
		"saved", savedCount,
	)

	return nil
}

func (h *Handler) HandlePortScan(ctx context.Context, t *asynq.Task) error {
	var payload PortScanPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	h.logger.Info("starting port scan",
		"scan_id", payload.ScanID,
		"assets", len(payload.AssetIDs),
		"ports", payload.Ports,
	)

	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusRunning); err != nil {
		return err
	}

	// TODO: Implement port scanning using naabu library
	// - Load assets from database
	// - Run port scan on each asset
	// - Create Finding records for open ports

	time.Sleep(2 * time.Second)

	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusCompleted); err != nil {
		return err
	}

	h.logger.Info("completed port scan", "scan_id", payload.ScanID)
	return nil
}

func (h *Handler) HandleHTTPProbe(ctx context.Context, t *asynq.Task) error {
	var payload HTTPProbePayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	h.logger.Info("starting HTTP probe",
		"scan_id", payload.ScanID,
		"assets", len(payload.AssetIDs),
	)

	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusRunning); err != nil {
		return err
	}

	// TODO: Implement HTTP probing
	// - Check if HTTP/HTTPS services are running
	// - Extract headers, titles, technologies
	// - Create findings for interesting discoveries

	time.Sleep(2 * time.Second)

	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusCompleted); err != nil {
		return err
	}

	h.logger.Info("completed HTTP probe", "scan_id", payload.ScanID)
	return nil
}

func (h *Handler) HandleCrawl(ctx context.Context, t *asynq.Task) error {
	var payload CrawlPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	h.logger.Info("starting crawl",
		"scan_id", payload.ScanID,
		"assets", len(payload.AssetIDs),
		"max_depth", payload.MaxDepth,
	)

	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusRunning); err != nil {
		return err
	}

	// TODO: Implement web crawling
	// - Crawl web applications
	// - Discover endpoints, forms, JavaScript files
	// - Create Asset records for discovered endpoints

	time.Sleep(2 * time.Second)

	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusCompleted); err != nil {
		return err
	}

	h.logger.Info("completed crawl", "scan_id", payload.ScanID)
	return nil
}

func (h *Handler) HandleVulnCheck(ctx context.Context, t *asynq.Task) error {
	var payload VulnCheckPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	h.logger.Info("starting vulnerability check",
		"scan_id", payload.ScanID,
		"assets", len(payload.AssetIDs),
		"checks", payload.CheckTypes,
	)

	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusRunning); err != nil {
		return err
	}

	// Check if exposed_bucket check is requested
	shouldCheckBuckets := len(payload.CheckTypes) == 0 // If no types specified, run all
	for _, ct := range payload.CheckTypes {
		if ct == "exposed_bucket" {
			shouldCheckBuckets = true
			break
		}
	}

	var totalFindings int

	if shouldCheckBuckets {
		findings, err := h.runS3BucketChecks(ctx, payload)
		if err != nil {
			h.logger.Error("S3 bucket checks failed", "error", err)
			// Continue with other checks, don't fail the entire scan
		}
		totalFindings += findings
	}

	// Update scan with results
	if err := h.updateScanWithResults(payload.ScanID, len(payload.AssetIDs), totalFindings); err != nil {
		h.logger.Error("failed to update scan results", "error", err)
	}

	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusCompleted); err != nil {
		return err
	}

	h.logger.Info("completed vulnerability check",
		"scan_id", payload.ScanID,
		"findings", totalFindings,
	)
	return nil
}

// runS3BucketChecks performs security checks on S3 bucket assets
func (h *Handler) runS3BucketChecks(ctx context.Context, payload VulnCheckPayload) (int, error) {
	// Load S3 bucket assets
	var bucketAssets []models.Asset
	query := h.db.WithContext(ctx).
		Where("organization_id = ?", payload.OrganizationID).
		Where("type = ?", models.AssetTypeBucket).
		Where("source LIKE ?", "aws:%").
		Where("is_active = ?", true)

	// If specific asset IDs provided, filter by them
	if len(payload.AssetIDs) > 0 {
		query = query.Where("id IN ?", payload.AssetIDs)
	}

	if err := query.Find(&bucketAssets).Error; err != nil {
		return 0, fmt.Errorf("loading bucket assets: %w", err)
	}

	if len(bucketAssets) == 0 {
		h.logger.Debug("no S3 bucket assets to check")
		return 0, nil
	}

	h.logger.Info("checking S3 buckets",
		"count", len(bucketAssets),
	)

	// Group buckets by credential for efficient processing
	credentialBuckets := make(map[uuid.UUID][]models.Asset)
	for _, asset := range bucketAssets {
		if asset.CredentialID != uuid.Nil {
			credentialBuckets[asset.CredentialID] = append(credentialBuckets[asset.CredentialID], asset)
		}
	}

	var totalFindings int

	// Process each credential's buckets
	for credID, buckets := range credentialBuckets {
		// Load and decrypt credential
		var cred models.CloudCredential
		if err := h.db.WithContext(ctx).First(&cred, "id = ?", credID).Error; err != nil {
			h.logger.Warn("failed to load credential",
				"credential_id", credID,
				"error", err,
			)
			continue
		}

		if cred.Provider != models.ProviderAWS {
			continue
		}

		// Decrypt credential
		decrypted, err := h.encryptor.Decrypt(cred.EncryptedData)
		if err != nil {
			h.logger.Error("failed to decrypt credential",
				"credential_id", credID,
				"error", err,
			)
			continue
		}

		var awsCred assets.AWSCredential
		if err := json.Unmarshal(decrypted, &awsCred); err != nil {
			h.logger.Error("failed to parse AWS credentials",
				"credential_id", credID,
				"error", err,
			)
			continue
		}

		// Create S3 checker
		checker := scanner.NewS3Checker(awsCred, h.logger)

		// Check each bucket
		for _, bucket := range buckets {
			findings, err := checker.CheckBucket(ctx, bucket.Value, bucket.ID, payload.ScanID, payload.OrganizationID)
			if err != nil {
				h.logger.Error("failed to check bucket",
					"bucket", bucket.Value,
					"error", err,
				)
				continue
			}

			// Persist findings with deduplication
			for _, finding := range findings {
				if err := h.saveFinding(ctx, finding); err != nil {
					h.logger.Error("failed to save finding",
						"bucket", bucket.Value,
						"title", finding.Title,
						"error", err,
					)
					continue
				}
				totalFindings++
			}
		}
	}

	return totalFindings, nil
}

// saveFinding persists a finding with deduplication via hash
func (h *Handler) saveFinding(ctx context.Context, finding models.Finding) error {
	result := h.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "hash"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"last_seen_at",
			"scan_id",
			"evidence",
			"raw_data",
		}),
	}).Create(&finding)

	return result.Error
}

func (h *Handler) updateScanStatus(scanID interface{}, status models.ScanStatus) error {
	updates := map[string]interface{}{
		"status":     status,
		"updated_at": time.Now(),
	}

	if status == models.ScanStatusRunning {
		updates["started_at"] = time.Now().Unix()
	} else if status == models.ScanStatusCompleted || status == models.ScanStatusFailed {
		updates["completed_at"] = time.Now().Unix()
	}

	return h.db.Model(&models.Scan{}).Where("id = ?", scanID).Updates(updates).Error
}

func (h *Handler) updateScanStatusWithError(scanID interface{}, status models.ScanStatus, errMsg string) error {
	updates := map[string]interface{}{
		"status":       status,
		"error":        errMsg,
		"updated_at":   time.Now(),
		"completed_at": time.Now().Unix(),
	}

	return h.db.Model(&models.Scan{}).Where("id = ?", scanID).Updates(updates).Error
}

func (h *Handler) updateScanWithResults(scanID interface{}, assetsScanned, findingsCount int) error {
	updates := map[string]interface{}{
		"assets_scanned":  assetsScanned,
		"findings_count":  findingsCount,
		"updated_at":      time.Now(),
	}

	return h.db.Model(&models.Scan{}).Where("id = ?", scanID).Updates(updates).Error
}
