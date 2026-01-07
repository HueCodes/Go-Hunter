package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/hugh/go-hunter/internal/assets"
	"github.com/hugh/go-hunter/internal/database/models"
	"github.com/hugh/go-hunter/internal/scanner"
	"github.com/hugh/go-hunter/pkg/crypto"
	"github.com/hugh/go-hunter/pkg/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Handler struct {
	db           *gorm.DB
	logger       *slog.Logger
	assetService *assets.Service
	encryptor    *crypto.Encryptor
	asynqClient  *asynq.Client
}

func NewHandler(db *gorm.DB, logger *slog.Logger, encryptor *crypto.Encryptor, asynqClient *asynq.Client) *Handler {
	return &Handler{
		db:           db,
		logger:       logger,
		assetService: assets.NewService(db, encryptor, logger),
		encryptor:    encryptor,
		asynqClient:  asynqClient,
	}
}

func (h *Handler) RegisterHandlers(mux *asynq.ServeMux) {
	mux.HandleFunc(TypeAssetDiscovery, h.HandleAssetDiscovery)
	mux.HandleFunc(TypePortScan, h.HandlePortScan)
	mux.HandleFunc(TypeHTTPProbe, h.HandleHTTPProbe)
	mux.HandleFunc(TypeCrawl, h.HandleCrawl)
	mux.HandleFunc(TypeVulnCheck, h.HandleVulnCheck)
	mux.HandleFunc(TypeSchedulerTick, h.HandleSchedulerTick)
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
		if updateErr := h.updateScanStatusWithError(payload.ScanID, models.ScanStatusFailed, err.Error()); updateErr != nil {
			h.logger.Error("failed to update scan status", "error", updateErr)
		}
		return fmt.Errorf("saving discovered assets: %w", err)
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

	// Parse port specification
	ports, err := scanner.ParsePorts(payload.Ports)
	if err != nil {
		h.logger.Error("failed to parse ports", "error", err)
		if updateErr := h.updateScanStatusWithError(payload.ScanID, models.ScanStatusFailed, err.Error()); updateErr != nil {
			h.logger.Error("failed to update scan status", "error", updateErr)
		}
		return fmt.Errorf("parsing ports: %w", err)
	}

	// Load scannable assets (IPs and domains)
	var assets []models.Asset
	query := h.db.WithContext(ctx).
		Where("organization_id = ?", payload.OrganizationID).
		Where("type IN ?", []models.AssetType{models.AssetTypeIP, models.AssetTypeDomain, models.AssetTypeSubdomain}).
		Where("is_active = ?", true)

	if len(payload.AssetIDs) > 0 {
		query = query.Where("id IN ?", payload.AssetIDs)
	}

	if err := query.Find(&assets).Error; err != nil {
		h.logger.Error("failed to load assets", "error", err)
		if updateErr := h.updateScanStatusWithError(payload.ScanID, models.ScanStatusFailed, err.Error()); updateErr != nil {
			h.logger.Error("failed to update scan status", "error", updateErr)
		}
		return fmt.Errorf("loading assets: %w", err)
	}

	if len(assets) == 0 {
		h.logger.Info("no scannable assets found", "scan_id", payload.ScanID)
		if err := h.updateScanStatus(payload.ScanID, models.ScanStatusCompleted); err != nil {
			return err
		}
		return nil
	}

	// Configure scanner
	concurrency := 100
	if payload.RateLimit > 0 && payload.RateLimit < concurrency {
		concurrency = payload.RateLimit
	}

	portScanner := scanner.NewPortScanner(h.logger, &scanner.PortScanConfig{
		Timeout:     3 * time.Second,
		Concurrency: concurrency,
	})

	var totalFindings int
	var totalOpenPorts int

	// Scan each asset
	for _, asset := range assets {
		h.logger.Debug("scanning asset",
			"asset_id", asset.ID,
			"host", asset.Value,
			"ports", len(ports),
		)

		results := portScanner.ScanHost(ctx, asset.Value, ports)
		totalOpenPorts += len(results)

		// Convert results to findings
		findings := portScanner.ResultsToFindings(asset.Value, results, asset.ID, payload.ScanID, payload.OrganizationID)

		// Save findings
		for _, finding := range findings {
			if err := h.saveFinding(ctx, finding); err != nil {
				h.logger.Error("failed to save port finding",
					"host", asset.Value,
					"port", finding.Port,
					"error", err,
				)
				continue
			}
			totalFindings++
		}
	}

	// Update scan with results
	if err := h.updateScanWithPortResults(payload.ScanID, len(assets), totalFindings, totalOpenPorts); err != nil {
		h.logger.Error("failed to update scan results", "error", err)
	}

	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusCompleted); err != nil {
		return err
	}

	h.logger.Info("completed port scan",
		"scan_id", payload.ScanID,
		"assets_scanned", len(assets),
		"open_ports", totalOpenPorts,
		"findings", totalFindings,
	)
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
		"ports", payload.Ports,
	)

	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusRunning); err != nil {
		return err
	}

	// Determine ports to probe
	ports := payload.Ports
	if len(ports) == 0 {
		// Default HTTP/HTTPS ports
		ports = []int{80, 443, 8080, 8443, 8000, 3000, 5000, 9443}
	}

	// Load scannable assets (IPs and domains)
	var assets []models.Asset
	query := h.db.WithContext(ctx).
		Where("organization_id = ?", payload.OrganizationID).
		Where("type IN ?", []models.AssetType{models.AssetTypeIP, models.AssetTypeDomain, models.AssetTypeSubdomain}).
		Where("is_active = ?", true)

	if len(payload.AssetIDs) > 0 {
		query = query.Where("id IN ?", payload.AssetIDs)
	}

	if err := query.Find(&assets).Error; err != nil {
		h.logger.Error("failed to load assets", "error", err)
		if updateErr := h.updateScanStatusWithError(payload.ScanID, models.ScanStatusFailed, err.Error()); updateErr != nil {
			h.logger.Error("failed to update scan status", "error", updateErr)
		}
		return fmt.Errorf("loading assets: %w", err)
	}

	if len(assets) == 0 {
		h.logger.Info("no scannable assets found", "scan_id", payload.ScanID)
		if err := h.updateScanStatus(payload.ScanID, models.ScanStatusCompleted); err != nil {
			return err
		}
		return nil
	}

	// Configure prober
	prober := scanner.NewHTTPProber(h.logger, &scanner.HTTPProbeConfig{
		Timeout:        10 * time.Second,
		Concurrency:    50,
		FollowRedirect: payload.FollowRedirect,
	})

	var totalFindings int
	var totalServices int

	// Probe each asset
	for _, asset := range assets {
		h.logger.Debug("probing asset",
			"asset_id", asset.ID,
			"host", asset.Value,
			"ports", len(ports),
		)

		results := prober.ProbeHost(ctx, asset.Value, ports)
		totalServices += len(results)

		// Convert results to findings
		findings := prober.ResultsToFindings(asset.Value, results, asset.ID, payload.ScanID, payload.OrganizationID)

		// Save findings
		for _, finding := range findings {
			if err := h.saveFinding(ctx, finding); err != nil {
				h.logger.Error("failed to save HTTP finding",
					"host", asset.Value,
					"title", finding.Title,
					"error", err,
				)
				continue
			}
			totalFindings++
		}
	}

	// Update scan with results
	if err := h.updateScanWithHTTPResults(payload.ScanID, len(assets), totalFindings, totalServices); err != nil {
		h.logger.Error("failed to update scan results", "error", err)
	}

	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusCompleted); err != nil {
		return err
	}

	h.logger.Info("completed HTTP probe",
		"scan_id", payload.ScanID,
		"assets_scanned", len(assets),
		"services_found", totalServices,
		"findings", totalFindings,
	)
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

	// Set defaults
	maxDepth := payload.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 3
	}
	maxPages := payload.MaxPages
	if maxPages <= 0 {
		maxPages = 100
	}

	// Load endpoint assets (URLs to crawl)
	var assets []models.Asset
	query := h.db.WithContext(ctx).
		Where("organization_id = ?", payload.OrganizationID).
		Where("type IN ?", []models.AssetType{models.AssetTypeEndpoint, models.AssetTypeDomain, models.AssetTypeSubdomain}).
		Where("is_active = ?", true)

	if len(payload.AssetIDs) > 0 {
		query = query.Where("id IN ?", payload.AssetIDs)
	}

	if err := query.Find(&assets).Error; err != nil {
		h.logger.Error("failed to load assets", "error", err)
		if updateErr := h.updateScanStatusWithError(payload.ScanID, models.ScanStatusFailed, err.Error()); updateErr != nil {
			h.logger.Error("failed to update scan status", "error", updateErr)
		}
		return fmt.Errorf("loading assets: %w", err)
	}

	if len(assets) == 0 {
		h.logger.Info("no crawlable assets found", "scan_id", payload.ScanID)
		if err := h.updateScanStatus(payload.ScanID, models.ScanStatusCompleted); err != nil {
			return err
		}
		return nil
	}

	// Configure crawler
	crawler := scanner.NewWebCrawler(h.logger, &scanner.WebCrawlerConfig{
		Timeout:     15 * time.Second,
		MaxDepth:    maxDepth,
		MaxPages:    maxPages,
		Concurrency: 10,
	})

	var totalFindings int
	var totalPagesCrawled int

	// Crawl each asset
	for _, asset := range assets {
		// Determine URL to crawl
		var crawlURL string
		if strings.HasPrefix(asset.Value, "http://") || strings.HasPrefix(asset.Value, "https://") {
			crawlURL = asset.Value
		} else {
			// Default to HTTPS for domains
			crawlURL = "https://" + asset.Value
		}

		h.logger.Debug("crawling asset",
			"asset_id", asset.ID,
			"url", crawlURL,
		)

		result, err := crawler.CrawlURL(ctx, crawlURL)
		if err != nil {
			h.logger.Error("failed to crawl",
				"url", crawlURL,
				"error", err,
			)
			continue
		}

		totalPagesCrawled += result.PagesCrawled

		// Convert results to findings
		findings := crawler.ResultsToFindings(result, asset.ID, payload.ScanID, payload.OrganizationID)

		// Save findings
		for _, finding := range findings {
			if err := h.saveFinding(ctx, finding); err != nil {
				h.logger.Error("failed to save crawl finding",
					"url", crawlURL,
					"title", finding.Title,
					"error", err,
				)
				continue
			}
			totalFindings++
		}

		// Convert discovered endpoints to assets
		newAssets := crawler.ResultsToAssets(result, payload.OrganizationID, &asset.ID)
		for _, newAsset := range newAssets {
			if err := h.saveDiscoveredAsset(ctx, newAsset); err != nil {
				h.logger.Debug("failed to save discovered asset",
					"value", newAsset.Value,
					"error", err,
				)
			}
		}
	}

	// Update scan with results
	if err := h.updateScanWithCrawlResults(payload.ScanID, len(assets), totalFindings, totalPagesCrawled); err != nil {
		h.logger.Error("failed to update scan results", "error", err)
	}

	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusCompleted); err != nil {
		return err
	}

	h.logger.Info("completed crawl",
		"scan_id", payload.ScanID,
		"assets_crawled", len(assets),
		"pages_crawled", totalPagesCrawled,
		"findings", totalFindings,
	)
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
		"assets_scanned": assetsScanned,
		"findings_count": findingsCount,
		"updated_at":     time.Now(),
	}

	return h.db.Model(&models.Scan{}).Where("id = ?", scanID).Updates(updates).Error
}

func (h *Handler) updateScanWithPortResults(scanID interface{}, assetsScanned, findingsCount, portsOpen int) error {
	updates := map[string]interface{}{
		"assets_scanned": assetsScanned,
		"findings_count": findingsCount,
		"ports_open":     portsOpen,
		"updated_at":     time.Now(),
	}

	return h.db.Model(&models.Scan{}).Where("id = ?", scanID).Updates(updates).Error
}

func (h *Handler) updateScanWithHTTPResults(scanID interface{}, assetsScanned, findingsCount, servicesFound int) error {
	updates := map[string]interface{}{
		"assets_scanned": assetsScanned,
		"findings_count": findingsCount,
		"services_found": servicesFound,
		"updated_at":     time.Now(),
	}

	return h.db.Model(&models.Scan{}).Where("id = ?", scanID).Updates(updates).Error
}

func (h *Handler) updateScanWithCrawlResults(scanID interface{}, assetsScanned, findingsCount, pagesCrawled int) error {
	updates := map[string]interface{}{
		"assets_scanned": assetsScanned,
		"findings_count": findingsCount,
		"updated_at":     time.Now(),
	}

	return h.db.Model(&models.Scan{}).Where("id = ?", scanID).Updates(updates).Error
}

func (h *Handler) saveDiscoveredAsset(ctx context.Context, asset models.Asset) error {
	result := h.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "organization_id"},
			{Name: "type"},
			{Name: "value"},
		},
		DoUpdates: clause.AssignmentColumns([]string{
			"last_seen_at",
			"source",
			"metadata",
			"is_active",
		}),
	}).Create(&asset)

	return result.Error
}

// HandleSchedulerTick processes scheduled scans that are due to run
func (h *Handler) HandleSchedulerTick(ctx context.Context, t *asynq.Task) error {
	now := time.Now().Unix()

	h.logger.Debug("scheduler tick", "now", now)

	// Find all enabled schedules where next_run_at <= now
	var schedules []models.ScheduledScan
	if err := h.db.WithContext(ctx).
		Where("is_enabled = ? AND next_run_at <= ? AND deleted_at IS NULL", true, now).
		Find(&schedules).Error; err != nil {
		return fmt.Errorf("querying due schedules: %w", err)
	}

	if len(schedules) == 0 {
		h.logger.Debug("no scheduled scans due")
		return nil
	}

	h.logger.Info("processing scheduled scans", "count", len(schedules))

	for _, sched := range schedules {
		if err := h.runScheduledScan(ctx, &sched); err != nil {
			h.logger.Error("failed to run scheduled scan",
				"schedule_id", sched.ID,
				"name", sched.Name,
				"error", err,
			)
			// Continue with other schedules
			continue
		}
	}

	return nil
}

// runScheduledScan creates and enqueues a scan from a schedule, then updates the schedule
func (h *Handler) runScheduledScan(ctx context.Context, sched *models.ScheduledScan) error {
	// Create a scan from the schedule
	scan := models.Scan{
		OrganizationID: sched.OrganizationID,
		Type:           sched.ScanType,
		Status:         models.ScanStatusPending,
		TargetAssetIDs: sched.TargetAssetIDs,
		CredentialIDs:  sched.CredentialIDs,
		Config:         sched.Config,
	}

	if err := h.db.WithContext(ctx).Create(&scan).Error; err != nil {
		return fmt.Errorf("creating scan: %w", err)
	}

	h.logger.Info("created scan from schedule",
		"schedule_id", sched.ID,
		"scan_id", scan.ID,
		"type", scan.Type,
	)

	// Enqueue the task
	if h.asynqClient != nil {
		task, err := h.createScanTask(scan)
		if err != nil {
			h.logger.Error("failed to create task", "error", err)
		} else if task != nil {
			info, err := h.asynqClient.EnqueueContext(ctx, task)
			if err != nil {
				h.logger.Error("failed to enqueue task", "error", err)
			} else {
				h.logger.Info("enqueued scan task",
					"scan_id", scan.ID,
					"task_id", info.ID,
				)
				// Update scan with task ID
				_ = h.db.Model(&scan).Update("task_id", info.ID)
			}
		}
	}

	// Calculate next run time
	nextRun, err := util.NextCronTime(sched.CronExpr, time.Now())
	if err != nil {
		h.logger.Error("failed to calculate next run time",
			"schedule_id", sched.ID,
			"cron_expr", sched.CronExpr,
			"error", err,
		)
		// Disable the schedule if cron expression is invalid
		_ = h.db.Model(sched).Update("is_enabled", false)
		return fmt.Errorf("invalid cron expression: %w", err)
	}

	// Update schedule with last run info and next run time
	now := time.Now().Unix()
	if err := h.db.Model(sched).Updates(map[string]interface{}{
		"last_run_at":  now,
		"last_scan_id": scan.ID,
		"next_run_at":  nextRun.Unix(),
	}).Error; err != nil {
		return fmt.Errorf("updating schedule: %w", err)
	}

	return nil
}

// createScanTask creates an asynq task for a scan
func (h *Handler) createScanTask(scan models.Scan) (*asynq.Task, error) {
	switch scan.Type {
	case models.ScanTypeDiscovery:
		return NewAssetDiscoveryTask(AssetDiscoveryPayload{
			ScanID:         scan.ID,
			OrganizationID: scan.OrganizationID,
			CredentialIDs:  scan.CredentialIDs,
		})
	case models.ScanTypePortScan:
		return NewPortScanTask(PortScanPayload{
			ScanID:         scan.ID,
			OrganizationID: scan.OrganizationID,
			AssetIDs:       scan.TargetAssetIDs,
		})
	case models.ScanTypeHTTPProbe:
		return NewHTTPProbeTask(HTTPProbePayload{
			ScanID:         scan.ID,
			OrganizationID: scan.OrganizationID,
			AssetIDs:       scan.TargetAssetIDs,
		})
	case models.ScanTypeCrawl:
		return NewCrawlTask(CrawlPayload{
			ScanID:         scan.ID,
			OrganizationID: scan.OrganizationID,
			AssetIDs:       scan.TargetAssetIDs,
		})
	case models.ScanTypeVulnCheck:
		return NewVulnCheckTask(VulnCheckPayload{
			ScanID:         scan.ID,
			OrganizationID: scan.OrganizationID,
			AssetIDs:       scan.TargetAssetIDs,
		})
	default:
		return nil, nil
	}
}
