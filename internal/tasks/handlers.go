package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"
	"github.com/hugh/go-hunter/internal/assets"
	"github.com/hugh/go-hunter/internal/database/models"
	"github.com/hugh/go-hunter/pkg/crypto"
	"gorm.io/gorm"
)

type Handler struct {
	db           *gorm.DB
	logger       *slog.Logger
	assetService *assets.Service
}

func NewHandler(db *gorm.DB, logger *slog.Logger, encryptor *crypto.Encryptor) *Handler {
	return &Handler{
		db:           db,
		logger:       logger,
		assetService: assets.NewService(db, encryptor, logger),
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

	// TODO: Implement vulnerability checking
	// - Run custom checks (exposed buckets, SSL issues, etc.)
	// - Create Finding records with severity levels

	time.Sleep(2 * time.Second)

	if err := h.updateScanStatus(payload.ScanID, models.ScanStatusCompleted); err != nil {
		return err
	}

	h.logger.Info("completed vulnerability check", "scan_id", payload.ScanID)
	return nil
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
