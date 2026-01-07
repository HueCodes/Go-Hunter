package cloudflare

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cloudflare/cloudflare-go"

	"github.com/hugh/go-hunter/internal/assets/types"
	"github.com/hugh/go-hunter/internal/database/models"
)

// Provider implements cloud asset discovery for Cloudflare
type Provider struct {
	creds  types.CloudflareCredential
	cfg    types.ProviderConfig
	logger *slog.Logger
	api    *cloudflare.API
}

// New creates a new Cloudflare provider instance
func New(creds types.CloudflareCredential, cfg types.ProviderConfig, logger *slog.Logger) *Provider {
	return &Provider{
		creds:  creds,
		cfg:    cfg,
		logger: logger,
	}
}

// Name returns the provider identifier
func (p *Provider) Name() models.CloudProvider {
	return models.ProviderCloudflare
}

// ValidateCredentials checks if the Cloudflare credentials are valid
func (p *Provider) ValidateCredentials(ctx context.Context) error {
	api, err := p.getAPI()
	if err != nil {
		return fmt.Errorf("invalid Cloudflare credentials: %w", err)
	}

	// Test by verifying token
	_, err = api.VerifyAPIToken(ctx)
	if err != nil {
		return fmt.Errorf("invalid Cloudflare credentials: %w", err)
	}

	p.api = api
	return nil
}

// Discover finds all Cloudflare assets
func (p *Provider) Discover(ctx context.Context) ([]types.DiscoveredAsset, error) {
	if p.api == nil {
		api, err := p.getAPI()
		if err != nil {
			return nil, err
		}
		p.api = api
	}

	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	// Get zones to discover
	zones, err := p.getZones(ctx)
	if err != nil {
		errors = append(errors, types.DiscoveryError{
			Resource: "zones",
			Message:  err.Error(),
		})
	}

	for _, zone := range zones {
		// Discover DNS records
		dnsAssets, dnsErrors := p.discoverDNSRecords(ctx, zone)
		discovered = append(discovered, dnsAssets...)
		errors = append(errors, dnsErrors...)

		// Discover Workers (if any)
		workerAssets, workerErrors := p.discoverWorkers(ctx, zone)
		discovered = append(discovered, workerAssets...)
		errors = append(errors, workerErrors...)
	}

	for _, e := range errors {
		p.logger.Warn("discovery error",
			"zone", e.Region,
			"resource", e.Resource,
			"error", e.Message,
		)
	}

	p.logger.Info("Cloudflare discovery complete",
		"total_assets", len(discovered),
		"zones", len(zones),
		"errors", len(errors),
	)

	return discovered, nil
}

// getAPI creates a new Cloudflare API client
func (p *Provider) getAPI() (*cloudflare.API, error) {
	if p.creds.APIToken != "" {
		return cloudflare.NewWithAPIToken(p.creds.APIToken)
	}
	if p.creds.APIKey != "" && p.creds.Email != "" {
		return cloudflare.New(p.creds.APIKey, p.creds.Email)
	}
	return nil, fmt.Errorf("no valid credentials provided")
}

// getZones returns zones to scan
func (p *Provider) getZones(ctx context.Context) ([]cloudflare.Zone, error) {
	// If specific zone IDs are provided, fetch those
	if len(p.creds.ZoneIDs) > 0 {
		var zones []cloudflare.Zone
		for _, zoneID := range p.creds.ZoneIDs {
			zone, err := p.api.ZoneDetails(ctx, zoneID)
			if err != nil {
				p.logger.Warn("failed to get zone", "zone_id", zoneID, "error", err)
				continue
			}
			zones = append(zones, zone)
		}
		return zones, nil
	}

	// Otherwise, list all zones
	zones, err := p.api.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	return zones, nil
}

// discoverDNSRecords finds DNS records in a zone
func (p *Provider) discoverDNSRecords(ctx context.Context, zone cloudflare.Zone) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	// Add zone as domain
	discovered = append(discovered, types.DiscoveredAsset{
		Type:   models.AssetTypeDomain,
		Value:  zone.Name,
		Source: "cloudflare:zone",
		Metadata: map[string]string{
			"zone_id":      zone.ID,
			"status":       zone.Status,
			"name_servers": joinStrings(zone.NameServers, ","),
			"plan":         zone.Plan.Name,
		},
	})

	// Get DNS records
	recs := cloudflare.ListDNSRecordsParams{}
	records, _, err := p.api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zone.ID), recs)
	if err != nil {
		errors = append(errors, types.DiscoveryError{
			Region:   zone.Name,
			Resource: "dns:records",
			Message:  err.Error(),
		})
		return discovered, errors
	}

	for _, record := range records {
		// Skip NS and SOA at zone apex
		if record.Name == zone.Name && (record.Type == "NS" || record.Type == "SOA") {
			continue
		}

		assetType := models.AssetTypeSubdomain
		if record.Name == zone.Name {
			assetType = models.AssetTypeDomain
		}

		metadata := map[string]string{
			"zone_id":     zone.ID,
			"zone_name":   zone.Name,
			"record_id":   record.ID,
			"record_type": record.Type,
			"ttl":         fmt.Sprintf("%d", record.TTL),
			"proxied":     fmt.Sprintf("%t", *record.Proxied),
		}

		discovered = append(discovered, types.DiscoveredAsset{
			Type:     assetType,
			Value:    record.Name,
			Source:   "cloudflare:dns",
			Metadata: metadata,
		})

		// Extract IPs from A/AAAA records
		if record.Type == "A" || record.Type == "AAAA" {
			ipMeta := map[string]string{
				"record_name": record.Name,
				"zone_name":   zone.Name,
				"proxied":     fmt.Sprintf("%t", *record.Proxied),
			}

			discovered = append(discovered, types.DiscoveredAsset{
				Type:     models.AssetTypeIP,
				Value:    record.Content,
				Source:   fmt.Sprintf("cloudflare:dns:%s", record.Type),
				Metadata: ipMeta,
			})
		}

		// Extract CNAME targets
		if record.Type == "CNAME" {
			discovered = append(discovered, types.DiscoveredAsset{
				Type:   models.AssetTypeEndpoint,
				Value:  record.Content,
				Source: "cloudflare:dns:cname",
				Metadata: map[string]string{
					"record_name": record.Name,
					"zone_name":   zone.Name,
				},
			})
		}
	}

	p.logger.Debug("discovered DNS records", "zone", zone.Name, "count", len(records))
	return discovered, errors
}

// discoverWorkers finds Cloudflare Workers in a zone
func (p *Provider) discoverWorkers(ctx context.Context, zone cloudflare.Zone) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	// List worker routes for this zone
	routes, err := p.api.ListWorkerRoutes(ctx, cloudflare.ZoneIdentifier(zone.ID), cloudflare.ListWorkerRoutesParams{})
	if err != nil {
		// Workers might not be enabled, not a critical error
		p.logger.Debug("could not list worker routes", "zone", zone.Name, "error", err)
		return discovered, errors
	}

	for _, route := range routes.Routes {
		discovered = append(discovered, types.DiscoveredAsset{
			Type:   models.AssetTypeEndpoint,
			Value:  route.Pattern,
			Source: "cloudflare:worker",
			Metadata: map[string]string{
				"zone_id":   zone.ID,
				"zone_name": zone.Name,
				"script":    route.ScriptName,
			},
		})
	}

	return discovered, errors
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for _, s := range strs[1:] {
		result += sep + s
	}
	return result
}
