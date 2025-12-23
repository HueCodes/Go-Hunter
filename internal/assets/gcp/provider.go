package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"cloud.google.com/go/storage"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/hugh/go-hunter/internal/assets/types"
	"github.com/hugh/go-hunter/internal/database/models"
)

// Provider implements cloud asset discovery for GCP
type Provider struct {
	creds  types.GCPCredential
	cfg    types.ProviderConfig
	logger *slog.Logger
}

// New creates a new GCP provider instance
func New(creds types.GCPCredential, cfg types.ProviderConfig, logger *slog.Logger) *Provider {
	return &Provider{
		creds:  creds,
		cfg:    cfg,
		logger: logger,
	}
}

// Name returns the provider identifier
func (p *Provider) Name() models.CloudProvider {
	return models.ProviderGCP
}

// ValidateCredentials checks if the GCP credentials are valid
func (p *Provider) ValidateCredentials(ctx context.Context) error {
	opts := p.clientOptions()

	// Try to create a storage client to validate credentials
	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return fmt.Errorf("invalid GCP credentials: %w", err)
	}
	defer client.Close()

	return nil
}

// Discover finds all GCP assets across configured projects
func (p *Provider) Discover(ctx context.Context) ([]types.DiscoveredAsset, error) {
	projects := p.creds.Projects
	if len(projects) == 0 {
		// Auto-discover projects would require Resource Manager API
		// For now, require explicit project list
		p.logger.Warn("no GCP projects specified, skipping discovery")
		return nil, nil
	}

	var (
		allAssets []types.DiscoveredAsset
		allErrors []types.DiscoveryError
		mu        sync.Mutex
		wg        sync.WaitGroup
		sem       = make(chan struct{}, p.cfg.ConcurrentScans)
	)

	for _, project := range projects {
		wg.Add(1)
		sem <- struct{}{}

		go func(project string) {
			defer wg.Done()
			defer func() { <-sem }()

			projectAssets, projectErrors := p.discoverProject(ctx, project)

			mu.Lock()
			allAssets = append(allAssets, projectAssets...)
			allErrors = append(allErrors, projectErrors...)
			mu.Unlock()
		}(project)
	}

	wg.Wait()

	for _, e := range allErrors {
		p.logger.Warn("discovery error",
			"project", e.Region,
			"resource", e.Resource,
			"error", e.Message,
		)
	}

	p.logger.Info("GCP discovery complete",
		"total_assets", len(allAssets),
		"errors", len(allErrors),
	)

	return allAssets, nil
}

// discoverProject discovers assets in a single GCP project
func (p *Provider) discoverProject(ctx context.Context, project string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	p.logger.Debug("discovering project", "project", project)

	// Discover Compute Engine instances
	computeAssets, computeErrors := p.discoverCompute(ctx, project)
	discovered = append(discovered, computeAssets...)
	errors = append(errors, computeErrors...)

	// Discover Cloud Storage buckets
	storageAssets, storageErrors := p.discoverStorage(ctx, project)
	discovered = append(discovered, storageAssets...)
	errors = append(errors, storageErrors...)

	// Discover Cloud DNS
	dnsAssets, dnsErrors := p.discoverDNS(ctx, project)
	discovered = append(discovered, dnsAssets...)
	errors = append(errors, dnsErrors...)

	return discovered, errors
}

// discoverCompute finds Compute Engine instances
func (p *Provider) discoverCompute(ctx context.Context, project string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	opts := p.clientOptions()
	client, err := compute.NewInstancesRESTClient(ctx, opts...)
	if err != nil {
		errors = append(errors, types.DiscoveryError{
			Region:   project,
			Resource: "compute",
			Message:  err.Error(),
		})
		return discovered, errors
	}
	defer client.Close()

	// List instances across all zones
	req := &computepb.AggregatedListInstancesRequest{
		Project: project,
	}

	it := client.AggregatedList(ctx, req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Region:   project,
				Resource: "compute:instances",
				Message:  err.Error(),
			})
			break
		}

		for _, instance := range resp.Value.Instances {
			metadata := map[string]string{
				"project":       project,
				"name":          instance.GetName(),
				"zone":          instance.GetZone(),
				"machine_type":  instance.GetMachineType(),
				"status":        instance.GetStatus(),
			}

			// Add external IPs
			for _, iface := range instance.GetNetworkInterfaces() {
				for _, accessCfg := range iface.GetAccessConfigs() {
					if natIP := accessCfg.GetNatIP(); natIP != "" {
						discovered = append(discovered, types.DiscoveredAsset{
							Type:     models.AssetTypeIP,
							Value:    natIP,
							Source:   "gcp:compute",
							Metadata: copyMetadata(metadata),
						})
					}
				}

				// Add internal IP
				if internalIP := iface.GetNetworkIP(); internalIP != "" {
					internalMeta := copyMetadata(metadata)
					internalMeta["visibility"] = "private"
					discovered = append(discovered, types.DiscoveredAsset{
						Type:     models.AssetTypeIP,
						Value:    internalIP,
						Source:   "gcp:compute:private",
						Metadata: internalMeta,
					})
				}
			}
		}
	}

	p.logger.Debug("discovered Compute Engine instances", "project", project, "count", len(discovered))
	return discovered, errors
}

// discoverStorage finds Cloud Storage buckets
func (p *Provider) discoverStorage(ctx context.Context, project string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	opts := p.clientOptions()
	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		errors = append(errors, types.DiscoveryError{
			Region:   project,
			Resource: "storage",
			Message:  err.Error(),
		})
		return discovered, errors
	}
	defer client.Close()

	it := client.Buckets(ctx, project)
	for {
		bucket, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Region:   project,
				Resource: "storage:buckets",
				Message:  err.Error(),
			})
			break
		}

		metadata := map[string]string{
			"project":       project,
			"name":          bucket.Name,
			"location":      bucket.Location,
			"storage_class": bucket.StorageClass,
			"created":       bucket.Created.String(),
		}

		// Check public access
		publicAccess := "private"
		if bucket.UniformBucketLevelAccess.Enabled {
			metadata["uniform_access"] = "true"
		}
		// Would need IAM check for true public status
		metadata["public_access"] = publicAccess

		discovered = append(discovered, types.DiscoveredAsset{
			Type:     models.AssetTypeBucket,
			Value:    bucket.Name,
			Source:   "gcp:storage",
			Metadata: metadata,
		})

		// Add bucket URL
		discovered = append(discovered, types.DiscoveredAsset{
			Type:   models.AssetTypeEndpoint,
			Value:  bucket.Name + ".storage.googleapis.com",
			Source: "gcp:storage",
			Metadata: map[string]string{
				"bucket_name": bucket.Name,
				"project":     project,
			},
		})
	}

	p.logger.Debug("discovered Cloud Storage buckets", "project", project)
	return discovered, errors
}

// discoverDNS finds Cloud DNS zones and records
func (p *Provider) discoverDNS(ctx context.Context, project string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	opts := p.clientOptions()
	dnsService, err := dns.NewService(ctx, opts...)
	if err != nil {
		errors = append(errors, types.DiscoveryError{
			Region:   project,
			Resource: "dns",
			Message:  err.Error(),
		})
		return discovered, errors
	}

	// List managed zones
	zonesResp, err := dnsService.ManagedZones.List(project).Context(ctx).Do()
	if err != nil {
		errors = append(errors, types.DiscoveryError{
			Region:   project,
			Resource: "dns:zones",
			Message:  err.Error(),
		})
		return discovered, errors
	}

	for _, zone := range zonesResp.ManagedZones {
		dnsName := zone.DnsName
		if len(dnsName) > 0 && dnsName[len(dnsName)-1] == '.' {
			dnsName = dnsName[:len(dnsName)-1]
		}

		discovered = append(discovered, types.DiscoveredAsset{
			Type:   models.AssetTypeDomain,
			Value:  dnsName,
			Source: "gcp:dns",
			Metadata: map[string]string{
				"project":     project,
				"zone_name":   zone.Name,
				"visibility":  zone.Visibility,
			},
		})

		// List records in zone
		recordsResp, err := dnsService.ResourceRecordSets.List(project, zone.Name).Context(ctx).Do()
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Region:   project,
				Resource: "dns:records",
				Message:  err.Error(),
			})
			continue
		}

		for _, record := range recordsResp.Rrsets {
			recordName := record.Name
			if len(recordName) > 0 && recordName[len(recordName)-1] == '.' {
				recordName = recordName[:len(recordName)-1]
			}

			// Skip NS and SOA for zone apex
			if recordName == dnsName && (record.Type == "NS" || record.Type == "SOA") {
				continue
			}

			assetType := models.AssetTypeSubdomain
			if recordName == dnsName {
				assetType = models.AssetTypeDomain
			}

			discovered = append(discovered, types.DiscoveredAsset{
				Type:   assetType,
				Value:  recordName,
				Source: "gcp:dns",
				Metadata: map[string]string{
					"project":     project,
					"zone_name":   zone.Name,
					"record_type": record.Type,
					"ttl":         fmt.Sprintf("%d", record.Ttl),
				},
			})

			// Extract IPs from A records
			if record.Type == "A" {
				for _, rdata := range record.Rrdatas {
					discovered = append(discovered, types.DiscoveredAsset{
						Type:   models.AssetTypeIP,
						Value:  rdata,
						Source: "gcp:dns:a",
						Metadata: map[string]string{
							"record_name": recordName,
							"project":     project,
						},
					})
				}
			}
		}
	}

	p.logger.Debug("discovered Cloud DNS", "project", project)
	return discovered, errors
}

// clientOptions returns the Google API client options
func (p *Provider) clientOptions() []option.ClientOption {
	return []option.ClientOption{
		option.WithCredentialsJSON([]byte(p.creds.ServiceAccountJSON)),
	}
}

func copyMetadata(m map[string]string) map[string]string {
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// parseServiceAccountProject extracts project ID from service account JSON
func parseServiceAccountProject(jsonData string) string {
	var sa struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal([]byte(jsonData), &sa); err != nil {
		return ""
	}
	return sa.ProjectID
}
