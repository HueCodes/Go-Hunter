package digitalocean

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/digitalocean/godo"
	"golang.org/x/oauth2"

	"github.com/hugh/go-hunter/internal/assets/types"
	"github.com/hugh/go-hunter/internal/database/models"
)

// Provider implements cloud asset discovery for DigitalOcean
type Provider struct {
	creds  types.DigitalOceanCredential
	cfg    types.ProviderConfig
	logger *slog.Logger
	client *godo.Client
}

// New creates a new DigitalOcean provider instance
func New(creds types.DigitalOceanCredential, cfg types.ProviderConfig, logger *slog.Logger) *Provider {
	return &Provider{
		creds:  creds,
		cfg:    cfg,
		logger: logger,
	}
}

// Name returns the provider identifier
func (p *Provider) Name() models.CloudProvider {
	return models.ProviderDigitalOcean
}

// ValidateCredentials checks if the DigitalOcean credentials are valid
func (p *Provider) ValidateCredentials(ctx context.Context) error {
	client := p.getClient()

	// Test by getting account info
	_, _, err := client.Account.Get(ctx)
	if err != nil {
		return fmt.Errorf("invalid DigitalOcean credentials: %w", err)
	}

	p.client = client
	return nil
}

// Discover finds all DigitalOcean assets
func (p *Provider) Discover(ctx context.Context) ([]types.DiscoveredAsset, error) {
	if p.client == nil {
		p.client = p.getClient()
	}

	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	// Discover Droplets
	dropletAssets, dropletErrors := p.discoverDroplets(ctx)
	discovered = append(discovered, dropletAssets...)
	errors = append(errors, dropletErrors...)

	// Discover Spaces (S3-compatible storage)
	spacesAssets, spacesErrors := p.discoverSpaces(ctx)
	discovered = append(discovered, spacesAssets...)
	errors = append(errors, spacesErrors...)

	// Discover Load Balancers
	lbAssets, lbErrors := p.discoverLoadBalancers(ctx)
	discovered = append(discovered, lbAssets...)
	errors = append(errors, lbErrors...)

	// Discover Domains
	domainAssets, domainErrors := p.discoverDomains(ctx)
	discovered = append(discovered, domainAssets...)
	errors = append(errors, domainErrors...)

	// Discover Kubernetes clusters
	k8sAssets, k8sErrors := p.discoverKubernetes(ctx)
	discovered = append(discovered, k8sAssets...)
	errors = append(errors, k8sErrors...)

	for _, e := range errors {
		p.logger.Warn("discovery error",
			"resource", e.Resource,
			"error", e.Message,
		)
	}

	p.logger.Info("DigitalOcean discovery complete",
		"total_assets", len(discovered),
		"errors", len(errors),
	)

	return discovered, nil
}

// getClient creates a new DigitalOcean client
func (p *Provider) getClient() *godo.Client {
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: p.creds.APIToken})
	oauthClient := oauth2.NewClient(context.Background(), tokenSource)
	return godo.NewClient(oauthClient)
}

// discoverDroplets finds DigitalOcean Droplets
func (p *Provider) discoverDroplets(ctx context.Context) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	opt := &godo.ListOptions{PerPage: 200}
	for {
		droplets, resp, err := p.client.Droplets.List(ctx, opt)
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Resource: "droplets",
				Message:  err.Error(),
			})
			break
		}

		for _, droplet := range droplets {
			metadata := map[string]string{
				"droplet_id": fmt.Sprintf("%d", droplet.ID),
				"name":       droplet.Name,
				"region":     droplet.Region.Slug,
				"size":       droplet.Size.Slug,
				"status":     droplet.Status,
				"vcpus":      fmt.Sprintf("%d", droplet.Vcpus),
				"memory":     fmt.Sprintf("%d", droplet.Memory),
			}

			// Add public IPv4
			publicIP, _ := droplet.PublicIPv4()
			if publicIP != "" {
				discovered = append(discovered, types.DiscoveredAsset{
					Type:     models.AssetTypeIP,
					Value:    publicIP,
					Source:   "digitalocean:droplet",
					Metadata: copyMetadata(metadata),
				})
			}

			// Add public IPv6
			publicIPv6, _ := droplet.PublicIPv6()
			if publicIPv6 != "" {
				ipv6Meta := copyMetadata(metadata)
				ipv6Meta["ip_version"] = "6"
				discovered = append(discovered, types.DiscoveredAsset{
					Type:     models.AssetTypeIP,
					Value:    publicIPv6,
					Source:   "digitalocean:droplet",
					Metadata: ipv6Meta,
				})
			}

			// Add private IP
			privateIP, _ := droplet.PrivateIPv4()
			if privateIP != "" {
				privateMeta := copyMetadata(metadata)
				privateMeta["visibility"] = "private"
				discovered = append(discovered, types.DiscoveredAsset{
					Type:     models.AssetTypeIP,
					Value:    privateIP,
					Source:   "digitalocean:droplet:private",
					Metadata: privateMeta,
				})
			}
		}

		if resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			break
		}
		opt.Page = page + 1
	}

	p.logger.Debug("discovered Droplets", "count", len(discovered))
	return discovered, errors
}

// discoverSpaces finds DigitalOcean Spaces (requires Spaces API)
func (p *Provider) discoverSpaces(ctx context.Context) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	// Spaces uses S3-compatible API, would need separate configuration
	// For now, return empty as it requires different credentials
	return nil, nil
}

// discoverLoadBalancers finds DigitalOcean Load Balancers
func (p *Provider) discoverLoadBalancers(ctx context.Context) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	opt := &godo.ListOptions{PerPage: 200}
	for {
		lbs, resp, err := p.client.LoadBalancers.List(ctx, opt)
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Resource: "loadbalancers",
				Message:  err.Error(),
			})
			break
		}

		for _, lb := range lbs {
			metadata := map[string]string{
				"lb_id":  lb.ID,
				"name":   lb.Name,
				"region": lb.Region.Slug,
				"status": string(lb.Status),
			}

			// Add LB IP
			if lb.IP != "" {
				discovered = append(discovered, types.DiscoveredAsset{
					Type:     models.AssetTypeIP,
					Value:    lb.IP,
					Source:   "digitalocean:lb",
					Metadata: copyMetadata(metadata),
				})
			}
		}

		if resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			break
		}
		opt.Page = page + 1
	}

	return discovered, errors
}

// discoverDomains finds DigitalOcean managed domains
func (p *Provider) discoverDomains(ctx context.Context) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	opt := &godo.ListOptions{PerPage: 200}
	for {
		domains, resp, err := p.client.Domains.List(ctx, opt)
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Resource: "domains",
				Message:  err.Error(),
			})
			break
		}

		for _, domain := range domains {
			discovered = append(discovered, types.DiscoveredAsset{
				Type:   models.AssetTypeDomain,
				Value:  domain.Name,
				Source: "digitalocean:dns",
				Metadata: map[string]string{
					"zone_file": domain.ZoneFile,
				},
			})

			// Get domain records
			recordAssets, _ := p.discoverDomainRecords(ctx, domain.Name)
			discovered = append(discovered, recordAssets...)
		}

		if resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			break
		}
		opt.Page = page + 1
	}

	return discovered, errors
}

// discoverDomainRecords gets DNS records for a domain
func (p *Provider) discoverDomainRecords(ctx context.Context, domain string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	opt := &godo.ListOptions{PerPage: 200}
	for {
		records, resp, err := p.client.Domains.Records(ctx, domain, opt)
		if err != nil {
			break
		}

		for _, record := range records {
			// Skip NS and SOA at apex
			if record.Name == "@" && (record.Type == "NS" || record.Type == "SOA") {
				continue
			}

			recordName := record.Name
			if recordName == "@" {
				recordName = domain
			} else {
				recordName = record.Name + "." + domain
			}

			assetType := models.AssetTypeSubdomain
			if recordName == domain {
				assetType = models.AssetTypeDomain
			}

			discovered = append(discovered, types.DiscoveredAsset{
				Type:   assetType,
				Value:  recordName,
				Source: "digitalocean:dns",
				Metadata: map[string]string{
					"record_type": record.Type,
					"data":        record.Data,
					"ttl":         fmt.Sprintf("%d", record.TTL),
				},
			})

			// Extract IPs from A records
			if record.Type == "A" {
				discovered = append(discovered, types.DiscoveredAsset{
					Type:   models.AssetTypeIP,
					Value:  record.Data,
					Source: "digitalocean:dns:a",
					Metadata: map[string]string{
						"record_name": recordName,
					},
				})
			}
		}

		if resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			break
		}
		opt.Page = page + 1
	}

	return discovered, errors
}

// discoverKubernetes finds DigitalOcean Kubernetes clusters
func (p *Provider) discoverKubernetes(ctx context.Context) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	opt := &godo.ListOptions{PerPage: 200}
	for {
		clusters, resp, err := p.client.Kubernetes.List(ctx, opt)
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Resource: "kubernetes",
				Message:  err.Error(),
			})
			break
		}

		for _, cluster := range clusters {
			metadata := map[string]string{
				"cluster_id": cluster.ID,
				"name":       cluster.Name,
				"region":     cluster.RegionSlug,
				"version":    cluster.VersionSlug,
				"status":     string(cluster.Status.State),
			}

			// Add cluster endpoint
			if cluster.Endpoint != "" {
				discovered = append(discovered, types.DiscoveredAsset{
					Type:     models.AssetTypeEndpoint,
					Value:    cluster.Endpoint,
					Source:   "digitalocean:kubernetes",
					Metadata: metadata,
				})
			}
		}

		if resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			break
		}
		opt.Page = page + 1
	}

	return discovered, errors
}

func copyMetadata(m map[string]string) map[string]string {
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
