package azure

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"

	"github.com/hugh/go-hunter/internal/assets/types"
	"github.com/hugh/go-hunter/internal/database/models"
)

// Provider implements cloud asset discovery for Azure
type Provider struct {
	creds  types.AzureCredential
	cfg    types.ProviderConfig
	logger *slog.Logger
	azCred *azidentity.ClientSecretCredential
}

// New creates a new Azure provider instance
func New(creds types.AzureCredential, cfg types.ProviderConfig, logger *slog.Logger) *Provider {
	return &Provider{
		creds:  creds,
		cfg:    cfg,
		logger: logger,
	}
}

// Name returns the provider identifier
func (p *Provider) Name() models.CloudProvider {
	return models.ProviderAzure
}

// ValidateCredentials checks if the Azure credentials are valid
func (p *Provider) ValidateCredentials(ctx context.Context) error {
	cred, err := azidentity.NewClientSecretCredential(
		p.creds.TenantID,
		p.creds.ClientID,
		p.creds.ClientSecret,
		nil,
	)
	if err != nil {
		return fmt.Errorf("invalid Azure credentials: %w", err)
	}

	// Test by listing subscriptions
	client, err := armsubscription.NewSubscriptionsClient(cred, nil)
	if err != nil {
		return fmt.Errorf("creating subscription client: %w", err)
	}

	pager := client.NewListPager(nil)
	_, err = pager.NextPage(ctx)
	if err != nil {
		return fmt.Errorf("invalid Azure credentials: %w", err)
	}

	p.azCred = cred
	return nil
}

// Discover finds all Azure assets across configured subscriptions
func (p *Provider) Discover(ctx context.Context) ([]types.DiscoveredAsset, error) {
	if p.azCred == nil {
		if err := p.ValidateCredentials(ctx); err != nil {
			return nil, err
		}
	}

	subscriptions := p.creds.Subscriptions
	if len(subscriptions) == 0 {
		// Auto-discover subscriptions
		var err error
		subscriptions, err = p.listSubscriptions(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing subscriptions: %w", err)
		}
	}

	var (
		allAssets []types.DiscoveredAsset
		allErrors []types.DiscoveryError
		mu        sync.Mutex
		wg        sync.WaitGroup
		sem       = make(chan struct{}, p.cfg.ConcurrentScans)
	)

	for _, sub := range subscriptions {
		wg.Add(1)
		sem <- struct{}{}

		go func(subscriptionID string) {
			defer wg.Done()
			defer func() { <-sem }()

			subAssets, subErrors := p.discoverSubscription(ctx, subscriptionID)

			mu.Lock()
			allAssets = append(allAssets, subAssets...)
			allErrors = append(allErrors, subErrors...)
			mu.Unlock()
		}(sub)
	}

	wg.Wait()

	for _, e := range allErrors {
		p.logger.Warn("discovery error",
			"subscription", e.Region,
			"resource", e.Resource,
			"error", e.Message,
		)
	}

	p.logger.Info("Azure discovery complete",
		"total_assets", len(allAssets),
		"errors", len(allErrors),
	)

	return allAssets, nil
}

// listSubscriptions returns all accessible subscription IDs
func (p *Provider) listSubscriptions(ctx context.Context) ([]string, error) {
	client, err := armsubscription.NewSubscriptionsClient(p.azCred, nil)
	if err != nil {
		return nil, err
	}

	var subscriptions []string
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, sub := range page.Value {
			if sub.SubscriptionID != nil {
				subscriptions = append(subscriptions, *sub.SubscriptionID)
			}
		}
	}

	return subscriptions, nil
}

// discoverSubscription discovers assets in a single Azure subscription
func (p *Provider) discoverSubscription(ctx context.Context, subscriptionID string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	p.logger.Debug("discovering subscription", "subscription", subscriptionID)

	// Discover Virtual Machines
	vmAssets, vmErrors := p.discoverVMs(ctx, subscriptionID)
	discovered = append(discovered, vmAssets...)
	errors = append(errors, vmErrors...)

	// Discover Storage Accounts
	storageAssets, storageErrors := p.discoverStorage(ctx, subscriptionID)
	discovered = append(discovered, storageAssets...)
	errors = append(errors, storageErrors...)

	// Discover DNS Zones
	dnsAssets, dnsErrors := p.discoverDNS(ctx, subscriptionID)
	discovered = append(discovered, dnsAssets...)
	errors = append(errors, dnsErrors...)

	// Discover Load Balancers
	lbAssets, lbErrors := p.discoverLoadBalancers(ctx, subscriptionID)
	discovered = append(discovered, lbAssets...)
	errors = append(errors, lbErrors...)

	// Discover Public IPs
	pipAssets, pipErrors := p.discoverPublicIPs(ctx, subscriptionID)
	discovered = append(discovered, pipAssets...)
	errors = append(errors, pipErrors...)

	return discovered, errors
}

// discoverVMs finds Azure Virtual Machines
func (p *Provider) discoverVMs(ctx context.Context, subscriptionID string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	client, err := armcompute.NewVirtualMachinesClient(subscriptionID, p.azCred, nil)
	if err != nil {
		errors = append(errors, types.DiscoveryError{
			Region:   subscriptionID,
			Resource: "compute:vm",
			Message:  err.Error(),
		})
		return discovered, errors
	}

	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Region:   subscriptionID,
				Resource: "compute:vm:list",
				Message:  err.Error(),
			})
			break
		}

		for _, vm := range page.Value {
			metadata := map[string]string{
				"subscription": subscriptionID,
				"name":         ptrToString(vm.Name),
				"location":     ptrToString(vm.Location),
				"vm_size":      string(ptrValue(vm.Properties.HardwareProfile.VMSize)),
			}

			if vm.Properties.ProvisioningState != nil {
				metadata["state"] = *vm.Properties.ProvisioningState
			}

			// VMs don't directly expose public IPs, they're associated via NICs
			// We'll discover those separately via Public IP discovery
			p.logger.Debug("found VM", "name", ptrToString(vm.Name))
		}
	}

	return discovered, errors
}

// discoverStorage finds Azure Storage Accounts
func (p *Provider) discoverStorage(ctx context.Context, subscriptionID string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	client, err := armstorage.NewAccountsClient(subscriptionID, p.azCred, nil)
	if err != nil {
		errors = append(errors, types.DiscoveryError{
			Region:   subscriptionID,
			Resource: "storage",
			Message:  err.Error(),
		})
		return discovered, errors
	}

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Region:   subscriptionID,
				Resource: "storage:list",
				Message:  err.Error(),
			})
			break
		}

		for _, account := range page.Value {
			accountName := ptrToString(account.Name)
			metadata := map[string]string{
				"subscription": subscriptionID,
				"name":         accountName,
				"location":     ptrToString(account.Location),
				"kind":         string(ptrValue(account.Kind)),
				"sku":          string(ptrValue(account.SKU.Name)),
			}

			// Check public access settings
			if account.Properties != nil && account.Properties.AllowBlobPublicAccess != nil {
				if *account.Properties.AllowBlobPublicAccess {
					metadata["public_access"] = "allowed"
				} else {
					metadata["public_access"] = "blocked"
				}
			}

			discovered = append(discovered, types.DiscoveredAsset{
				Type:     models.AssetTypeBucket,
				Value:    accountName,
				Source:   "azure:storage",
				Metadata: metadata,
			})

			// Add blob endpoint
			if account.Properties != nil && account.Properties.PrimaryEndpoints != nil {
				if blobEndpoint := account.Properties.PrimaryEndpoints.Blob; blobEndpoint != nil {
					discovered = append(discovered, types.DiscoveredAsset{
						Type:   models.AssetTypeEndpoint,
						Value:  *blobEndpoint,
						Source: "azure:storage:blob",
						Metadata: map[string]string{
							"account_name": accountName,
							"subscription": subscriptionID,
						},
					})
				}
			}
		}
	}

	p.logger.Debug("discovered Storage Accounts", "subscription", subscriptionID)
	return discovered, errors
}

// discoverDNS finds Azure DNS Zones
func (p *Provider) discoverDNS(ctx context.Context, subscriptionID string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	client, err := armdns.NewZonesClient(subscriptionID, p.azCred, nil)
	if err != nil {
		errors = append(errors, types.DiscoveryError{
			Region:   subscriptionID,
			Resource: "dns",
			Message:  err.Error(),
		})
		return discovered, errors
	}

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Region:   subscriptionID,
				Resource: "dns:zones",
				Message:  err.Error(),
			})
			break
		}

		for _, zone := range page.Value {
			zoneName := ptrToString(zone.Name)

			discovered = append(discovered, types.DiscoveredAsset{
				Type:   models.AssetTypeDomain,
				Value:  zoneName,
				Source: "azure:dns",
				Metadata: map[string]string{
					"subscription": subscriptionID,
					"zone_type":    string(ptrValue(zone.Properties.ZoneType)),
				},
			})

			// Discover records in zone
			recordAssets, recordErrors := p.discoverDNSRecords(ctx, subscriptionID, zoneName)
			discovered = append(discovered, recordAssets...)
			errors = append(errors, recordErrors...)
		}
	}

	return discovered, errors
}

// discoverDNSRecords finds records in a DNS zone
func (p *Provider) discoverDNSRecords(ctx context.Context, subscriptionID, zoneName string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	client, err := armdns.NewRecordSetsClient(subscriptionID, p.azCred, nil)
	if err != nil {
		return discovered, errors
	}

	// We need the resource group - for simplicity, list all record sets
	pager := client.NewListAllByDNSZonePager(extractResourceGroup(zoneName), zoneName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			// Resource group extraction might fail, skip
			break
		}

		for _, record := range page.Value {
			recordName := ptrToString(record.Name)
			if recordName == "@" {
				recordName = zoneName
			} else {
				recordName = recordName + "." + zoneName
			}

			// Skip NS and SOA at apex
			recordType := ptrToString(record.Type)
			if recordName == zoneName && (recordType == "NS" || recordType == "SOA") {
				continue
			}

			assetType := models.AssetTypeSubdomain
			if recordName == zoneName {
				assetType = models.AssetTypeDomain
			}

			discovered = append(discovered, types.DiscoveredAsset{
				Type:   assetType,
				Value:  recordName,
				Source: "azure:dns",
				Metadata: map[string]string{
					"subscription": subscriptionID,
					"zone_name":    zoneName,
					"record_type":  recordType,
				},
			})
		}
	}

	return discovered, errors
}

// discoverLoadBalancers finds Azure Load Balancers
func (p *Provider) discoverLoadBalancers(ctx context.Context, subscriptionID string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	client, err := armnetwork.NewLoadBalancersClient(subscriptionID, p.azCred, nil)
	if err != nil {
		errors = append(errors, types.DiscoveryError{
			Region:   subscriptionID,
			Resource: "network:lb",
			Message:  err.Error(),
		})
		return discovered, errors
	}

	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Region:   subscriptionID,
				Resource: "network:lb:list",
				Message:  err.Error(),
			})
			break
		}

		for _, lb := range page.Value {
			metadata := map[string]string{
				"subscription": subscriptionID,
				"name":         ptrToString(lb.Name),
				"location":     ptrToString(lb.Location),
				"sku":          string(ptrValue(lb.SKU.Name)),
			}

			// Get frontend IPs
			if lb.Properties != nil {
				for _, feCfg := range lb.Properties.FrontendIPConfigurations {
					if feCfg.Properties != nil && feCfg.Properties.PublicIPAddress != nil {
						// The public IP ID is referenced, actual IP comes from PublicIP discovery
						p.logger.Debug("found LB with public frontend", "name", ptrToString(lb.Name))
					}
				}
			}

			discovered = append(discovered, types.DiscoveredAsset{
				Type:     models.AssetTypeEndpoint,
				Value:    ptrToString(lb.Name),
				Source:   "azure:lb",
				Metadata: metadata,
			})
		}
	}

	return discovered, errors
}

// discoverPublicIPs finds Azure Public IP addresses
func (p *Provider) discoverPublicIPs(ctx context.Context, subscriptionID string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	client, err := armnetwork.NewPublicIPAddressesClient(subscriptionID, p.azCred, nil)
	if err != nil {
		errors = append(errors, types.DiscoveryError{
			Region:   subscriptionID,
			Resource: "network:publicip",
			Message:  err.Error(),
		})
		return discovered, errors
	}

	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Region:   subscriptionID,
				Resource: "network:publicip:list",
				Message:  err.Error(),
			})
			break
		}

		for _, pip := range page.Value {
			metadata := map[string]string{
				"subscription": subscriptionID,
				"name":         ptrToString(pip.Name),
				"location":     ptrToString(pip.Location),
				"sku":          string(ptrValue(pip.SKU.Name)),
			}

			if pip.Properties != nil {
				if pip.Properties.IPAddress != nil {
					discovered = append(discovered, types.DiscoveredAsset{
						Type:     models.AssetTypeIP,
						Value:    *pip.Properties.IPAddress,
						Source:   "azure:publicip",
						Metadata: copyMetadata(metadata),
					})
				}

				if pip.Properties.DNSSettings != nil && pip.Properties.DNSSettings.Fqdn != nil {
					discovered = append(discovered, types.DiscoveredAsset{
						Type:     models.AssetTypeSubdomain,
						Value:    *pip.Properties.DNSSettings.Fqdn,
						Source:   "azure:publicip",
						Metadata: copyMetadata(metadata),
					})
				}
			}
		}
	}

	p.logger.Debug("discovered Public IPs", "subscription", subscriptionID, "count", len(discovered))
	return discovered, errors
}

func ptrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func ptrValue[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func copyMetadata(m map[string]string) map[string]string {
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func extractResourceGroup(resourceID string) string {
	// Simplified - in reality would parse the resource ID
	return ""
}
