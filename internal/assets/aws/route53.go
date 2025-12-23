package aws

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/hugh/go-hunter/internal/assets/types"
	"github.com/hugh/go-hunter/internal/database/models"
)

// discoverRoute53 finds Route53 hosted zones and their records
func (p *Provider) discoverRoute53(ctx context.Context, cfg aws.Config) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	client := route53.NewFromConfig(cfg)

	// List all hosted zones
	zonesPaginator := route53.NewListHostedZonesPaginator(client, &route53.ListHostedZonesInput{})

	for zonesPaginator.HasMorePages() {
		zonesPage, err := zonesPaginator.NextPage(ctx)
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Region:   "global",
				Resource: "route53:zones",
				Message:  err.Error(),
			})
			break
		}

		for _, zone := range zonesPage.HostedZones {
			zoneName := strings.TrimSuffix(aws.ToString(zone.Name), ".")
			zoneID := aws.ToString(zone.Id)

			// Add the zone itself as a domain
			discovered = append(discovered, types.DiscoveredAsset{
				Type:   models.AssetTypeDomain,
				Value:  zoneName,
				Source: "aws:route53",
				Metadata: map[string]string{
					"zone_id":      zoneID,
					"record_count": string(rune(aws.ToInt64(zone.ResourceRecordSetCount))),
					"private_zone": boolToString(zone.Config != nil && zone.Config.PrivateZone),
				},
			})

			// Get all records in this zone
			recordAssets, recordErrors := p.discoverRoute53Records(ctx, client, zoneID, zoneName)
			discovered = append(discovered, recordAssets...)
			errors = append(errors, recordErrors...)
		}
	}

	p.logger.Debug("discovered Route53 zones and records", "count", len(discovered))
	return discovered, errors
}

// discoverRoute53Records gets all DNS records in a hosted zone
func (p *Provider) discoverRoute53Records(ctx context.Context, client *route53.Client, zoneID, zoneName string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	paginator := route53.NewListResourceRecordSetsPaginator(client, &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Region:   "global",
				Resource: "route53:records",
				Message:  err.Error(),
			})
			break
		}

		for _, record := range page.ResourceRecordSets {
			recordName := strings.TrimSuffix(aws.ToString(record.Name), ".")
			recordType := string(record.Type)

			// Skip the zone apex NS and SOA records
			if recordName == zoneName && (recordType == "NS" || recordType == "SOA") {
				continue
			}

			metadata := map[string]string{
				"zone_id":     zoneID,
				"zone_name":   zoneName,
				"record_type": recordType,
				"ttl":         ttlToString(record.TTL),
			}

			// Determine asset type based on record type
			assetType := models.AssetTypeSubdomain
			if recordName == zoneName {
				assetType = models.AssetTypeDomain
			}

			// Add the record name as an asset
			discovered = append(discovered, types.DiscoveredAsset{
				Type:     assetType,
				Value:    recordName,
				Source:   "aws:route53",
				Metadata: metadata,
			})

			// Also extract IPs from A records
			if record.Type == r53types.RRTypeA {
				for _, rr := range record.ResourceRecords {
					discovered = append(discovered, types.DiscoveredAsset{
						Type:   models.AssetTypeIP,
						Value:  aws.ToString(rr.Value),
						Source: "aws:route53:a",
						Metadata: map[string]string{
							"record_name": recordName,
							"zone_name":   zoneName,
						},
					})
				}
			}

			// Extract alias targets (often ELB/CloudFront endpoints)
			if record.AliasTarget != nil {
				aliasTarget := aws.ToString(record.AliasTarget.DNSName)
				aliasTarget = strings.TrimSuffix(aliasTarget, ".")
				if aliasTarget != "" {
					discovered = append(discovered, types.DiscoveredAsset{
						Type:   models.AssetTypeEndpoint,
						Value:  aliasTarget,
						Source: "aws:route53:alias",
						Metadata: map[string]string{
							"record_name":   recordName,
							"alias_zone_id": aws.ToString(record.AliasTarget.HostedZoneId),
						},
					})
				}
			}
		}
	}

	return discovered, errors
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func ttlToString(ttl *int64) string {
	if ttl == nil {
		return "0"
	}
	return string(rune(*ttl))
}
