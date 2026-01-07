package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/hugh/go-hunter/internal/assets/types"
	"github.com/hugh/go-hunter/internal/database/models"
)

// discoverELB finds Classic ELB and ALB/NLB load balancers
func (p *Provider) discoverELB(ctx context.Context, cfg aws.Config, region string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	// Discover Classic ELBs
	classicAssets, classicErrors := p.discoverClassicELB(ctx, cfg, region)
	discovered = append(discovered, classicAssets...)
	errors = append(errors, classicErrors...)

	// Discover ALB/NLB (ELBv2)
	v2Assets, v2Errors := p.discoverELBv2(ctx, cfg, region)
	discovered = append(discovered, v2Assets...)
	errors = append(errors, v2Errors...)

	return discovered, errors
}

// discoverClassicELB finds Classic Elastic Load Balancers
func (p *Provider) discoverClassicELB(ctx context.Context, cfg aws.Config, region string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	client := elasticloadbalancing.NewFromConfig(cfg)

	result, err := client.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
	if err != nil {
		errors = append(errors, types.DiscoveryError{
			Region:   region,
			Resource: "elb:classic",
			Message:  err.Error(),
		})
		return discovered, errors
	}

	for _, lb := range result.LoadBalancerDescriptions {
		lbName := aws.ToString(lb.LoadBalancerName)
		dnsName := aws.ToString(lb.DNSName)

		metadata := map[string]string{
			"name":   lbName,
			"region": region,
			"type":   "classic",
			"scheme": aws.ToString(lb.Scheme),
			"vpc_id": aws.ToString(lb.VPCId),
		}

		// Add listener ports
		var ports []string
		for _, listener := range lb.ListenerDescriptions {
			if listener.Listener != nil {
				ports = append(ports, fmt.Sprintf("%d", listener.Listener.LoadBalancerPort))
			}
		}
		metadata["ports"] = joinStrings(ports, ",")

		// Add DNS name as endpoint
		if dnsName != "" {
			discovered = append(discovered, types.DiscoveredAsset{
				Type:     models.AssetTypeEndpoint,
				Value:    dnsName,
				Source:   "aws:elb:classic",
				Metadata: metadata,
			})
		}
	}

	return discovered, errors
}

// discoverELBv2 finds Application and Network Load Balancers
func (p *Provider) discoverELBv2(ctx context.Context, cfg aws.Config, region string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	client := elasticloadbalancingv2.NewFromConfig(cfg)

	paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Region:   region,
				Resource: "elb:v2",
				Message:  err.Error(),
			})
			break
		}

		for _, lb := range page.LoadBalancers {
			lbName := aws.ToString(lb.LoadBalancerName)
			dnsName := aws.ToString(lb.DNSName)
			lbType := string(lb.Type)

			metadata := map[string]string{
				"name":   lbName,
				"arn":    aws.ToString(lb.LoadBalancerArn),
				"region": region,
				"type":   lbType,
				"scheme": string(lb.Scheme),
				"state":  string(lb.State.Code),
				"vpc_id": aws.ToString(lb.VpcId),
			}

			// Add DNS name as endpoint
			if dnsName != "" {
				discovered = append(discovered, types.DiscoveredAsset{
					Type:     models.AssetTypeEndpoint,
					Value:    dnsName,
					Source:   fmt.Sprintf("aws:elb:%s", lbType),
					Metadata: metadata,
				})
			}

			// Get listeners to find ports
			listenersResult, err := client.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{
				LoadBalancerArn: lb.LoadBalancerArn,
			})
			if err == nil {
				var ports []string
				for _, listener := range listenersResult.Listeners {
					ports = append(ports, fmt.Sprintf("%d", aws.ToInt32(listener.Port)))
				}
				metadata["ports"] = joinStrings(ports, ",")
			}
		}
	}

	p.logger.Debug("discovered ELBv2 load balancers", "region", region)
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
