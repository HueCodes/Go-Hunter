package aws

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hugh/go-hunter/internal/assets/types"
	"github.com/hugh/go-hunter/internal/database/models"
)

// AllRegions lists all AWS regions for discovery
var AllRegions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
	"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"ap-southeast-1", "ap-southeast-2",
	"ap-south-1", "sa-east-1", "ca-central-1",
	"me-south-1", "af-south-1",
}

// Provider implements cloud asset discovery for AWS
type Provider struct {
	creds  types.AWSCredential
	cfg    types.ProviderConfig
	logger *slog.Logger

	awsCfg aws.Config
}

// New creates a new AWS provider instance
func New(creds types.AWSCredential, cfg types.ProviderConfig, logger *slog.Logger) *Provider {
	return &Provider{
		creds:  creds,
		cfg:    cfg,
		logger: logger,
	}
}

// Name returns the provider identifier
func (p *Provider) Name() models.CloudProvider {
	return models.ProviderAWS
}

// ValidateCredentials checks if the AWS credentials are valid
func (p *Provider) ValidateCredentials(ctx context.Context) error {
	cfg, err := p.loadConfig(ctx, "us-east-1")
	if err != nil {
		return fmt.Errorf("loading AWS config: %w", err)
	}

	// Test credentials with STS GetCallerIdentity
	stsClient := sts.NewFromConfig(cfg)
	_, err = stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("invalid AWS credentials: %w", err)
	}

	p.awsCfg = cfg
	return nil
}

// Discover finds all AWS assets across configured regions
func (p *Provider) Discover(ctx context.Context) ([]types.DiscoveredAsset, error) {
	regions := p.creds.Regions
	if len(regions) == 0 {
		regions = AllRegions
	}

	var (
		allAssets []types.DiscoveredAsset
		allErrors []types.DiscoveryError
		mu        sync.Mutex
		wg        sync.WaitGroup
		sem       = make(chan struct{}, p.cfg.ConcurrentScans)
	)

	for _, region := range regions {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(region string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			regionAssets, regionErrors := p.discoverRegion(ctx, region)

			mu.Lock()
			allAssets = append(allAssets, regionAssets...)
			allErrors = append(allErrors, regionErrors...)
			mu.Unlock()
		}(region)
	}

	wg.Wait()

	// Log any errors that occurred
	for _, e := range allErrors {
		p.logger.Warn("discovery error",
			"region", e.Region,
			"resource", e.Resource,
			"error", e.Message,
		)
	}

	p.logger.Info("AWS discovery complete",
		"total_assets", len(allAssets),
		"errors", len(allErrors),
	)

	return allAssets, nil
}

// discoverRegion discovers assets in a single AWS region
func (p *Provider) discoverRegion(ctx context.Context, region string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	cfg, err := p.loadConfig(ctx, region)
	if err != nil {
		errors = append(errors, types.DiscoveryError{
			Region:   region,
			Resource: "config",
			Message:  err.Error(),
		})
		return discovered, errors
	}

	p.logger.Debug("discovering region", "region", region)

	// Discover EC2 instances
	ec2Assets, ec2Errors := p.discoverEC2(ctx, cfg, region)
	discovered = append(discovered, ec2Assets...)
	errors = append(errors, ec2Errors...)

	// Discover S3 buckets (only in us-east-1 to avoid duplicates)
	if region == "us-east-1" {
		s3Assets, s3Errors := p.discoverS3(ctx, cfg)
		discovered = append(discovered, s3Assets...)
		errors = append(errors, s3Errors...)
	}

	// Discover Route53 (global, only in us-east-1)
	if region == "us-east-1" {
		route53Assets, route53Errors := p.discoverRoute53(ctx, cfg)
		discovered = append(discovered, route53Assets...)
		errors = append(errors, route53Errors...)
	}

	// Discover ELB/ALB
	elbAssets, elbErrors := p.discoverELB(ctx, cfg, region)
	discovered = append(discovered, elbAssets...)
	errors = append(errors, elbErrors...)

	return discovered, errors
}

// loadConfig creates an AWS config for the specified region
func (p *Provider) loadConfig(ctx context.Context, region string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			p.creds.AccessKeyID,
			p.creds.SecretAccessKey,
			"",
		)),
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, err
	}

	// Handle assume role if configured
	if p.creds.AssumeRoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		assumeRoleOpts := func(o *stscreds.AssumeRoleOptions) {
			if p.creds.ExternalID != "" {
				o.ExternalID = aws.String(p.creds.ExternalID)
			}
		}
		cfg.Credentials = stscreds.NewAssumeRoleProvider(stsClient, p.creds.AssumeRoleARN, assumeRoleOpts)
	}

	return cfg, nil
}

// discoverEC2 finds EC2 instances with public IPs
func (p *Provider) discoverEC2(ctx context.Context, cfg aws.Config, region string) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	client := ec2.NewFromConfig(cfg)

	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errors = append(errors, types.DiscoveryError{
				Region:   region,
				Resource: "ec2",
				Message:  err.Error(),
			})
			break
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				// Skip terminated instances
				if instance.State != nil && instance.State.Name == "terminated" {
					continue
				}

				instanceID := aws.ToString(instance.InstanceId)
				metadata := map[string]string{
					"instance_id":   instanceID,
					"instance_type": string(instance.InstanceType),
					"region":        region,
					"state":         string(instance.State.Name),
				}

				// Add tags to metadata
				for _, tag := range instance.Tags {
					if aws.ToString(tag.Key) == "Name" {
						metadata["name"] = aws.ToString(tag.Value)
					}
				}

				// Add public IP as asset
				if instance.PublicIpAddress != nil {
					discovered = append(discovered, types.DiscoveredAsset{
						Type:     models.AssetTypeIP,
						Value:    aws.ToString(instance.PublicIpAddress),
						Source:   "aws:ec2",
						Metadata: copyMetadata(metadata),
					})
				}

				// Add public DNS as asset
				if instance.PublicDnsName != nil && aws.ToString(instance.PublicDnsName) != "" {
					discovered = append(discovered, types.DiscoveredAsset{
						Type:     models.AssetTypeSubdomain,
						Value:    aws.ToString(instance.PublicDnsName),
						Source:   "aws:ec2",
						Metadata: copyMetadata(metadata),
					})
				}

				// Add private IP for internal scanning
				if instance.PrivateIpAddress != nil {
					metadata["visibility"] = "private"
					discovered = append(discovered, types.DiscoveredAsset{
						Type:     models.AssetTypeIP,
						Value:    aws.ToString(instance.PrivateIpAddress),
						Source:   "aws:ec2:private",
						Metadata: copyMetadata(metadata),
					})
				}
			}
		}
	}

	p.logger.Debug("discovered EC2 instances", "region", region, "count", len(discovered))
	return discovered, errors
}

func copyMetadata(m map[string]string) map[string]string {
	copy := make(map[string]string, len(m))
	for k, v := range m {
		copy[k] = v
	}
	return copy
}
