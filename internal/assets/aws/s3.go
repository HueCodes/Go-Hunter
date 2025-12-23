package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/hugh/go-hunter/internal/assets/types"
	"github.com/hugh/go-hunter/internal/database/models"
)

// discoverS3 finds S3 buckets
func (p *Provider) discoverS3(ctx context.Context, cfg aws.Config) ([]types.DiscoveredAsset, []types.DiscoveryError) {
	var discovered []types.DiscoveredAsset
	var errors []types.DiscoveryError

	client := s3.NewFromConfig(cfg)

	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		errors = append(errors, types.DiscoveryError{
			Region:   "global",
			Resource: "s3",
			Message:  err.Error(),
		})
		return discovered, errors
	}

	for _, bucket := range result.Buckets {
		bucketName := aws.ToString(bucket.Name)

		metadata := map[string]string{
			"bucket_name":  bucketName,
			"created_date": bucket.CreationDate.String(),
		}

		// Get bucket location
		locResult, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: bucket.Name,
		})
		if err == nil {
			region := string(locResult.LocationConstraint)
			if region == "" {
				region = "us-east-1" // Default region
			}
			metadata["region"] = region
		}

		// Check if bucket has public access
		publicStatus := p.checkBucketPublicAccess(ctx, client, bucketName)
		metadata["public_access"] = publicStatus

		discovered = append(discovered, types.DiscoveredAsset{
			Type:     models.AssetTypeBucket,
			Value:    bucketName,
			Source:   "aws:s3",
			Metadata: metadata,
		})

		// Also add the bucket URL as an endpoint
		bucketURL := bucketName + ".s3.amazonaws.com"
		discovered = append(discovered, types.DiscoveredAsset{
			Type:   models.AssetTypeEndpoint,
			Value:  bucketURL,
			Source: "aws:s3",
			Metadata: map[string]string{
				"bucket_name":   bucketName,
				"public_access": publicStatus,
			},
		})
	}

	p.logger.Debug("discovered S3 buckets", "count", len(result.Buckets))
	return discovered, errors
}

// checkBucketPublicAccess checks if a bucket has public access enabled
func (p *Provider) checkBucketPublicAccess(ctx context.Context, client *s3.Client, bucketName string) string {
	// Check public access block
	pabResult, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		// If we can't get the public access block, it might be public
		return "unknown"
	}

	if pabResult.PublicAccessBlockConfiguration != nil {
		cfg := pabResult.PublicAccessBlockConfiguration
		if aws.ToBool(cfg.BlockPublicAcls) &&
			aws.ToBool(cfg.BlockPublicPolicy) &&
			aws.ToBool(cfg.IgnorePublicAcls) &&
			aws.ToBool(cfg.RestrictPublicBuckets) {
			return "blocked"
		}
	}

	return "potentially_public"
}
