package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/assets/types"
	"github.com/hugh/go-hunter/internal/database/models"
)

// S3CheckType identifies the type of S3 security check
type S3CheckType string

const (
	CheckTypePublicACL         S3CheckType = "public_acl"
	CheckTypePublicPolicy      S3CheckType = "public_bucket_policy"
	CheckTypePublicAccessBlock S3CheckType = "public_access_block"
	CheckTypeBucketVersioning  S3CheckType = "bucket_versioning"
	CheckTypeServerEncryption  S3CheckType = "server_encryption"
	CheckTypeBucketLogging     S3CheckType = "bucket_logging"
)

// S3Checker performs security checks on S3 buckets
type S3Checker struct {
	creds  types.AWSCredential
	logger *slog.Logger
}

// NewS3Checker creates a new S3 security checker
func NewS3Checker(creds types.AWSCredential, logger *slog.Logger) *S3Checker {
	return &S3Checker{
		creds:  creds,
		logger: logger,
	}
}

// CheckResult represents a single security finding for an S3 bucket
type CheckResult struct {
	CheckType   S3CheckType
	Title       string
	Description string
	Severity    models.Severity
	Evidence    map[string]interface{}
	Remediation string
	References  []string
}

// CheckBucket performs all security checks on a bucket and returns findings
func (c *S3Checker) CheckBucket(ctx context.Context, bucketName string, assetID, scanID, orgID uuid.UUID) ([]models.Finding, error) {
	// Determine bucket region first
	region, err := c.getBucketRegion(ctx, bucketName)
	if err != nil {
		c.logger.Warn("failed to get bucket region, using us-east-1",
			"bucket", bucketName,
			"error", err,
		)
		region = "us-east-1"
	}

	// Create S3 client for the bucket's region
	cfg, err := c.loadConfig(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config for region %s: %w", region, err)
	}

	client := s3.NewFromConfig(cfg)

	var results []CheckResult

	// Run all checks, collecting results
	if aclResults := c.checkBucketACL(ctx, client, bucketName); len(aclResults) > 0 {
		results = append(results, aclResults...)
	}

	if result := c.checkBucketPolicy(ctx, client, bucketName); result != nil {
		results = append(results, *result)
	}

	if result := c.checkPublicAccessBlock(ctx, client, bucketName); result != nil {
		results = append(results, *result)
	}

	if result := c.checkBucketVersioning(ctx, client, bucketName); result != nil {
		results = append(results, *result)
	}

	if result := c.checkServerEncryption(ctx, client, bucketName); result != nil {
		results = append(results, *result)
	}

	if result := c.checkBucketLogging(ctx, client, bucketName); result != nil {
		results = append(results, *result)
	}

	// Convert results to Finding models
	now := time.Now().Unix()
	var findings []models.Finding

	for _, result := range results {
		// Marshal evidence to JSON
		evidenceJSON, _ := json.Marshal(result.Evidence)
		referencesJSON, _ := json.Marshal(result.References)

		// Generate deduplication hash
		hash := c.generateFindingHash(assetID, string(result.CheckType), result.Title)

		finding := models.Finding{
			OrganizationID: orgID,
			AssetID:        assetID,
			ScanID:         scanID,
			Title:          result.Title,
			Description:    result.Description,
			Severity:       result.Severity,
			Status:         models.FindingStatusOpen,
			Type:           string(result.CheckType),
			Category:       "cloud",
			Evidence:       string(evidenceJSON),
			RawData:        string(evidenceJSON),
			Remediation:    result.Remediation,
			References:     string(referencesJSON),
			FirstSeenAt:    now,
			LastSeenAt:     now,
			Hash:           hash,
		}

		findings = append(findings, finding)
	}

	c.logger.Debug("completed S3 bucket checks",
		"bucket", bucketName,
		"findings", len(findings),
	)

	return findings, nil
}

// getBucketRegion determines the region where a bucket is located
func (c *S3Checker) getBucketRegion(ctx context.Context, bucketName string) (string, error) {
	cfg, err := c.loadConfig(ctx, "us-east-1")
	if err != nil {
		return "", err
	}

	client := s3.NewFromConfig(cfg)

	result, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return "", fmt.Errorf("getting bucket location: %w", err)
	}

	region := string(result.LocationConstraint)
	if region == "" {
		region = "us-east-1" // Default region for buckets without explicit location
	}

	return region, nil
}

// loadConfig creates an AWS config for the specified region
func (c *S3Checker) loadConfig(ctx context.Context, region string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			c.creds.AccessKeyID,
			c.creds.SecretAccessKey,
			"",
		)),
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, err
	}

	// Handle assume role if configured
	if c.creds.AssumeRoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		assumeRoleOpts := func(o *stscreds.AssumeRoleOptions) {
			if c.creds.ExternalID != "" {
				o.ExternalID = aws.String(c.creds.ExternalID)
			}
		}
		cfg.Credentials = stscreds.NewAssumeRoleProvider(stsClient, c.creds.AssumeRoleARN, assumeRoleOpts)
	}

	return cfg, nil
}

// checkBucketACL checks for public read/write access via ACL
func (c *S3Checker) checkBucketACL(ctx context.Context, client *s3.Client, bucketName string) []CheckResult {
	result, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		if c.isAccessDenied(err) {
			c.logger.Warn("access denied checking bucket ACL",
				"bucket", bucketName,
			)
			return nil
		}
		c.logger.Error("failed to get bucket ACL",
			"bucket", bucketName,
			"error", err,
		)
		return nil
	}

	var results []CheckResult

	// Check grants for public access
	for _, grant := range result.Grants {
		if grant.Grantee == nil {
			continue
		}

		// Check for AllUsers (public) or AuthenticatedUsers groups
		granteeURI := aws.ToString(grant.Grantee.URI)
		isPublic := strings.Contains(granteeURI, "AllUsers")
		isAuthenticatedUsers := strings.Contains(granteeURI, "AuthenticatedUsers")

		if !isPublic && !isAuthenticatedUsers {
			continue
		}

		permission := string(grant.Permission)

		// Public read access
		if isPublic && (grant.Permission == s3types.PermissionRead || grant.Permission == s3types.PermissionFullControl) {
			results = append(results, CheckResult{
				CheckType:   CheckTypePublicACL,
				Title:       "Public Read Access Enabled via ACL",
				Description: fmt.Sprintf("The S3 bucket '%s' has an ACL that grants public read access. Anyone on the internet can list and read objects in this bucket, potentially exposing sensitive data.", bucketName),
				Severity:    models.SeverityCritical,
				Evidence: map[string]interface{}{
					"bucket_name": bucketName,
					"grantee_uri": granteeURI,
					"permission":  permission,
					"acl_type":    "AllUsers",
				},
				Remediation: "Remove the public ACL grant by updating the bucket ACL to remove AllUsers access. Consider using bucket policies with explicit deny for public access, and enable S3 Block Public Access settings at the account level.",
				References: []string{
					"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
					"https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html",
				},
			})
		}

		// Public write access
		if isPublic && (grant.Permission == s3types.PermissionWrite || grant.Permission == s3types.PermissionFullControl) {
			results = append(results, CheckResult{
				CheckType:   CheckTypePublicACL,
				Title:       "Public Write Access Enabled via ACL",
				Description: fmt.Sprintf("The S3 bucket '%s' has an ACL that grants public write access. Anyone on the internet can upload, modify, or delete objects in this bucket. This is a severe security risk that could lead to data tampering, malware distribution, or unauthorized storage usage.", bucketName),
				Severity:    models.SeverityCritical,
				Evidence: map[string]interface{}{
					"bucket_name": bucketName,
					"grantee_uri": granteeURI,
					"permission":  permission,
					"acl_type":    "AllUsers",
				},
				Remediation: "Immediately remove the public write ACL grant. Review bucket contents for unauthorized modifications. Enable S3 Block Public Access settings and consider enabling MFA Delete for additional protection.",
				References: []string{
					"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
					"https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMFADelete.html",
				},
			})
		}

		// Authenticated users access (still a concern as any AWS account can access)
		if isAuthenticatedUsers {
			results = append(results, CheckResult{
				CheckType:   CheckTypePublicACL,
				Title:       "Authenticated Users Access Enabled via ACL",
				Description: fmt.Sprintf("The S3 bucket '%s' has an ACL that grants access to any authenticated AWS user. Any person with an AWS account can access this bucket with %s permissions.", bucketName, permission),
				Severity:    models.SeverityHigh,
				Evidence: map[string]interface{}{
					"bucket_name": bucketName,
					"grantee_uri": granteeURI,
					"permission":  permission,
					"acl_type":    "AuthenticatedUsers",
				},
				Remediation: "Remove the AuthenticatedUsers ACL grant and use specific IAM policies to grant access only to required principals.",
				References: []string{
					"https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#specifying-grantee-predefined-groups",
				},
			})
		}
	}

	return results
}

// checkBucketPolicy checks for public access via bucket policy
func (c *S3Checker) checkBucketPolicy(ctx context.Context, client *s3.Client, bucketName string) *CheckResult {
	result, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		// NoSuchBucketPolicy is not an error - bucket just has no policy
		var apiErr smithy.APIError
		if ok := errors.As(err, &apiErr); ok && apiErr.ErrorCode() == "NoSuchBucketPolicy" {
			return nil
		}
		if c.isAccessDenied(err) {
			c.logger.Warn("access denied checking bucket policy",
				"bucket", bucketName,
			)
			return nil
		}
		c.logger.Error("failed to get bucket policy",
			"bucket", bucketName,
			"error", err,
		)
		return nil
	}

	policy := aws.ToString(result.Policy)
	if policy == "" {
		return nil
	}

	// Parse and analyze the policy
	var policyDoc struct {
		Version   string `json:"Version"`
		Statement []struct {
			Sid       string      `json:"Sid"`
			Effect    string      `json:"Effect"`
			Principal interface{} `json:"Principal"`
			Action    interface{} `json:"Action"`
			Resource  interface{} `json:"Resource"`
			Condition interface{} `json:"Condition,omitempty"`
		} `json:"Statement"`
	}

	if err := json.Unmarshal([]byte(policy), &policyDoc); err != nil {
		c.logger.Error("failed to parse bucket policy",
			"bucket", bucketName,
			"error", err,
		)
		return nil
	}

	// Check each statement for public access
	for _, stmt := range policyDoc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		isPublic := false
		principalStr := ""

		switch p := stmt.Principal.(type) {
		case string:
			if p == "*" {
				isPublic = true
				principalStr = "*"
			}
		case map[string]interface{}:
			if aws, ok := p["AWS"]; ok {
				switch a := aws.(type) {
				case string:
					if a == "*" {
						isPublic = true
						principalStr = "AWS: *"
					}
				case []interface{}:
					for _, v := range a {
						if v == "*" {
							isPublic = true
							principalStr = "AWS: [*, ...]"
							break
						}
					}
				}
			}
		}

		if isPublic {
			// Check if there are conditions that might restrict access
			hasCondition := stmt.Condition != nil

			return &CheckResult{
				CheckType:   CheckTypePublicPolicy,
				Title:       "Public Bucket Policy Detected",
				Description: fmt.Sprintf("The S3 bucket '%s' has a bucket policy that grants public access (Principal: %s). %s", bucketName, principalStr, c.describePolicyRisk(hasCondition)),
				Severity:    models.SeverityCritical,
				Evidence: map[string]interface{}{
					"bucket_name":    bucketName,
					"policy":         policy,
					"principal":      principalStr,
					"has_conditions": hasCondition,
					"statement_sid":  stmt.Sid,
				},
				Remediation: "Review and update the bucket policy to remove public access. Use specific AWS account IDs or IAM ARNs instead of wildcards. If public access is required, ensure it's intentional and use conditions to restrict access appropriately.",
				References: []string{
					"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html",
					"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html",
				},
			}
		}
	}

	return nil
}

// describePolicyRisk returns appropriate risk description based on conditions
func (c *S3Checker) describePolicyRisk(hasCondition bool) string {
	if hasCondition {
		return "While conditions are present that may restrict access, any policy with a wildcard principal should be carefully reviewed."
	}
	return "This allows unrestricted access to the bucket from any source, which could lead to data exposure or unauthorized access."
}

// checkPublicAccessBlock checks if public access block is disabled
func (c *S3Checker) checkPublicAccessBlock(ctx context.Context, client *s3.Client, bucketName string) *CheckResult {
	result, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		// NoSuchPublicAccessBlockConfiguration means public access block is not configured
		var apiErr smithy.APIError
		if ok := errors.As(err, &apiErr); ok && apiErr.ErrorCode() == "NoSuchPublicAccessBlockConfiguration" {
			return &CheckResult{
				CheckType:   CheckTypePublicAccessBlock,
				Title:       "S3 Block Public Access Not Configured",
				Description: fmt.Sprintf("The S3 bucket '%s' does not have Block Public Access settings configured. This means the bucket could potentially be made public through ACLs or bucket policies.", bucketName),
				Severity:    models.SeverityHigh,
				Evidence: map[string]interface{}{
					"bucket_name":             bucketName,
					"public_access_block":     "not_configured",
					"block_public_acls":       false,
					"ignore_public_acls":      false,
					"block_public_policy":     false,
					"restrict_public_buckets": false,
				},
				Remediation: "Enable S3 Block Public Access settings at both the bucket and account level. Configure all four settings: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.",
				References: []string{
					"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
				},
			}
		}
		if c.isAccessDenied(err) {
			c.logger.Warn("access denied checking public access block",
				"bucket", bucketName,
			)
			return nil
		}
		c.logger.Error("failed to get public access block",
			"bucket", bucketName,
			"error", err,
		)
		return nil
	}

	if result.PublicAccessBlockConfiguration == nil {
		return nil
	}

	cfg := result.PublicAccessBlockConfiguration
	blockPublicAcls := aws.ToBool(cfg.BlockPublicAcls)
	ignorePublicAcls := aws.ToBool(cfg.IgnorePublicAcls)
	blockPublicPolicy := aws.ToBool(cfg.BlockPublicPolicy)
	restrictPublicBuckets := aws.ToBool(cfg.RestrictPublicBuckets)

	// Check if any settings are disabled
	allEnabled := blockPublicAcls && ignorePublicAcls && blockPublicPolicy && restrictPublicBuckets

	if !allEnabled {
		var disabledSettings []string
		if !blockPublicAcls {
			disabledSettings = append(disabledSettings, "BlockPublicAcls")
		}
		if !ignorePublicAcls {
			disabledSettings = append(disabledSettings, "IgnorePublicAcls")
		}
		if !blockPublicPolicy {
			disabledSettings = append(disabledSettings, "BlockPublicPolicy")
		}
		if !restrictPublicBuckets {
			disabledSettings = append(disabledSettings, "RestrictPublicBuckets")
		}

		return &CheckResult{
			CheckType:   CheckTypePublicAccessBlock,
			Title:       "S3 Block Public Access Partially Disabled",
			Description: fmt.Sprintf("The S3 bucket '%s' has some Block Public Access settings disabled: %s. This could allow the bucket to be made publicly accessible.", bucketName, strings.Join(disabledSettings, ", ")),
			Severity:    models.SeverityHigh,
			Evidence: map[string]interface{}{
				"bucket_name":             bucketName,
				"block_public_acls":       blockPublicAcls,
				"ignore_public_acls":      ignorePublicAcls,
				"block_public_policy":     blockPublicPolicy,
				"restrict_public_buckets": restrictPublicBuckets,
				"disabled_settings":       disabledSettings,
			},
			Remediation: "Enable all Block Public Access settings for this bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets. Also consider enabling these at the account level for defense in depth.",
			References: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
			},
		}
	}

	return nil
}

// checkBucketVersioning checks if versioning is disabled
func (c *S3Checker) checkBucketVersioning(ctx context.Context, client *s3.Client, bucketName string) *CheckResult {
	result, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		if c.isAccessDenied(err) {
			c.logger.Warn("access denied checking bucket versioning",
				"bucket", bucketName,
			)
			return nil
		}
		c.logger.Error("failed to get bucket versioning",
			"bucket", bucketName,
			"error", err,
		)
		return nil
	}

	// Check if versioning is not enabled
	if result.Status != s3types.BucketVersioningStatusEnabled {
		status := "Disabled"
		if result.Status == s3types.BucketVersioningStatusSuspended {
			status = "Suspended"
		}

		return &CheckResult{
			CheckType:   CheckTypeBucketVersioning,
			Title:       "Bucket Versioning Disabled",
			Description: fmt.Sprintf("The S3 bucket '%s' does not have versioning enabled (Status: %s). Without versioning, deleted or overwritten objects cannot be recovered, increasing data loss risk.", bucketName, status),
			Severity:    models.SeverityLow,
			Evidence: map[string]interface{}{
				"bucket_name":       bucketName,
				"versioning_status": status,
				"mfa_delete":        string(result.MFADelete),
			},
			Remediation: "Enable versioning on this bucket to protect against accidental deletion or overwrites. Consider also enabling MFA Delete for critical buckets.",
			References: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMFADelete.html",
			},
		}
	}

	return nil
}

// checkServerEncryption checks if default encryption is enabled
func (c *S3Checker) checkServerEncryption(ctx context.Context, client *s3.Client, bucketName string) *CheckResult {
	result, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		// ServerSideEncryptionConfigurationNotFoundError means no encryption configured
		var apiErr smithy.APIError
		if ok := errors.As(err, &apiErr); ok && apiErr.ErrorCode() == "ServerSideEncryptionConfigurationNotFoundError" {
			return &CheckResult{
				CheckType:   CheckTypeServerEncryption,
				Title:       "Default Server-Side Encryption Not Enabled",
				Description: fmt.Sprintf("The S3 bucket '%s' does not have default server-side encryption enabled. Objects uploaded without explicit encryption will be stored unencrypted, which may violate data protection requirements.", bucketName),
				Severity:    models.SeverityMedium,
				Evidence: map[string]interface{}{
					"bucket_name":   bucketName,
					"encryption":    "not_configured",
					"sse_algorithm": "none",
				},
				Remediation: "Enable default encryption using either SSE-S3 (AES-256) or SSE-KMS with a customer managed key. SSE-KMS provides additional control and audit capabilities through AWS CloudTrail.",
				References: []string{
					"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
					"https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html",
				},
			}
		}
		if c.isAccessDenied(err) {
			c.logger.Warn("access denied checking bucket encryption",
				"bucket", bucketName,
			)
			return nil
		}
		c.logger.Error("failed to get bucket encryption",
			"bucket", bucketName,
			"error", err,
		)
		return nil
	}

	// Encryption is configured - no finding needed
	if result.ServerSideEncryptionConfiguration != nil &&
		len(result.ServerSideEncryptionConfiguration.Rules) > 0 {
		return nil
	}

	return nil
}

// checkBucketLogging checks if access logging is enabled
func (c *S3Checker) checkBucketLogging(ctx context.Context, client *s3.Client, bucketName string) *CheckResult {
	result, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		if c.isAccessDenied(err) {
			c.logger.Warn("access denied checking bucket logging",
				"bucket", bucketName,
			)
			return nil
		}
		c.logger.Error("failed to get bucket logging",
			"bucket", bucketName,
			"error", err,
		)
		return nil
	}

	// Check if logging is not configured
	if result.LoggingEnabled == nil {
		return &CheckResult{
			CheckType:   CheckTypeBucketLogging,
			Title:       "Bucket Access Logging Disabled",
			Description: fmt.Sprintf("The S3 bucket '%s' does not have access logging enabled. Without logging, it is difficult to audit who accessed the bucket, detect unauthorized access, or perform forensic analysis.", bucketName),
			Severity:    models.SeverityInfo,
			Evidence: map[string]interface{}{
				"bucket_name": bucketName,
				"logging":     "disabled",
			},
			Remediation: "Enable server access logging for this bucket. Configure logs to be delivered to a separate logging bucket. Consider also using AWS CloudTrail for data event logging which provides more detailed access information.",
			References: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging.html",
			},
		}
	}

	return nil
}

// isAccessDenied checks if an error is an access denied error
func (c *S3Checker) isAccessDenied(err error) bool {
	var apiErr smithy.APIError
	if ok := errors.As(err, &apiErr); ok {
		code := apiErr.ErrorCode()
		return code == "AccessDenied" || code == "Forbidden" || code == "UnauthorizedAccess"
	}
	return false
}

// generateFindingHash creates a deterministic hash for deduplication
func (c *S3Checker) generateFindingHash(assetID uuid.UUID, checkType, title string) string {
	data := fmt.Sprintf("%s:%s:%s", assetID.String(), checkType, title)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
