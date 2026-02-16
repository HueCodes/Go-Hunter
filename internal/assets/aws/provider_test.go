package aws

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hugh/go-hunter/internal/assets/types"
	"github.com/hugh/go-hunter/internal/database/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProviderName tests the Name() method
func TestProviderName(t *testing.T) {
	creds := types.AWSCredential{
		AccessKeyID:     "test-key",
		SecretAccessKey: "test-secret",
	}
	cfg := types.ProviderConfig{
		ConcurrentScans: 5,
		TimeoutSeconds:  30,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	provider := New(creds, cfg, logger)
	assert.Equal(t, models.ProviderAWS, provider.Name())
}

// TestValidateCredentials_Success tests successful credential validation
func TestValidateCredentials_Success(t *testing.T) {
	// This test requires actual AWS credentials or mocking the AWS SDK
	// For now, we'll skip it in CI/CD but provide the structure
	t.Skip("Requires AWS credentials or SDK mocking")

	creds := types.AWSCredential{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	cfg := types.ProviderConfig{
		ConcurrentScans: 5,
		TimeoutSeconds:  30,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	provider := New(creds, cfg, logger)
	err := provider.ValidateCredentials(context.Background())

	// With mock credentials, this should fail
	assert.Error(t, err)
}

// TestValidateCredentials_InvalidCredentials tests invalid credentials
func TestValidateCredentials_InvalidCredentials(t *testing.T) {
	creds := types.AWSCredential{
		AccessKeyID:     "invalid-key",
		SecretAccessKey: "invalid-secret",
	}
	cfg := types.ProviderConfig{
		ConcurrentScans: 5,
		TimeoutSeconds:  30,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	provider := New(creds, cfg, logger)
	ctx := context.Background()

	err := provider.ValidateCredentials(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid AWS credentials")
}

// TestDiscover_DefaultRegions tests discovery with default regions
func TestDiscover_DefaultRegions(t *testing.T) {
	t.Skip("Requires AWS SDK mocking or integration test environment")

	creds := types.AWSCredential{
		AccessKeyID:     "test-key",
		SecretAccessKey: "test-secret",
		Regions:         []string{}, // Empty to use defaults
	}
	cfg := types.ProviderConfig{
		ConcurrentScans: 3,
		TimeoutSeconds:  30,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	provider := New(creds, cfg, logger)

	// Mock the AWS config to avoid real API calls
	ctx := context.Background()
	_, err := provider.Discover(ctx)

	// Without mocking, this will fail
	assert.Error(t, err)
}

// TestDiscover_CustomRegions tests discovery with custom regions
func TestDiscover_CustomRegions(t *testing.T) {
	t.Skip("Requires AWS SDK mocking or integration test environment")

	creds := types.AWSCredential{
		AccessKeyID:     "test-key",
		SecretAccessKey: "test-secret",
		Regions:         []string{"us-east-1", "us-west-2"},
	}
	cfg := types.ProviderConfig{
		ConcurrentScans: 2,
		TimeoutSeconds:  30,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	provider := New(creds, cfg, logger)
	ctx := context.Background()

	_, err := provider.Discover(ctx)
	assert.Error(t, err) // Will fail without valid credentials
}

// TestDiscover_ConcurrencyControl tests semaphore-based concurrency
func TestDiscover_ConcurrencyControl(t *testing.T) {
	// This test verifies that the semaphore limits concurrent region scans
	// In a real implementation, we'd mock the discoverRegion function
	t.Skip("Requires refactoring for testability with dependency injection")
}

// TestDiscoverEC2_MockData tests EC2 discovery with mock data
func TestDiscoverEC2_MockData(t *testing.T) {
	t.Skip("Requires AWS SDK v2 mock client implementation")

	// Example of how this test would work with mocking:
	// 1. Create mock EC2 client
	// 2. Configure mock to return test instances
	// 3. Call discoverEC2 and verify results

	// Expected test cases:
	// - Instance with public IP
	// - Instance with public DNS
	// - Instance with private IP only
	// - Terminated instance (should be skipped)
	// - Instance with tags (Name tag should be in metadata)
	// - Pagination (multiple pages of results)
}

// TestDiscoverEC2_Pagination tests handling of paginated EC2 responses
func TestDiscoverEC2_Pagination(t *testing.T) {
	t.Skip("Requires AWS SDK v2 mock paginator")

	// Test that discoverEC2 correctly handles:
	// - Multiple pages of instances
	// - Accumulates all results
	// - Handles errors during pagination
}

// TestDiscoverEC2_ErrorHandling tests error scenarios
func TestDiscoverEC2_ErrorHandling(t *testing.T) {
	t.Skip("Requires AWS SDK v2 mock client for error injection")

	// Test cases:
	// - DescribeInstances API error
	// - Partial failure (some pages succeed, some fail)
	// - Context cancellation
	// - Timeout
}

// TestDiscoverS3_OnlyInUSEast1 tests that S3 discovery only runs in us-east-1
func TestDiscoverS3_OnlyInUSEast1(t *testing.T) {
	// S3 buckets are global, so we only discover them in us-east-1
	// This test would verify that discoverRegion only calls discoverS3 for us-east-1
	t.Skip("Requires AWS SDK mocking")
}

// TestDiscoverRoute53_OnlyInUSEast1 tests that Route53 discovery only runs in us-east-1
func TestDiscoverRoute53_OnlyInUSEast1(t *testing.T) {
	// Route53 is global, so we only discover zones in us-east-1
	t.Skip("Requires AWS SDK mocking")
}

// TestLoadConfig_BasicCredentials tests loading config with access key/secret
func TestLoadConfig_BasicCredentials(t *testing.T) {
	creds := types.AWSCredential{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	cfg := types.ProviderConfig{
		ConcurrentScans: 5,
		TimeoutSeconds:  30,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	provider := New(creds, cfg, logger)
	awsCfg, err := provider.loadConfig(context.Background(), "us-east-1")

	require.NoError(t, err)
	assert.Equal(t, "us-east-1", awsCfg.Region)
}

// TestLoadConfig_AssumeRole tests loading config with assume role
func TestLoadConfig_AssumeRole(t *testing.T) {
	creds := types.AWSCredential{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		AssumeRoleARN:   "arn:aws:iam::123456789012:role/TestRole",
		ExternalID:      "test-external-id",
	}
	cfg := types.ProviderConfig{
		ConcurrentScans: 5,
		TimeoutSeconds:  30,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	provider := New(creds, cfg, logger)
	awsCfg, err := provider.loadConfig(context.Background(), "us-west-2")

	require.NoError(t, err)
	assert.Equal(t, "us-west-2", awsCfg.Region)
	// Verify assume role credentials are configured
	assert.NotNil(t, awsCfg.Credentials)
}

// TestCopyMetadata tests the metadata copy helper
func TestCopyMetadata(t *testing.T) {
	original := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}

	copied := copyMetadata(original)

	assert.Equal(t, original, copied)

	// Verify it's a deep copy
	copied["key3"] = "value3"
	assert.NotContains(t, original, "key3")
}

// TestAllRegions verifies the complete list of AWS regions
func TestAllRegions(t *testing.T) {
	assert.NotEmpty(t, AllRegions)
	assert.Contains(t, AllRegions, "us-east-1")
	assert.Contains(t, AllRegions, "eu-west-1")
	assert.Contains(t, AllRegions, "ap-southeast-1")

	// Verify no duplicates
	regionSet := make(map[string]bool)
	for _, region := range AllRegions {
		assert.False(t, regionSet[region], "duplicate region: %s", region)
		regionSet[region] = true
	}
}

// TestDiscoverRegion_ErrorAccumulation tests that errors from different services are accumulated
func TestDiscoverRegion_ErrorAccumulation(t *testing.T) {
	t.Skip("Requires AWS SDK mocking to inject errors")

	// Test that if EC2, S3, and Route53 all fail, all errors are collected
	// and returned along with any successful discoveries
}

// Mock implementations for future use when adding comprehensive mocking

// mockSTSClient would mock the STS API for GetCallerIdentity
type mockSTSClient struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *mockSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.GetCallerIdentityFunc != nil {
		return m.GetCallerIdentityFunc(ctx, params, optFns...)
	}
	return nil, errors.New("not implemented")
}

// mockEC2Client would mock the EC2 API for DescribeInstances
type mockEC2Client struct {
	DescribeInstancesFunc func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

func (m *mockEC2Client) DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if m.DescribeInstancesFunc != nil {
		return m.DescribeInstancesFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeInstancesOutput{
		Reservations: []ec2types.Reservation{},
	}, nil
}

// mockS3Client would mock the S3 API for ListBuckets
type mockS3Client struct {
	ListBucketsFunc func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
}

func (m *mockS3Client) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if m.ListBucketsFunc != nil {
		return m.ListBucketsFunc(ctx, params, optFns...)
	}
	return &s3.ListBucketsOutput{}, nil
}

// mockRoute53Client would mock the Route53 API for ListHostedZones
type mockRoute53Client struct {
	ListHostedZonesFunc func(ctx context.Context, params *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
}

func (m *mockRoute53Client) ListHostedZones(ctx context.Context, params *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	if m.ListHostedZonesFunc != nil {
		return m.ListHostedZonesFunc(ctx, params, optFns...)
	}
	return &route53.ListHostedZonesOutput{
		HostedZones: []route53types.HostedZone{},
	}, nil
}

// Example of a complete test with mocking (commented out until SDK is refactored for DI)
/*
func TestDiscoverEC2_WithMocking(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  *ec2.DescribeInstancesOutput
		mockError     error
		expectedCount int
		expectError   bool
	}{
		{
			name: "single_instance_with_public_ip",
			mockResponse: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId:       aws.String("i-1234567890abcdef0"),
								InstanceType:     ec2types.InstanceTypeT2Micro,
								PublicIpAddress:  aws.String("54.123.45.67"),
								PrivateIpAddress: aws.String("10.0.1.100"),
								State: &ec2types.InstanceState{
									Name: ec2types.InstanceStateNameRunning,
								},
							},
						},
					},
				},
			},
			expectedCount: 2, // public IP + private IP
			expectError:   false,
		},
		{
			name: "terminated_instance_skipped",
			mockResponse: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId: aws.String("i-terminated"),
								State: &ec2types.InstanceState{
									Name: ec2types.InstanceStateNameTerminated,
								},
							},
						},
					},
				},
			},
			expectedCount: 0,
			expectError:   false,
		},
		{
			name:          "api_error",
			mockError:     errors.New("API rate limit exceeded"),
			expectedCount: 0,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockEC2Client{
				DescribeInstancesFunc: func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			// Inject mock client into provider
			// This would require refactoring the provider to accept clients via DI

			creds := types.AWSCredential{
				AccessKeyID:     "test-key",
				SecretAccessKey: "test-secret",
			}
			cfg := types.ProviderConfig{
				ConcurrentScans: 5,
				TimeoutSeconds:  30,
			}
			logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
			provider := New(creds, cfg, logger)

			// Call discoverEC2 with mock client
			// assets, errors := provider.discoverEC2(ctx, awsCfg, "us-east-1")

			// assert.Equal(t, tt.expectedCount, len(assets))
			// if tt.expectError {
			//     assert.NotEmpty(t, errors)
			// } else {
			//     assert.Empty(t, errors)
			// }
		})
	}
}
*/
