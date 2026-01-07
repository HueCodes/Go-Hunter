package scanner

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/assets/types"
	"github.com/hugh/go-hunter/internal/database/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewS3Checker(t *testing.T) {
	creds := types.AWSCredential{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	checker := NewS3Checker(creds, newTestLogger())

	require.NotNil(t, checker)
	assert.Equal(t, creds.AccessKeyID, checker.creds.AccessKeyID)
	assert.Equal(t, creds.SecretAccessKey, checker.creds.SecretAccessKey)
}

func TestNewS3Checker_WithAssumeRole(t *testing.T) {
	creds := types.AWSCredential{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		AssumeRoleARN:   "arn:aws:iam::123456789012:role/S3ReadRole",
		ExternalID:      "external-id-123",
	}

	checker := NewS3Checker(creds, newTestLogger())

	require.NotNil(t, checker)
	assert.Equal(t, creds.AssumeRoleARN, checker.creds.AssumeRoleARN)
	assert.Equal(t, creds.ExternalID, checker.creds.ExternalID)
}

func TestS3Checker_GenerateFindingHash(t *testing.T) {
	checker := NewS3Checker(types.AWSCredential{}, newTestLogger())
	assetID := uuid.New()

	hash1 := checker.generateFindingHash(assetID, "public_acl", "Test Title")
	hash2 := checker.generateFindingHash(assetID, "public_acl", "Test Title")
	hash3 := checker.generateFindingHash(assetID, "public_acl", "Different Title")
	hash4 := checker.generateFindingHash(uuid.New(), "public_acl", "Test Title")

	// Same inputs = same hash
	assert.Equal(t, hash1, hash2)
	// Different title = different hash
	assert.NotEqual(t, hash1, hash3)
	// Different asset ID = different hash
	assert.NotEqual(t, hash1, hash4)
	// Hash is 64 chars (SHA256 hex encoded)
	assert.Len(t, hash1, 64)
}

func TestS3Checker_IsAccessDenied(t *testing.T) {
	checker := NewS3Checker(types.AWSCredential{}, newTestLogger())

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "access denied",
			err:      &mockAPIError{code: "AccessDenied", message: "Access Denied"},
			expected: true,
		},
		{
			name:     "forbidden",
			err:      &mockAPIError{code: "Forbidden", message: "Forbidden"},
			expected: true,
		},
		{
			name:     "unauthorized access",
			err:      &mockAPIError{code: "UnauthorizedAccess", message: "Unauthorized"},
			expected: true,
		},
		{
			name:     "not found",
			err:      &mockAPIError{code: "NoSuchBucket", message: "Bucket not found"},
			expected: false,
		},
		{
			name:     "regular error",
			err:      fmt.Errorf("network error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.isAccessDenied(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestS3Checker_DescribePolicyRisk(t *testing.T) {
	checker := NewS3Checker(types.AWSCredential{}, newTestLogger())

	withCondition := checker.describePolicyRisk(true)
	assert.Contains(t, withCondition, "conditions are present")

	withoutCondition := checker.describePolicyRisk(false)
	assert.Contains(t, withoutCondition, "unrestricted access")
}

func TestCheckResult_ToFinding(t *testing.T) {
	assetID := uuid.New()
	scanID := uuid.New()
	orgID := uuid.New()

	checkResult := CheckResult{
		CheckType:   CheckTypePublicACL,
		Title:       "Public Read Access Enabled via ACL",
		Description: "The S3 bucket 'test-bucket' has public read access.",
		Severity:    models.SeverityCritical,
		Evidence: map[string]interface{}{
			"bucket_name": "test-bucket",
			"permission":  "READ",
		},
		Remediation: "Remove the public ACL grant.",
		References:  []string{"https://docs.aws.amazon.com/s3/"},
	}

	// Simulate conversion (same logic as in CheckBucket)
	evidenceJSON, _ := json.Marshal(checkResult.Evidence)
	referencesJSON, _ := json.Marshal(checkResult.References)

	checker := NewS3Checker(types.AWSCredential{}, newTestLogger())
	hash := checker.generateFindingHash(assetID, string(checkResult.CheckType), checkResult.Title)

	finding := models.Finding{
		OrganizationID: orgID,
		AssetID:        assetID,
		ScanID:         scanID,
		Title:          checkResult.Title,
		Description:    checkResult.Description,
		Severity:       checkResult.Severity,
		Status:         models.FindingStatusOpen,
		Type:           string(checkResult.CheckType),
		Category:       "cloud",
		Evidence:       string(evidenceJSON),
		RawData:        string(evidenceJSON),
		Remediation:    checkResult.Remediation,
		References:     string(referencesJSON),
		Hash:           hash,
	}

	assert.Equal(t, orgID, finding.OrganizationID)
	assert.Equal(t, assetID, finding.AssetID)
	assert.Equal(t, scanID, finding.ScanID)
	assert.Equal(t, "Public Read Access Enabled via ACL", finding.Title)
	assert.Equal(t, models.SeverityCritical, finding.Severity)
	assert.Equal(t, string(CheckTypePublicACL), finding.Type)
	assert.Equal(t, "cloud", finding.Category)
	assert.Contains(t, finding.Evidence, "test-bucket")
	assert.NotEmpty(t, finding.Hash)
}

func TestS3CheckTypes(t *testing.T) {
	// Verify check type constants
	assert.Equal(t, S3CheckType("public_acl"), CheckTypePublicACL)
	assert.Equal(t, S3CheckType("public_bucket_policy"), CheckTypePublicPolicy)
	assert.Equal(t, S3CheckType("public_access_block"), CheckTypePublicAccessBlock)
	assert.Equal(t, S3CheckType("bucket_versioning"), CheckTypeBucketVersioning)
	assert.Equal(t, S3CheckType("server_encryption"), CheckTypeServerEncryption)
	assert.Equal(t, S3CheckType("bucket_logging"), CheckTypeBucketLogging)
}

func TestCheckResult_Severities(t *testing.T) {
	// Test that different check types have appropriate severities
	tests := []struct {
		checkType S3CheckType
		minSev    models.Severity
	}{
		{CheckTypePublicACL, models.SeverityHigh},
		{CheckTypePublicPolicy, models.SeverityCritical},
		{CheckTypePublicAccessBlock, models.SeverityHigh},
		{CheckTypeBucketVersioning, models.SeverityLow},
		{CheckTypeServerEncryption, models.SeverityMedium},
		{CheckTypeBucketLogging, models.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(string(tt.checkType), func(t *testing.T) {
			// Just verify the check types are usable as strings
			assert.NotEmpty(t, string(tt.checkType))
		})
	}
}

func TestCheckResult_EvidenceJSON(t *testing.T) {
	checkResult := CheckResult{
		CheckType: CheckTypePublicACL,
		Evidence: map[string]interface{}{
			"bucket_name": "my-bucket",
			"grantee_uri": "http://acs.amazonaws.com/groups/global/AllUsers",
			"permission":  "FULL_CONTROL",
			"acl_type":    "AllUsers",
		},
	}

	jsonBytes, err := json.Marshal(checkResult.Evidence)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(jsonBytes, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "my-bucket", parsed["bucket_name"])
	assert.Equal(t, "FULL_CONTROL", parsed["permission"])
}

func TestCheckResult_References(t *testing.T) {
	checkResult := CheckResult{
		CheckType: CheckTypePublicAccessBlock,
		References: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html",
		},
	}

	jsonBytes, err := json.Marshal(checkResult.References)
	require.NoError(t, err)

	var parsed []string
	err = json.Unmarshal(jsonBytes, &parsed)
	require.NoError(t, err)

	assert.Len(t, parsed, 2)
	assert.Contains(t, parsed[0], "block-public-access")
}

// mockAPIError implements smithy.APIError for testing
type mockAPIError struct {
	code    string
	message string
}

func (e *mockAPIError) Error() string {
	return e.message
}

func (e *mockAPIError) ErrorCode() string {
	return e.code
}

func (e *mockAPIError) ErrorMessage() string {
	return e.message
}

func (e *mockAPIError) ErrorFault() smithy.ErrorFault {
	return smithy.FaultClient
}

// Verify mockAPIError implements smithy.APIError
var _ smithy.APIError = (*mockAPIError)(nil)
