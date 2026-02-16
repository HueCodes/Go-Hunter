package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		name  string
		email string
		valid bool
	}{
		{"valid_simple", "user@example.com", true},
		{"valid_subdomain", "user@mail.example.com", true},
		{"valid_plus", "user+tag@example.com", true},
		{"valid_dash", "user-name@example.com", true},
		{"valid_dot", "user.name@example.com", true},
		{"valid_numbers", "user123@example456.com", true},
		{"invalid_no_at", "userexample.com", false},
		{"invalid_no_domain", "user@", false},
		{"invalid_no_user", "@example.com", false},
		{"invalid_double_at", "user@@example.com", false},
		{"invalid_spaces", "user @example.com", false},
		{"invalid_no_tld", "user@example", false},
		{"too_long", "a" + string(make([]byte, 250)) + "@example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidEmail(tt.email)
			assert.Equal(t, tt.valid, result, "Email: %s", tt.email)
		})
	}
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		valid  bool
	}{
		{"valid_simple", "example.com", true},
		{"valid_subdomain", "mail.example.com", true},
		{"valid_multiple_subs", "a.b.c.example.com", true},
		{"valid_dash", "my-domain.com", true},
		{"valid_numbers", "example123.com", true},
		{"invalid_no_tld", "example", false},
		{"invalid_dash_start", "-example.com", false},
		{"invalid_dash_end", "example-.com", false},
		{"invalid_underscore", "exam_ple.com", false},
		{"invalid_spaces", "exam ple.com", false},
		{"too_long", string(make([]byte, 255)) + ".com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidDomain(tt.domain)
			assert.Equal(t, tt.valid, result, "Domain: %s", tt.domain)
		})
	}
}

func TestIsValidUUID(t *testing.T) {
	tests := []struct {
		name  string
		uuid  string
		valid bool
	}{
		{"valid_uuid", "550e8400-e29b-41d4-a716-446655440000", true},
		{"valid_uppercase", "550E8400-E29B-41D4-A716-446655440000", true},
		{"valid_mixed", "550e8400-E29B-41d4-A716-446655440000", true},
		{"invalid_short", "550e8400-e29b-41d4-a716", false},
		{"invalid_long", "550e8400-e29b-41d4-a716-446655440000-extra", false},
		{"invalid_no_dashes", "550e8400e29b41d4a716446655440000", false},
		{"invalid_wrong_format", "550e8400-e29b-41d4a716-446655440000", false},
		{"invalid_letters", "ggge8400-e29b-41d4-a716-446655440000", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidUUID(tt.uuid)
			assert.Equal(t, tt.valid, result, "UUID: %s", tt.uuid)
		})
	}
}

func TestIsValidIP(t *testing.T) {
	tests := []struct {
		name  string
		ip    string
		valid bool
	}{
		{"valid_ipv4", "192.168.1.1", true},
		{"valid_ipv4_zero", "0.0.0.0", true},
		{"valid_ipv4_255", "255.255.255.255", true},
		{"valid_ipv6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", true},
		{"valid_ipv6_short", "2001:db8::1", true},
		{"valid_ipv6_localhost", "::1", true},
		{"invalid_out_of_range", "256.1.1.1", false},
		{"invalid_not_enough", "192.168.1", false},
		{"invalid_text", "not-an-ip", false},
		{"invalid_empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidIP(tt.ip)
			assert.Equal(t, tt.valid, result, "IP: %s", tt.ip)
		})
	}
}

func TestIsValidIPv4(t *testing.T) {
	tests := []struct {
		name  string
		ip    string
		valid bool
	}{
		{"valid_ipv4", "192.168.1.1", true},
		{"valid_localhost", "127.0.0.1", true},
		{"ipv6_not_v4", "2001:db8::1", false},
		{"invalid_format", "not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidIPv4(tt.ip)
			assert.Equal(t, tt.valid, result, "IP: %s", tt.ip)
		})
	}
}

func TestIsValidCIDR(t *testing.T) {
	tests := []struct {
		name  string
		cidr  string
		valid bool
	}{
		{"valid_class_c", "192.168.1.0/24", true},
		{"valid_class_b", "10.0.0.0/16", true},
		{"valid_single", "192.168.1.1/32", true},
		{"valid_ipv6", "2001:db8::/32", true},
		{"invalid_no_prefix", "192.168.1.0", false},
		{"invalid_bad_ip", "999.999.999.999/24", false},
		{"invalid_bad_prefix", "192.168.1.0/99", false},
		{"invalid_format", "not-a-cidr", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidCIDR(tt.cidr)
			assert.Equal(t, tt.valid, result, "CIDR: %s", tt.cidr)
		})
	}
}

func TestIsValidPortRange(t *testing.T) {
	tests := []struct {
		name  string
		ports string
		valid bool
	}{
		{"empty_default", "", true},
		{"single_port", "80", true},
		{"multiple_ports", "80,443,8080", true},
		{"range", "1-1000", true},
		{"mixed", "80,443,8000-9000", true},
		{"invalid_letters", "abc", false},
		{"invalid_dash_only", "80-", false},
		{"invalid_comma_only", "80,", false},
		{"invalid_double_dash", "80--90", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidPortRange(tt.ports)
			assert.Equal(t, tt.valid, result, "Ports: %s", tt.ports)
		})
	}
}

func TestIsValidPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		valid    bool
		errMsg   string
	}{
		{"valid_strong", "MyP@ssw0rd!", true, ""},
		{"valid_complex", "Tr0ng!Pass#2024", true, ""},
		{"too_short", "Pass1!", false, "at least 8 characters"},
		{"too_long", "MyP@ss" + string(make([]byte, 125)), false, "at most 128 characters"},
		{"no_uppercase", "myp@ssw0rd!", false, "uppercase letter"},
		{"no_lowercase", "MYP@SSW0RD!", false, "lowercase letter"},
		{"no_number", "MyPassword!", false, "number"},
		{"no_special", "MyPassword1", false, "special character"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, msg := IsValidPassword(tt.password)
			assert.Equal(t, tt.valid, valid, "Password: %s", tt.password)
			if !valid {
				assert.Contains(t, msg, tt.errMsg)
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"clean_text", "Hello World", "Hello World"},
		{"null_bytes", "Hello\x00World", "HelloWorld"},
		{"control_chars", "Hello\x01\x02World", "HelloWorld"},
		{"keep_newlines", "Hello\nWorld", "Hello\nWorld"},
		{"keep_tabs", "Hello\tWorld", "Hello\tWorld"},
		{"keep_carriage_return", "Hello\rWorld", "Hello\rWorld"},
		{"mixed", "Hello\x00\x01\nWorld\t!", "Hello\nWorld\t!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEscapeHTML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no_special", "Hello World", "Hello World"},
		{"ampersand", "Ben & Jerry", "Ben &amp; Jerry"},
		{"less_than", "<script>", "&lt;script&gt;"},
		{"greater_than", "a > b", "a &gt; b"},
		{"double_quote", `Say "Hello"`, "Say &quot;Hello&quot;"},
		{"single_quote", "It's fine", "It&#39;s fine"},
		{"all_special", `<a href="test">&</a>`, "&lt;a href=&quot;test&quot;&gt;&amp;&lt;/a&gt;"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EscapeHTML(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"shorter_than_max", "Hello", 10, "Hello"},
		{"equal_to_max", "Hello", 5, "Hello"},
		{"longer_than_max", "Hello World", 5, "Hello"},
		{"empty", "", 10, ""},
		{"zero_max", "Hello", 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TruncateString(tt.input, tt.maxLen)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateAssetValue(t *testing.T) {
	tests := []struct {
		name      string
		assetType string
		value     string
		valid     bool
		errMsg    string
	}{
		{"valid_domain", "domain", "example.com", true, ""},
		{"valid_subdomain", "subdomain", "api.example.com", true, ""},
		{"invalid_domain", "domain", "not a domain", false, "Invalid domain format"},
		{"valid_ip", "ip", "192.168.1.1", true, ""},
		{"invalid_ip", "ip", "999.999.999.999", false, "Invalid IP address format"},
		{"valid_cidr", "cidr", "10.0.0.0/24", true, ""},
		{"invalid_cidr", "cidr", "10.0.0.0", false, "Invalid CIDR notation"},
		{"valid_bucket", "bucket", "my-s3-bucket", true, ""},
		{"bucket_too_short", "bucket", "ab", false, "between 3 and 63 characters"},
		{"bucket_too_long", "bucket", string(make([]byte, 65)), false, "between 3 and 63 characters"},
		{"valid_endpoint", "endpoint", "https://api.example.com", true, ""},
		{"invalid_endpoint", "endpoint", "not-a-url", false, "must be a valid URL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, msg := ValidateAssetValue(tt.assetType, tt.value)
			assert.Equal(t, tt.valid, valid)
			if !valid {
				assert.Contains(t, msg, tt.errMsg)
			}
		})
	}
}

func TestValidateCredentialData_AWS(t *testing.T) {
	tests := []struct {
		name   string
		data   map[string]interface{}
		hasErr bool
		errKey string
	}{
		{
			name: "valid_aws",
			data: map[string]interface{}{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			hasErr: false,
		},
		{
			name:   "missing_access_key",
			data:   map[string]interface{}{"secret_access_key": "secret"},
			hasErr: true,
			errKey: "access_key_id",
		},
		{
			name:   "missing_secret_key",
			data:   map[string]interface{}{"access_key_id": "AKIA..."},
			hasErr: true,
			errKey: "secret_access_key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := ValidateCredentialData("aws", tt.data)
			if tt.hasErr {
				assert.NotEmpty(t, errors)
				assert.Contains(t, errors, tt.errKey)
			} else {
				assert.Empty(t, errors)
			}
		})
	}
}

func TestValidateCredentialData_Azure(t *testing.T) {
	validData := map[string]interface{}{
		"tenant_id":       "tenant",
		"client_id":       "client",
		"client_secret":   "secret",
		"subscription_id": "sub",
	}

	errors := ValidateCredentialData("azure", validData)
	assert.Empty(t, errors)

	// Missing field
	incompleteData := map[string]interface{}{
		"tenant_id": "tenant",
		"client_id": "client",
	}
	errors = ValidateCredentialData("azure", incompleteData)
	assert.NotEmpty(t, errors)
	assert.Contains(t, errors, "client_secret")
	assert.Contains(t, errors, "subscription_id")
}

func TestValidateCredentialData_GCP(t *testing.T) {
	validData := map[string]interface{}{
		"service_account_json": `{"type":"service_account"}`,
	}
	errors := ValidateCredentialData("gcp", validData)
	assert.Empty(t, errors)

	emptyData := map[string]interface{}{}
	errors = ValidateCredentialData("gcp", emptyData)
	assert.NotEmpty(t, errors)
	assert.Contains(t, errors, "service_account_json")
}

func TestValidateCredentialData_DigitalOcean(t *testing.T) {
	validData := map[string]interface{}{
		"api_token": "dop_v1_abc123",
	}
	errors := ValidateCredentialData("digitalocean", validData)
	assert.Empty(t, errors)

	emptyData := map[string]interface{}{}
	errors = ValidateCredentialData("digitalocean", emptyData)
	assert.NotEmpty(t, errors)
	assert.Contains(t, errors, "api_token")
}

func TestValidateCredentialData_Cloudflare(t *testing.T) {
	validData := map[string]interface{}{
		"api_token": "cf_token_123",
	}
	errors := ValidateCredentialData("cloudflare", validData)
	assert.Empty(t, errors)

	emptyData := map[string]interface{}{}
	errors = ValidateCredentialData("cloudflare", emptyData)
	assert.NotEmpty(t, errors)
	assert.Contains(t, errors, "api_token")
}

func TestValidateCredentialData_UnsupportedProvider(t *testing.T) {
	data := map[string]interface{}{}
	errors := ValidateCredentialData("unknown-provider", data)
	assert.NotEmpty(t, errors)
	assert.Contains(t, errors, "provider")
	assert.Contains(t, errors["provider"], "Unsupported provider")
}
