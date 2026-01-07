package validation

import (
	"net"
	"regexp"
	"strings"
	"unicode"
)

var (
	// EmailRegex validates email format
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

	// DomainRegex validates domain format
	domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

	// UUIDRegex validates UUID format
	uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

	// PortRangeRegex validates port range format like "1-1000" or "80,443,8080"
	portRangeRegex = regexp.MustCompile(`^(\d+(-\d+)?)(,\d+(-\d+)?)*$`)
)

// IsValidEmail checks if the string is a valid email format
func IsValidEmail(email string) bool {
	if len(email) > 254 {
		return false
	}
	return emailRegex.MatchString(email)
}

// IsValidDomain checks if the string is a valid domain format
func IsValidDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}
	return domainRegex.MatchString(domain)
}

// IsValidUUID checks if the string is a valid UUID format
func IsValidUUID(id string) bool {
	return uuidRegex.MatchString(id)
}

// IsValidIP checks if the string is a valid IP address (v4 or v6)
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsValidIPv4 checks if the string is a valid IPv4 address
func IsValidIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

// IsValidCIDR checks if the string is a valid CIDR notation
func IsValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// IsValidPortRange checks if the string is a valid port specification
func IsValidPortRange(ports string) bool {
	if ports == "" {
		return true // Empty is valid (uses defaults)
	}
	return portRangeRegex.MatchString(ports)
}

// IsValidPassword checks password strength
func IsValidPassword(password string) (bool, string) {
	if len(password) < 8 {
		return false, "Password must be at least 8 characters"
	}
	if len(password) > 128 {
		return false, "Password must be at most 128 characters"
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return false, "Password must contain at least one uppercase letter"
	}
	if !hasLower {
		return false, "Password must contain at least one lowercase letter"
	}
	if !hasNumber {
		return false, "Password must contain at least one number"
	}
	if !hasSpecial {
		return false, "Password must contain at least one special character"
	}

	return true, ""
}

// SanitizeString removes potentially dangerous characters for display
func SanitizeString(s string) string {
	// Remove null bytes
	s = strings.ReplaceAll(s, "\x00", "")

	// Remove control characters except newlines and tabs
	var result strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || !unicode.IsControl(r) {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// EscapeHTML escapes HTML special characters
func EscapeHTML(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

// TruncateString truncates a string to maxLen characters
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// ValidateAssetValue validates an asset value based on its type
func ValidateAssetValue(assetType, value string) (bool, string) {
	switch assetType {
	case "domain", "subdomain":
		if !IsValidDomain(value) {
			return false, "Invalid domain format"
		}
	case "ip":
		if !IsValidIP(value) {
			return false, "Invalid IP address format"
		}
	case "cidr":
		if !IsValidCIDR(value) {
			return false, "Invalid CIDR notation"
		}
	case "bucket":
		// S3 bucket naming rules
		if len(value) < 3 || len(value) > 63 {
			return false, "Bucket name must be between 3 and 63 characters"
		}
	case "endpoint":
		// Basic URL validation
		if !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
			return false, "Endpoint must be a valid URL starting with http:// or https://"
		}
	}
	return true, ""
}

// ValidateCredentialData validates credential data for different providers
func ValidateCredentialData(provider string, data map[string]interface{}) map[string]string {
	errors := make(map[string]string)

	switch provider {
	case "aws":
		if _, ok := data["access_key_id"]; !ok {
			errors["access_key_id"] = "AWS Access Key ID is required"
		}
		if _, ok := data["secret_access_key"]; !ok {
			errors["secret_access_key"] = "AWS Secret Access Key is required"
		}
	case "gcp":
		if _, ok := data["service_account_json"]; !ok {
			errors["service_account_json"] = "GCP service account JSON is required"
		}
	case "azure":
		required := []string{"tenant_id", "client_id", "client_secret", "subscription_id"}
		for _, field := range required {
			if _, ok := data[field]; !ok {
				errors[field] = "Azure " + field + " is required"
			}
		}
	case "digitalocean":
		if _, ok := data["api_token"]; !ok {
			errors["api_token"] = "DigitalOcean API token is required"
		}
	case "cloudflare":
		if _, ok := data["api_token"]; !ok {
			errors["api_token"] = "Cloudflare API token is required"
		}
	default:
		errors["provider"] = "Unsupported provider: " + provider
	}

	return errors
}
