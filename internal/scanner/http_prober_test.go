package scanner

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPProber_ProbeHost_Success(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.20.0")
		w.Header().Set("X-Powered-By", "PHP/8.0")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><head><title>Test Page</title></head><body>Hello</body></html>"))
	}))
	defer server.Close()

	prober := NewHTTPProber(newTestLogger(), &HTTPProbeConfig{
		Timeout:     5 * time.Second,
		Concurrency: 10,
	})

	ctx := context.Background()
	// Extract host and port from server URL
	results := prober.probeURL(ctx, server.URL)

	require.NotNil(t, results)
	assert.Equal(t, http.StatusOK, results.StatusCode)
	assert.Equal(t, "nginx/1.20.0", results.Server)
	assert.Equal(t, "Test Page", results.Title)
	assert.Contains(t, results.Technologies, "Nginx")
	assert.Contains(t, results.Technologies, "PHP")
}

func TestHTTPProber_ProbeHost_Redirect(t *testing.T) {
	// Create redirect target
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><head><title>Final Page</title></head></html>"))
	}))
	defer target.Close()

	// Create redirecting server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusMovedPermanently)
	}))
	defer server.Close()

	// Test with follow redirect enabled
	prober := NewHTTPProber(newTestLogger(), &HTTPProbeConfig{
		Timeout:        5 * time.Second,
		FollowRedirect: true,
	})

	ctx := context.Background()
	result := prober.probeURL(ctx, server.URL)

	require.NotNil(t, result)
	// Following redirects should land on 200
	assert.Equal(t, http.StatusOK, result.StatusCode)
	assert.Equal(t, "Final Page", result.Title)
}

func TestHTTPProber_ProbeHost_NoRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/redirect")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer server.Close()

	// Test with follow redirect disabled
	prober := NewHTTPProber(newTestLogger(), &HTTPProbeConfig{
		Timeout:        5 * time.Second,
		FollowRedirect: false,
	})

	ctx := context.Background()
	result := prober.probeURL(ctx, server.URL)

	require.NotNil(t, result)
	assert.Equal(t, http.StatusMovedPermanently, result.StatusCode)
	assert.Equal(t, "https://example.com/redirect", result.RedirectURL)
}

func TestHTTPProber_ProbeHost_TLSInfo(t *testing.T) {
	// Create TLS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	prober := NewHTTPProber(newTestLogger(), &HTTPProbeConfig{
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	result := prober.probeURL(ctx, server.URL)

	require.NotNil(t, result)
	require.NotNil(t, result.TLSInfo)
	assert.NotEmpty(t, result.TLSInfo.Version)
	assert.NotEmpty(t, result.TLSInfo.CipherSuite)
	assert.True(t, result.TLSInfo.IsSelfsigned) // Test certs are self-signed
}

func TestHTTPProber_ProbeHost_Timeout(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	prober := NewHTTPProber(newTestLogger(), &HTTPProbeConfig{
		Timeout: 100 * time.Millisecond,
	})

	ctx := context.Background()
	result := prober.probeURL(ctx, server.URL)

	// Should return nil on timeout
	assert.Nil(t, result)
}

func TestHTTPProber_ProbeHost_Headers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "custom-value")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	prober := NewHTTPProber(newTestLogger(), nil)
	ctx := context.Background()
	result := prober.probeURL(ctx, server.URL)

	require.NotNil(t, result)
	assert.Equal(t, "custom-value", result.Headers["X-Custom-Header"])
	assert.Contains(t, result.Headers["Content-Type"], "text/html")
}

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		expected string
	}{
		{"basic title", "<html><head><title>Hello World</title></head></html>", "Hello World"},
		{"title with whitespace", "<title>  Trimmed Title  </title>", "Trimmed Title"},
		{"no title", "<html><head></head></html>", ""},
		{"empty title", "<title></title>", ""},
		{"title with attributes", "<title class='foo'>With Attrs</title>", "With Attrs"},
		{"case insensitive", "<TITLE>Upper Case</TITLE>", "Upper Case"},
		{"long title truncated", "<title>" + string(make([]byte, 300)) + "</title>", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTitle(tt.html)
			if tt.name == "long title truncated" {
				assert.LessOrEqual(t, len(result), 200)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestDetectTechnologies(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		body       string
		shouldFind []string
	}{
		{
			name:       "nginx server",
			headers:    map[string]string{"Server": "nginx/1.20.0"},
			body:       "",
			shouldFind: []string{"Nginx"},
		},
		{
			name:       "apache server",
			headers:    map[string]string{"Server": "Apache/2.4.48"},
			body:       "",
			shouldFind: []string{"Apache"},
		},
		{
			name:       "php powered",
			headers:    map[string]string{"X-Powered-By": "PHP/8.0"},
			body:       "",
			shouldFind: []string{"PHP"},
		},
		{
			name:       "express.js",
			headers:    map[string]string{"X-Powered-By": "Express"},
			body:       "",
			shouldFind: []string{"Express.js"},
		},
		{
			name:       "wordpress in body",
			headers:    map[string]string{},
			body:       "<link rel='stylesheet' href='/wp-content/themes/style.css'>",
			shouldFind: []string{"WordPress"},
		},
		{
			name:       "react in body",
			headers:    map[string]string{},
			body:       "<div id='root'></div><script>window.__REACT_DEVTOOLS</script>",
			shouldFind: []string{"React"},
		},
		{
			name:       "angular in body",
			headers:    map[string]string{},
			body:       "<div ng-app='myApp' ng-controller='myCtrl'></div>",
			shouldFind: []string{"AngularJS"},
		},
		{
			name:       "jquery in body",
			headers:    map[string]string{},
			body:       "<script src='jquery.min.js'></script>",
			shouldFind: []string{"jQuery"},
		},
		{
			name:       "bootstrap in body",
			headers:    map[string]string{},
			body:       "<link href='bootstrap.css'><div class='container'>",
			shouldFind: []string{"Bootstrap"},
		},
		{
			name:       "cloudflare server",
			headers:    map[string]string{"Server": "cloudflare"},
			body:       "",
			shouldFind: []string{"Cloudflare"},
		},
		{
			name:       "multiple technologies",
			headers:    map[string]string{"Server": "nginx", "X-Powered-By": "PHP"},
			body:       "<script src='jquery.min.js'></script>",
			shouldFind: []string{"Nginx", "PHP", "jQuery"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			for k, v := range tt.headers {
				headers.Set(k, v)
			}

			techs := detectTechnologies(headers, tt.body)

			for _, expected := range tt.shouldFind {
				assert.Contains(t, techs, expected, "Should detect %s", expected)
			}
		})
	}
}

func TestHTTPProber_ResultsToFindings_Basic(t *testing.T) {
	prober := NewHTTPProber(newTestLogger(), nil)

	results := []HTTPProbeResult{
		{
			URL:          "https://example.com:443",
			StatusCode:   200,
			Title:        "Example Domain",
			Server:       "nginx",
			Technologies: []string{"Nginx", "PHP"},
			Headers:      map[string]string{"Server": "nginx"},
			ResponseTime: 100 * time.Millisecond,
		},
	}

	assetID := uuid.New()
	scanID := uuid.New()
	orgID := uuid.New()

	findings := prober.ResultsToFindings("example.com", results, assetID, scanID, orgID)

	require.NotEmpty(t, findings)
	assert.Equal(t, "http_service", findings[0].Type)
	assert.Equal(t, "web", findings[0].Category)
	assert.Equal(t, assetID, findings[0].AssetID)
}

func TestHTTPProber_ResultsToFindings_ExpiredCert(t *testing.T) {
	prober := NewHTTPProber(newTestLogger(), nil)

	results := []HTTPProbeResult{
		{
			URL:        "https://example.com:443",
			StatusCode: 200,
			TLSInfo: &TLSInfo{
				Version:   "TLS 1.2",
				IsExpired: true,
				NotAfter:  time.Now().Add(-24 * time.Hour),
				Subject:   "example.com",
				Issuer:    "Let's Encrypt",
			},
		},
	}

	findings := prober.ResultsToFindings("example.com", results, uuid.New(), uuid.New(), uuid.New())

	// Should have service finding + expired cert finding
	require.GreaterOrEqual(t, len(findings), 2)

	var hasExpiredCert bool
	for _, f := range findings {
		if f.Type == "expired_certificate" {
			hasExpiredCert = true
			assert.Equal(t, "high", string(f.Severity))
		}
	}
	assert.True(t, hasExpiredCert, "Should have expired certificate finding")
}

func TestHTTPProber_ResultsToFindings_SelfSignedCert(t *testing.T) {
	prober := NewHTTPProber(newTestLogger(), nil)

	results := []HTTPProbeResult{
		{
			URL:        "https://example.com:443",
			StatusCode: 200,
			TLSInfo: &TLSInfo{
				Version:      "TLS 1.2",
				IsSelfsigned: true,
				Subject:      "localhost",
				Issuer:       "localhost",
			},
		},
	}

	findings := prober.ResultsToFindings("example.com", results, uuid.New(), uuid.New(), uuid.New())

	var hasSelfSigned bool
	for _, f := range findings {
		if f.Type == "self_signed_certificate" {
			hasSelfSigned = true
			assert.Equal(t, "medium", string(f.Severity))
		}
	}
	assert.True(t, hasSelfSigned, "Should have self-signed certificate finding")
}

func TestHTTPProber_ResultsToFindings_WeakTLS(t *testing.T) {
	prober := NewHTTPProber(newTestLogger(), nil)

	for _, version := range []string{"TLS 1.0", "TLS 1.1"} {
		t.Run(version, func(t *testing.T) {
			results := []HTTPProbeResult{
				{
					URL:        "https://example.com:443",
					StatusCode: 200,
					TLSInfo: &TLSInfo{
						Version: version,
					},
				},
			}

			findings := prober.ResultsToFindings("example.com", results, uuid.New(), uuid.New(), uuid.New())

			var hasWeakTLS bool
			for _, f := range findings {
				if f.Type == "weak_tls_version" {
					hasWeakTLS = true
					assert.Equal(t, "medium", string(f.Severity))
				}
			}
			assert.True(t, hasWeakTLS, "Should have weak TLS finding for %s", version)
		})
	}
}

func TestHTTPProber_ResultsToFindings_ExpiringCert(t *testing.T) {
	prober := NewHTTPProber(newTestLogger(), nil)

	results := []HTTPProbeResult{
		{
			URL:        "https://example.com:443",
			StatusCode: 200,
			TLSInfo: &TLSInfo{
				Version:         "TLS 1.2",
				DaysUntilExpiry: 15,
				NotAfter:        time.Now().Add(15 * 24 * time.Hour),
			},
		},
	}

	findings := prober.ResultsToFindings("example.com", results, uuid.New(), uuid.New(), uuid.New())

	var hasExpiring bool
	for _, f := range findings {
		if f.Type == "expiring_certificate" {
			hasExpiring = true
			assert.Equal(t, "low", string(f.Severity))
		}
	}
	assert.True(t, hasExpiring, "Should have expiring certificate finding")
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0, "Unknown (0x0000)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tlsVersionString(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHTTPProber_DefaultConfig(t *testing.T) {
	prober := NewHTTPProber(newTestLogger(), nil)
	assert.NotNil(t, prober)
	assert.Equal(t, 50, prober.concurrency)
}

func TestHTTPProber_CustomConfig(t *testing.T) {
	prober := NewHTTPProber(newTestLogger(), &HTTPProbeConfig{
		Timeout:     30 * time.Second,
		Concurrency: 100,
	})
	assert.Equal(t, 100, prober.concurrency)
}

func TestHTTPProber_GetProtocolsForPort(t *testing.T) {
	prober := NewHTTPProber(newTestLogger(), nil)

	tests := []struct {
		port     int
		expected []string
	}{
		{443, []string{"https"}},
		{8443, []string{"https"}},
		{80, []string{"http"}},
		{8080, []string{"http"}},
		{3000, []string{"http"}},
		{9999, []string{"https", "http"}}, // Unknown port tries both
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.port)), func(t *testing.T) {
			protocols := prober.getProtocolsForPort(tt.port)
			assert.Equal(t, tt.expected, protocols)
		})
	}
}

func TestGenerateHTTPFindingHash(t *testing.T) {
	assetID := uuid.New()

	hash1 := generateHTTPFindingHash(assetID, "https://example.com", "http_service")
	hash2 := generateHTTPFindingHash(assetID, "https://example.com", "http_service")
	hash3 := generateHTTPFindingHash(assetID, "https://other.com", "http_service")

	// Same input = same hash
	assert.Equal(t, hash1, hash2)
	// Different input = different hash
	assert.NotEqual(t, hash1, hash3)
	// Hash is 64 chars (SHA256 hex)
	assert.Len(t, hash1, 64)
}
