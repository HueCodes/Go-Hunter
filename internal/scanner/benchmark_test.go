package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/database/models"
)

func newBenchmarkLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// BenchmarkParsePorts benchmarks port specification parsing
func BenchmarkParsePorts(b *testing.B) {
	b.Run("SinglePort", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ParsePorts("80")
		}
	})

	b.Run("MultiplePorts", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ParsePorts("80,443,8080,22,3306,5432")
		}
	})

	b.Run("PortRange", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ParsePorts("1-1000")
		}
	})

	b.Run("MixedFormat", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ParsePorts("80,443,1000-2000,3306,5000-6000")
		}
	})

	b.Run("DefaultPorts", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ParsePorts("")
		}
	})

	b.Run("LargeRange", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ParsePorts("1-65535")
		}
	})
}

// BenchmarkPortScanResultsToFindings benchmarks conversion of scan results to findings
func BenchmarkPortScanResultsToFindings(b *testing.B) {
	scanner := NewPortScanner(newBenchmarkLogger(), nil)
	assetID := uuid.New()
	scanID := uuid.New()
	orgID := uuid.New()

	b.Run("SingleResult", func(b *testing.B) {
		results := []PortScanResult{
			{Port: 22, Protocol: "tcp", Service: "ssh", Open: true, Banner: "SSH-2.0-OpenSSH_8.0"},
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = scanner.ResultsToFindings("192.168.1.1", results, assetID, scanID, orgID)
		}
	})

	b.Run("TenResults", func(b *testing.B) {
		results := generatePortScanResults(10)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = scanner.ResultsToFindings("192.168.1.1", results, assetID, scanID, orgID)
		}
	})

	b.Run("FiftyResults", func(b *testing.B) {
		results := generatePortScanResults(50)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = scanner.ResultsToFindings("192.168.1.1", results, assetID, scanID, orgID)
		}
	})

	b.Run("HundredResults", func(b *testing.B) {
		results := generatePortScanResults(100)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = scanner.ResultsToFindings("192.168.1.1", results, assetID, scanID, orgID)
		}
	})

	b.Run("WithBanners", func(b *testing.B) {
		results := []PortScanResult{
			{Port: 22, Protocol: "tcp", Service: "ssh", Open: true, Banner: "SSH-2.0-OpenSSH_8.0"},
			{Port: 21, Protocol: "tcp", Service: "ftp", Open: true, Banner: "220 FTP Server Ready"},
			{Port: 25, Protocol: "tcp", Service: "smtp", Open: true, Banner: "220 mail.example.com ESMTP Postfix"},
			{Port: 3306, Protocol: "tcp", Service: "mysql", Open: true, Banner: "5.7.32-0ubuntu0.18.04.1 MySQL"},
			{Port: 5432, Protocol: "tcp", Service: "postgresql", Open: true, Banner: "PostgreSQL 14.0"},
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = scanner.ResultsToFindings("192.168.1.1", results, assetID, scanID, orgID)
		}
	})
}

// BenchmarkHTTPProbeResultsToFindings benchmarks HTTP prober result conversion
func BenchmarkHTTPProbeResultsToFindings(b *testing.B) {
	prober := NewHTTPProber(newBenchmarkLogger(), nil)
	assetID := uuid.New()
	scanID := uuid.New()
	orgID := uuid.New()

	b.Run("SingleResult", func(b *testing.B) {
		results := []HTTPProbeResult{
			{
				URL:           "https://example.com",
				StatusCode:    200,
				ContentLength: 1024,
				Title:         "Example Domain",
				Server:        "nginx/1.18.0",
				Technologies:  []string{"Nginx", "PHP"},
				Headers:       map[string]string{"Content-Type": "text/html"},
				ResponseTime:  100 * time.Millisecond,
			},
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = prober.ResultsToFindings("example.com", results, assetID, scanID, orgID)
		}
	})

	b.Run("TenResults", func(b *testing.B) {
		results := generateHTTPProbeResults(10)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = prober.ResultsToFindings("example.com", results, assetID, scanID, orgID)
		}
	})

	b.Run("WithTLSInfo", func(b *testing.B) {
		results := []HTTPProbeResult{
			{
				URL:           "https://example.com",
				StatusCode:    200,
				Title:         "Example Domain",
				Server:        "nginx",
				Technologies:  []string{"Nginx", "PHP", "WordPress"},
				Headers:       map[string]string{"Content-Type": "text/html", "X-Powered-By": "PHP/7.4"},
				ResponseTime:  100 * time.Millisecond,
				TLSInfo: &TLSInfo{
					Version:         "TLS 1.2",
					CipherSuite:     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					Subject:         "example.com",
					Issuer:          "Let's Encrypt Authority X3",
					NotBefore:       time.Now().Add(-30 * 24 * time.Hour),
					NotAfter:        time.Now().Add(60 * 24 * time.Hour),
					DNSNames:        []string{"example.com", "www.example.com"},
					IsExpired:       false,
					DaysUntilExpiry: 60,
					IsSelfsigned:    false,
				},
			},
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = prober.ResultsToFindings("example.com", results, assetID, scanID, orgID)
		}
	})

	b.Run("WithExpiredCert", func(b *testing.B) {
		results := []HTTPProbeResult{
			{
				URL:          "https://example.com",
				StatusCode:   200,
				Title:        "Example Domain",
				Server:       "nginx",
				ResponseTime: 100 * time.Millisecond,
				TLSInfo: &TLSInfo{
					Version:      "TLS 1.2",
					Subject:     "example.com",
					Issuer:       "Let's Encrypt",
					NotAfter:     time.Now().Add(-24 * time.Hour),
					IsExpired:    true,
					IsSelfsigned: false,
				},
			},
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = prober.ResultsToFindings("example.com", results, assetID, scanID, orgID)
		}
	})

	b.Run("WithWeakTLS", func(b *testing.B) {
		results := []HTTPProbeResult{
			{
				URL:          "https://example.com",
				StatusCode:   200,
				Title:        "Example Domain",
				Server:       "nginx",
				ResponseTime: 100 * time.Millisecond,
				TLSInfo: &TLSInfo{
					Version:      "TLS 1.0",
					Subject:      "example.com",
					Issuer:       "DigiCert",
					NotAfter:     time.Now().Add(365 * 24 * time.Hour),
					IsExpired:    false,
					IsSelfsigned: false,
				},
			},
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = prober.ResultsToFindings("example.com", results, assetID, scanID, orgID)
		}
	})
}

// BenchmarkSanitizeBanner benchmarks banner sanitization
func BenchmarkSanitizeBanner(b *testing.B) {
	b.Run("CleanBanner", func(b *testing.B) {
		banner := "SSH-2.0-OpenSSH_8.0"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = sanitizeBanner(banner)
		}
	})

	b.Run("BannerWithNulls", func(b *testing.B) {
		banner := "SSH\x00-2.0\x00-OpenSSH\x00_8.0"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = sanitizeBanner(banner)
		}
	})

	b.Run("BannerWithControlChars", func(b *testing.B) {
		banner := "SSH\x01\x02\x03-2.0-OpenSSH\x04\x05_8.0"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = sanitizeBanner(banner)
		}
	})

	b.Run("LongBanner", func(b *testing.B) {
		// Create a banner longer than 500 chars to test truncation
		banner := ""
		for i := 0; i < 100; i++ {
			banner += "SSH-2.0-"
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = sanitizeBanner(banner)
		}
	})
}

// BenchmarkDetectServiceFromBanner benchmarks service detection from banner
func BenchmarkDetectServiceFromBanner(b *testing.B) {
	banners := []struct {
		name   string
		banner string
	}{
		{"SSH", "SSH-2.0-OpenSSH_8.0"},
		{"FTP", "220 FTP Server Ready"},
		{"SMTP", "220 mail.example.com ESMTP Postfix"},
		{"HTTP", "HTTP/1.1 200 OK"},
		{"MySQL", "5.7.32-0ubuntu0.18.04.1 MySQL"},
		{"PostgreSQL", "PostgreSQL 14.0"},
		{"Redis", "REDIS:0.1"},
		{"MongoDB", "MongoDB server"},
		{"Elasticsearch", "Elasticsearch cluster"},
		{"Unknown", "Some random banner text"},
	}

	for _, bb := range banners {
		b.Run(bb.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = detectServiceFromBanner(bb.banner)
			}
		})
	}
}

// BenchmarkExtractTitle benchmarks HTML title extraction
func BenchmarkExtractTitle(b *testing.B) {
	b.Run("SimpleTitle", func(b *testing.B) {
		html := "<html><head><title>Example Page</title></head><body></body></html>"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = extractTitle(html)
		}
	})

	b.Run("TitleWithAttributes", func(b *testing.B) {
		html := `<html><head><title lang="en" dir="ltr">Example Page with Attributes</title></head><body></body></html>`
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = extractTitle(html)
		}
	})

	b.Run("NoTitle", func(b *testing.B) {
		html := "<html><head></head><body><h1>Page Content</h1></body></html>"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = extractTitle(html)
		}
	})

	b.Run("LargeHTML", func(b *testing.B) {
		html := "<html><head><title>Example Page</title></head><body>"
		for i := 0; i < 100; i++ {
			html += "<div><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p></div>"
		}
		html += "</body></html>"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = extractTitle(html)
		}
	})
}

// BenchmarkDetectTechnologies benchmarks technology detection
func BenchmarkDetectTechnologies(b *testing.B) {
	b.Run("NginxServer", func(b *testing.B) {
		headers := http.Header{"Server": []string{"nginx/1.18.0"}}
		body := "<html><head><title>Test</title></head><body></body></html>"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = detectTechnologies(headers, body)
		}
	})

	b.Run("WordPressSite", func(b *testing.B) {
		headers := http.Header{
			"Server":       []string{"Apache"},
			"X-Powered-By": []string{"PHP/7.4"},
		}
		body := `<html><head><title>WP Site</title></head><body class="wp-content">WordPress content</body></html>`
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = detectTechnologies(headers, body)
		}
	})

	b.Run("ReactApp", func(b *testing.B) {
		headers := http.Header{"Server": []string{"cloudflare"}}
		body := `<html><head><title>React App</title></head><body><div id="root">React __REACT_DEVTOOLS content</div></body></html>`
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = detectTechnologies(headers, body)
		}
	})

	b.Run("MultipleTechnologies", func(b *testing.B) {
		headers := http.Header{
			"Server":       []string{"nginx"},
			"X-Powered-By": []string{"Express.js"},
			"X-Generator":  []string{"WordPress 5.8"},
		}
		body := `<html><head><title>Test</title></head><body>
			<script src="jquery.min.js"></script>
			<script src="react.js">__REACT_DEVTOOLS</script>
			<link rel="stylesheet" href="bootstrap.css">
			<link rel="stylesheet" href="tailwind.css">
		</body></html>`
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = detectTechnologies(headers, body)
		}
	})
}

// BenchmarkFindingHashGeneration benchmarks finding hash generation for deduplication
func BenchmarkFindingHashGeneration(b *testing.B) {
	assetID := uuid.New()

	b.Run("PortFindingHash", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = generatePortFindingHash(assetID, 22, "tcp")
		}
	})

	b.Run("HTTPFindingHash", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = generateHTTPFindingHash(assetID, "https://example.com:443", "http_service")
		}
	})

	b.Run("DirectSHA256", func(b *testing.B) {
		data := fmt.Sprintf("%s:open_port:%d:%s", assetID.String(), 22, "tcp")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hash := sha256.Sum256([]byte(data))
			_ = hex.EncodeToString(hash[:])
		}
	})
}

// BenchmarkFindingJSONSerialization benchmarks JSON serialization of findings
func BenchmarkFindingJSONSerialization(b *testing.B) {
	finding := models.Finding{
		OrganizationID: uuid.New(),
		AssetID:        uuid.New(),
		ScanID:         uuid.New(),
		Title:          "Open Port 22/tcp (ssh)",
		Description:    "Port 22/tcp is open on 192.168.1.1, identified as ssh service. Banner: SSH-2.0-OpenSSH_8.0",
		Severity:       models.SeverityLow,
		Status:         models.FindingStatusOpen,
		Type:           "open_port",
		Category:       "network",
		Evidence:       `{"host":"192.168.1.1","port":22,"protocol":"tcp","service":"ssh","banner":"SSH-2.0-OpenSSH_8.0"}`,
		Port:           22,
		Protocol:       "tcp",
		Service:        "ssh",
		Banner:         "SSH-2.0-OpenSSH_8.0",
		Remediation:    "Ensure SSH is using key-based authentication. Disable root login. Keep SSH updated.",
		References:     `["https://nmap.org/book/nmap-services.html"]`,
		FirstSeenAt:    time.Now().Unix(),
		LastSeenAt:     time.Now().Unix(),
		Hash:           "abc123def456",
	}

	b.Run("SingleFinding", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(finding)
		}
	})

	b.Run("TenFindings", func(b *testing.B) {
		findings := make([]models.Finding, 10)
		for i := 0; i < 10; i++ {
			findings[i] = finding
			findings[i].Port = 22 + i
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(findings)
		}
	})

	b.Run("HundredFindings", func(b *testing.B) {
		findings := make([]models.Finding, 100)
		for i := 0; i < 100; i++ {
			findings[i] = finding
			findings[i].Port = 22 + i
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(findings)
		}
	})
}

// BenchmarkParallelPortResultsToFindings benchmarks parallel conversion
func BenchmarkParallelPortResultsToFindings(b *testing.B) {
	scanner := NewPortScanner(newBenchmarkLogger(), nil)
	results := generatePortScanResults(20)
	scanID := uuid.New()
	orgID := uuid.New()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		assetID := uuid.New()
		for pb.Next() {
			_ = scanner.ResultsToFindings("192.168.1.1", results, assetID, scanID, orgID)
		}
	})
}

// Helper functions

func generatePortScanResults(count int) []PortScanResult {
	services := []string{"ssh", "http", "https", "ftp", "smtp", "mysql", "postgresql", "redis", "mongodb", ""}
	results := make([]PortScanResult, count)
	for i := 0; i < count; i++ {
		results[i] = PortScanResult{
			Port:     22 + i,
			Protocol: "tcp",
			Service:  services[i%len(services)],
			Open:     true,
			Banner:   fmt.Sprintf("Service banner %d", i),
		}
	}
	return results
}

func generateHTTPProbeResults(count int) []HTTPProbeResult {
	results := make([]HTTPProbeResult, count)
	for i := 0; i < count; i++ {
		results[i] = HTTPProbeResult{
			URL:           fmt.Sprintf("https://example%d.com", i),
			StatusCode:    200,
			ContentLength: int64(1024 + i*100),
			Title:         fmt.Sprintf("Example Page %d", i),
			Server:        "nginx/1.18.0",
			Technologies:  []string{"Nginx", "PHP"},
			Headers:       map[string]string{"Content-Type": "text/html"},
			ResponseTime:  time.Duration(100+i) * time.Millisecond,
		}
	}
	return results
}
