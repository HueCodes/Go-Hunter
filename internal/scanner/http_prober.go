package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/database/models"
)

// HTTPProber performs HTTP/HTTPS service detection
type HTTPProber struct {
	logger      *slog.Logger
	client      *http.Client
	concurrency int
}

// HTTPProbeConfig configures the HTTP prober behavior
type HTTPProbeConfig struct {
	Timeout        time.Duration
	Concurrency    int
	FollowRedirect bool
	MaxBodySize    int64
}

// HTTPProbeResult represents a single HTTP probe result
type HTTPProbeResult struct {
	URL           string
	StatusCode    int
	ContentLength int64
	Title         string
	Server        string
	Technologies  []string
	Headers       map[string]string
	TLSInfo       *TLSInfo
	RedirectURL   string
	ResponseTime  time.Duration
}

// TLSInfo contains TLS certificate information
type TLSInfo struct {
	Version            string
	CipherSuite        string
	Subject            string
	Issuer             string
	NotBefore          time.Time
	NotAfter           time.Time
	DNSNames           []string
	IsExpired          bool
	DaysUntilExpiry    int
	IsSelfsigned       bool
	CertificateChain   int
}

// NewHTTPProber creates a new HTTP prober instance
func NewHTTPProber(logger *slog.Logger, cfg *HTTPProbeConfig) *HTTPProber {
	timeout := 10 * time.Second
	concurrency := 50
	followRedirect := true
	maxBodySize := int64(1024 * 1024) // 1MB

	if cfg != nil {
		if cfg.Timeout > 0 {
			timeout = cfg.Timeout
		}
		if cfg.Concurrency > 0 {
			concurrency = cfg.Concurrency
		}
		followRedirect = cfg.FollowRedirect
		// MaxBodySize is available in config but body size is limited inline
		_ = maxBodySize
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // We want to probe even invalid certs
		},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		MaxIdleConnsPerHost: 10,
	}

	var checkRedirect func(req *http.Request, via []*http.Request) error
	if !followRedirect {
		checkRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	client := &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: checkRedirect,
	}

	return &HTTPProber{
		logger:      logger,
		client:      client,
		concurrency: concurrency,
	}
}

// ProbeHost probes a host on specified ports for HTTP/HTTPS services
func (p *HTTPProber) ProbeHost(ctx context.Context, host string, ports []int) []HTTPProbeResult {
	var results []HTTPProbeResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, p.concurrency)

	for _, port := range ports {
		// Determine protocols to try based on port
		protocols := p.getProtocolsForPort(port)

		for _, protocol := range protocols {
			select {
			case <-ctx.Done():
				return results
			case sem <- struct{}{}:
			}

			wg.Add(1)
			go func(proto string, pt int) {
				defer wg.Done()
				defer func() { <-sem }()

				url := fmt.Sprintf("%s://%s:%d", proto, host, pt)
				result := p.probeURL(ctx, url)
				if result != nil {
					mu.Lock()
					results = append(results, *result)
					mu.Unlock()
				}
			}(protocol, port)
		}
	}

	wg.Wait()
	return results
}

// getProtocolsForPort returns protocols to try for a given port
func (p *HTTPProber) getProtocolsForPort(port int) []string {
	switch port {
	case 443, 8443, 9443:
		return []string{"https"}
	case 80, 8080, 8000, 3000, 5000:
		return []string{"http"}
	default:
		// For other ports, try both
		return []string{"https", "http"}
	}
}

// probeURL probes a single URL
func (p *HTTPProber) probeURL(ctx context.Context, url string) *HTTPProbeResult {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}

	// Set common headers
	req.Header.Set("User-Agent", "Go-Hunter/1.0 (Security Scanner)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "close")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	result := &HTTPProbeResult{
		URL:          url,
		StatusCode:   resp.StatusCode,
		ResponseTime: time.Since(start),
		Headers:      make(map[string]string),
	}

	// Extract headers
	for key := range resp.Header {
		result.Headers[key] = resp.Header.Get(key)
	}

	// Get server header
	if server := resp.Header.Get("Server"); server != "" {
		result.Server = server
	}

	// Get content length
	result.ContentLength = resp.ContentLength

	// Get redirect location
	if location := resp.Header.Get("Location"); location != "" {
		result.RedirectURL = location
	}

	// Read body for title and technology detection
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // Limit to 64KB for title extraction
	if err == nil && len(body) > 0 {
		result.Title = extractTitle(string(body))
		result.Technologies = detectTechnologies(resp.Header, string(body))
	}

	// Extract TLS info if HTTPS
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		result.TLSInfo = extractTLSInfo(resp.TLS)
	}

	return result
}

// extractTitle extracts the page title from HTML
func extractTitle(body string) string {
	// Simple regex to extract title
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		// Limit length
		if len(title) > 200 {
			title = title[:200]
		}
		return title
	}
	return ""
}

// detectTechnologies attempts to identify technologies from headers and body
func detectTechnologies(headers http.Header, body string) []string {
	var techs []string
	seen := make(map[string]bool)

	addTech := func(tech string) {
		if !seen[tech] {
			techs = append(techs, tech)
			seen[tech] = true
		}
	}

	// Check headers
	server := strings.ToLower(headers.Get("Server"))
	powered := strings.ToLower(headers.Get("X-Powered-By"))
	generator := strings.ToLower(headers.Get("X-Generator"))

	// Server detection
	switch {
	case strings.Contains(server, "nginx"):
		addTech("Nginx")
	case strings.Contains(server, "apache"):
		addTech("Apache")
	case strings.Contains(server, "iis"):
		addTech("IIS")
	case strings.Contains(server, "cloudflare"):
		addTech("Cloudflare")
	case strings.Contains(server, "openresty"):
		addTech("OpenResty")
	}

	// X-Powered-By detection
	switch {
	case strings.Contains(powered, "php"):
		addTech("PHP")
	case strings.Contains(powered, "asp.net"):
		addTech("ASP.NET")
	case strings.Contains(powered, "express"):
		addTech("Express.js")
	case strings.Contains(powered, "next.js"):
		addTech("Next.js")
	}

	// Generator detection
	if strings.Contains(generator, "wordpress") || strings.Contains(body, "wp-content") {
		addTech("WordPress")
	}

	// Body-based detection
	bodyLower := strings.ToLower(body)

	if strings.Contains(bodyLower, "react") || strings.Contains(body, "__REACT_DEVTOOLS") {
		addTech("React")
	}
	if strings.Contains(body, "ng-app") || strings.Contains(body, "ng-controller") {
		addTech("AngularJS")
	}
	if strings.Contains(body, "vue") && strings.Contains(body, "__VUE__") {
		addTech("Vue.js")
	}
	if strings.Contains(bodyLower, "jquery") {
		addTech("jQuery")
	}
	if strings.Contains(body, "drupal") {
		addTech("Drupal")
	}
	if strings.Contains(body, "joomla") {
		addTech("Joomla")
	}
	if strings.Contains(bodyLower, "bootstrap") {
		addTech("Bootstrap")
	}
	if strings.Contains(bodyLower, "tailwind") {
		addTech("Tailwind CSS")
	}

	return techs
}

// extractTLSInfo extracts TLS certificate information
func extractTLSInfo(state *tls.ConnectionState) *TLSInfo {
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	cert := state.PeerCertificates[0]
	now := time.Now()

	info := &TLSInfo{
		Version:          tlsVersionString(state.Version),
		CipherSuite:      tls.CipherSuiteName(state.CipherSuite),
		Subject:          cert.Subject.CommonName,
		Issuer:           cert.Issuer.CommonName,
		NotBefore:        cert.NotBefore,
		NotAfter:         cert.NotAfter,
		DNSNames:         cert.DNSNames,
		IsExpired:        now.After(cert.NotAfter),
		CertificateChain: len(state.PeerCertificates),
	}

	// Calculate days until expiry
	if !info.IsExpired {
		info.DaysUntilExpiry = int(cert.NotAfter.Sub(now).Hours() / 24)
	}

	// Check if self-signed
	info.IsSelfsigned = cert.Issuer.CommonName == cert.Subject.CommonName

	return info
}

// tlsVersionString converts TLS version to string
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// ResultsToFindings converts HTTP probe results to Finding models
func (p *HTTPProber) ResultsToFindings(host string, results []HTTPProbeResult, assetID, scanID, orgID uuid.UUID) []models.Finding {
	var findings []models.Finding
	now := time.Now().Unix()

	for _, result := range results {
		// Create a finding for each detected service
		finding := p.createHTTPServiceFinding(host, result, assetID, scanID, orgID, now)
		findings = append(findings, finding)

		// Create additional findings for security issues
		if result.TLSInfo != nil {
			if result.TLSInfo.IsExpired {
				findings = append(findings, p.createExpiredCertFinding(host, result, assetID, scanID, orgID, now))
			}
			if result.TLSInfo.IsSelfsigned {
				findings = append(findings, p.createSelfSignedCertFinding(host, result, assetID, scanID, orgID, now))
			}
			if result.TLSInfo.Version == "TLS 1.0" || result.TLSInfo.Version == "TLS 1.1" {
				findings = append(findings, p.createWeakTLSFinding(host, result, assetID, scanID, orgID, now))
			}
			if result.TLSInfo.DaysUntilExpiry > 0 && result.TLSInfo.DaysUntilExpiry < 30 {
				findings = append(findings, p.createExpiringCertFinding(host, result, assetID, scanID, orgID, now))
			}
		}
	}

	return findings
}

func (p *HTTPProber) createHTTPServiceFinding(host string, result HTTPProbeResult, assetID, scanID, orgID uuid.UUID, now int64) models.Finding {
	evidence := map[string]interface{}{
		"url":           result.URL,
		"status_code":   result.StatusCode,
		"title":         result.Title,
		"server":        result.Server,
		"technologies":  result.Technologies,
		"response_time": result.ResponseTime.Milliseconds(),
	}
	if result.TLSInfo != nil {
		evidence["tls_version"] = result.TLSInfo.Version
		evidence["tls_issuer"] = result.TLSInfo.Issuer
	}
	evidenceJSON, _ := json.Marshal(evidence)

	headersJSON, _ := json.Marshal(result.Headers)

	title := fmt.Sprintf("HTTP Service on %s", result.URL)
	if result.Title != "" {
		title = fmt.Sprintf("HTTP Service: %s", result.Title)
	}

	return models.Finding{
		OrganizationID: orgID,
		AssetID:        assetID,
		ScanID:         scanID,
		Title:          title,
		Description:    fmt.Sprintf("HTTP service detected at %s. Status: %d, Server: %s, Technologies: %v", result.URL, result.StatusCode, result.Server, result.Technologies),
		Severity:       models.SeverityInfo,
		Status:         models.FindingStatusOpen,
		Type:           "http_service",
		Category:       "web",
		Evidence:       string(evidenceJSON),
		RawData:        string(headersJSON),
		Service:        "http",
		Remediation:    "Review exposed HTTP services and ensure they are intentionally public. Implement proper access controls if needed.",
		FirstSeenAt:    now,
		LastSeenAt:     now,
		Hash:           generateHTTPFindingHash(assetID, result.URL, "http_service"),
	}
}

func (p *HTTPProber) createExpiredCertFinding(host string, result HTTPProbeResult, assetID, scanID, orgID uuid.UUID, now int64) models.Finding {
	evidence := map[string]interface{}{
		"url":        result.URL,
		"expired_on": result.TLSInfo.NotAfter,
		"subject":    result.TLSInfo.Subject,
		"issuer":     result.TLSInfo.Issuer,
	}
	evidenceJSON, _ := json.Marshal(evidence)

	return models.Finding{
		OrganizationID: orgID,
		AssetID:        assetID,
		ScanID:         scanID,
		Title:          fmt.Sprintf("Expired SSL Certificate on %s", host),
		Description:    fmt.Sprintf("The SSL certificate for %s expired on %s. Expired certificates cause browser warnings and may indicate abandoned or misconfigured services.", result.URL, result.TLSInfo.NotAfter.Format("2006-01-02")),
		Severity:       models.SeverityHigh,
		Status:         models.FindingStatusOpen,
		Type:           "expired_certificate",
		Category:       "web",
		Evidence:       string(evidenceJSON),
		Service:        "https",
		Remediation:    "Renew the SSL certificate immediately. Consider using automated certificate management like Let's Encrypt with auto-renewal.",
		References:     `["https://letsencrypt.org/docs/"]`,
		FirstSeenAt:    now,
		LastSeenAt:     now,
		Hash:           generateHTTPFindingHash(assetID, result.URL, "expired_certificate"),
	}
}

func (p *HTTPProber) createSelfSignedCertFinding(host string, result HTTPProbeResult, assetID, scanID, orgID uuid.UUID, now int64) models.Finding {
	evidence := map[string]interface{}{
		"url":     result.URL,
		"subject": result.TLSInfo.Subject,
		"issuer":  result.TLSInfo.Issuer,
	}
	evidenceJSON, _ := json.Marshal(evidence)

	return models.Finding{
		OrganizationID: orgID,
		AssetID:        assetID,
		ScanID:         scanID,
		Title:          fmt.Sprintf("Self-Signed SSL Certificate on %s", host),
		Description:    fmt.Sprintf("The SSL certificate for %s is self-signed. Self-signed certificates are not trusted by browsers and may indicate a development or misconfigured service.", result.URL),
		Severity:       models.SeverityMedium,
		Status:         models.FindingStatusOpen,
		Type:           "self_signed_certificate",
		Category:       "web",
		Evidence:       string(evidenceJSON),
		Service:        "https",
		Remediation:    "Replace the self-signed certificate with one issued by a trusted Certificate Authority. Consider using Let's Encrypt for free certificates.",
		References:     `["https://letsencrypt.org/"]`,
		FirstSeenAt:    now,
		LastSeenAt:     now,
		Hash:           generateHTTPFindingHash(assetID, result.URL, "self_signed_certificate"),
	}
}

func (p *HTTPProber) createWeakTLSFinding(host string, result HTTPProbeResult, assetID, scanID, orgID uuid.UUID, now int64) models.Finding {
	evidence := map[string]interface{}{
		"url":         result.URL,
		"tls_version": result.TLSInfo.Version,
		"cipher":      result.TLSInfo.CipherSuite,
	}
	evidenceJSON, _ := json.Marshal(evidence)

	return models.Finding{
		OrganizationID: orgID,
		AssetID:        assetID,
		ScanID:         scanID,
		Title:          fmt.Sprintf("Weak TLS Version (%s) on %s", result.TLSInfo.Version, host),
		Description:    fmt.Sprintf("The server at %s supports %s, which has known vulnerabilities. TLS 1.0 and 1.1 are deprecated and should be disabled.", result.URL, result.TLSInfo.Version),
		Severity:       models.SeverityMedium,
		Status:         models.FindingStatusOpen,
		Type:           "weak_tls_version",
		Category:       "web",
		Evidence:       string(evidenceJSON),
		Service:        "https",
		Remediation:    "Disable TLS 1.0 and TLS 1.1 on the server. Configure the server to only support TLS 1.2 and TLS 1.3.",
		References:     `["https://www.ssllabs.com/ssl-pulse/", "https://tools.ietf.org/html/rfc8996"]`,
		FirstSeenAt:    now,
		LastSeenAt:     now,
		Hash:           generateHTTPFindingHash(assetID, result.URL, "weak_tls_version"),
	}
}

func (p *HTTPProber) createExpiringCertFinding(host string, result HTTPProbeResult, assetID, scanID, orgID uuid.UUID, now int64) models.Finding {
	evidence := map[string]interface{}{
		"url":               result.URL,
		"expires_on":        result.TLSInfo.NotAfter,
		"days_until_expiry": result.TLSInfo.DaysUntilExpiry,
		"subject":           result.TLSInfo.Subject,
	}
	evidenceJSON, _ := json.Marshal(evidence)

	return models.Finding{
		OrganizationID: orgID,
		AssetID:        assetID,
		ScanID:         scanID,
		Title:          fmt.Sprintf("SSL Certificate Expiring Soon on %s (%d days)", host, result.TLSInfo.DaysUntilExpiry),
		Description:    fmt.Sprintf("The SSL certificate for %s will expire in %d days on %s. Plan certificate renewal to avoid service disruption.", result.URL, result.TLSInfo.DaysUntilExpiry, result.TLSInfo.NotAfter.Format("2006-01-02")),
		Severity:       models.SeverityLow,
		Status:         models.FindingStatusOpen,
		Type:           "expiring_certificate",
		Category:       "web",
		Evidence:       string(evidenceJSON),
		Service:        "https",
		Remediation:    "Renew the SSL certificate before expiration. Consider implementing automated certificate renewal.",
		FirstSeenAt:    now,
		LastSeenAt:     now,
		Hash:           generateHTTPFindingHash(assetID, result.URL, "expiring_certificate"),
	}
}

func generateHTTPFindingHash(assetID uuid.UUID, url, findingType string) string {
	data := fmt.Sprintf("%s:%s:%s", assetID.String(), findingType, url)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
