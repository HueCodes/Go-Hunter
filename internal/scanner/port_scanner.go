package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/database/models"
)

// Common port to service mappings
var commonServices = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	443:   "https",
	445:   "microsoft-ds",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5900:  "vnc",
	6379:  "redis",
	8080:  "http-proxy",
	8443:  "https-alt",
	9200:  "elasticsearch",
	27017: "mongodb",
}

// PortScanner performs TCP port scanning
type PortScanner struct {
	logger      *slog.Logger
	timeout     time.Duration
	concurrency int
}

// PortScanConfig configures the port scanner behavior
type PortScanConfig struct {
	Timeout     time.Duration
	Concurrency int
}

// PortScanResult represents a single open port finding
type PortScanResult struct {
	Port     int
	Protocol string
	Service  string
	Banner   string
	Open     bool
}

// NewPortScanner creates a new port scanner instance
func NewPortScanner(logger *slog.Logger, cfg *PortScanConfig) *PortScanner {
	timeout := 3 * time.Second
	concurrency := 100

	if cfg != nil {
		if cfg.Timeout > 0 {
			timeout = cfg.Timeout
		}
		if cfg.Concurrency > 0 {
			concurrency = cfg.Concurrency
		}
	}

	return &PortScanner{
		logger:      logger,
		timeout:     timeout,
		concurrency: concurrency,
	}
}

// ParsePorts parses a port specification string into a list of ports
// Supports formats: "80", "80,443,8080", "1-1000", "80,443,1000-2000"
func ParsePorts(spec string) ([]int, error) {
	if spec == "" {
		// Default to common ports
		return []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
			993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}, nil
	}

	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			// Range: "1-1000"
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", rangeParts[1])
			}

			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}

			for p := start; p <= end; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			// Single port
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", part)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range: %d", port)
			}
			if !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
		}
	}

	return ports, nil
}

// ScanHost scans a single host for open ports
func (s *PortScanner) ScanHost(ctx context.Context, host string, ports []int) []PortScanResult {
	var results []PortScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore for concurrency control
	sem := make(chan struct{}, s.concurrency)

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return results
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			result := s.scanPort(ctx, host, p)
			if result.Open {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return results
}

// scanPort checks if a single port is open
func (s *PortScanner) scanPort(ctx context.Context, host string, port int) PortScanResult {
	result := PortScanResult{
		Port:     port,
		Protocol: "tcp",
		Open:     false,
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := &net.Dialer{
		Timeout: s.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return result
	}
	defer conn.Close()

	result.Open = true

	// Try to identify the service
	if service, ok := commonServices[port]; ok {
		result.Service = service
	}

	// Try banner grabbing with short timeout
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err == nil {
		banner := make([]byte, 1024)
		n, err := conn.Read(banner)
		if err == nil && n > 0 {
			result.Banner = sanitizeBanner(string(banner[:n]))
			// Try to detect service from banner
			if result.Service == "" {
				result.Service = detectServiceFromBanner(result.Banner)
			}
		}
	}

	return result
}

// sanitizeBanner cleans up banner text for storage
func sanitizeBanner(banner string) string {
	// Remove null bytes and control characters
	var cleaned strings.Builder
	for _, r := range banner {
		if r >= 32 && r < 127 || r == '\n' || r == '\r' || r == '\t' {
			cleaned.WriteRune(r)
		}
	}
	result := strings.TrimSpace(cleaned.String())
	// Limit length
	if len(result) > 500 {
		result = result[:500]
	}
	return result
}

// detectServiceFromBanner attempts to identify service from banner
func detectServiceFromBanner(banner string) string {
	bannerLower := strings.ToLower(banner)

	switch {
	case strings.Contains(bannerLower, "ssh"):
		return "ssh"
	case strings.Contains(bannerLower, "ftp"):
		return "ftp"
	case strings.Contains(bannerLower, "smtp") || strings.Contains(bannerLower, "postfix") || strings.Contains(bannerLower, "sendmail"):
		return "smtp"
	case strings.Contains(bannerLower, "http"):
		return "http"
	case strings.Contains(bannerLower, "mysql"):
		return "mysql"
	case strings.Contains(bannerLower, "postgresql"):
		return "postgresql"
	case strings.Contains(bannerLower, "redis"):
		return "redis"
	case strings.Contains(bannerLower, "mongodb"):
		return "mongodb"
	case strings.Contains(bannerLower, "elasticsearch"):
		return "elasticsearch"
	default:
		return ""
	}
}

// ResultsToFindings converts port scan results to Finding models
func (s *PortScanner) ResultsToFindings(host string, results []PortScanResult, assetID, scanID, orgID uuid.UUID) []models.Finding {
	var findings []models.Finding
	now := time.Now().Unix()

	for _, result := range results {
		if !result.Open {
			continue
		}

		severity := s.determinePortSeverity(result.Port, result.Service)

		evidence := map[string]interface{}{
			"host":     host,
			"port":     result.Port,
			"protocol": result.Protocol,
			"service":  result.Service,
		}
		if result.Banner != "" {
			evidence["banner"] = result.Banner
		}
		evidenceJSON, _ := json.Marshal(evidence)

		references := []string{
			"https://nmap.org/book/nmap-services.html",
		}
		referencesJSON, _ := json.Marshal(references)

		// Generate hash for deduplication
		hash := generatePortFindingHash(assetID, result.Port, result.Protocol)

		title := fmt.Sprintf("Open Port %d/%s", result.Port, result.Protocol)
		if result.Service != "" {
			title = fmt.Sprintf("Open Port %d/%s (%s)", result.Port, result.Protocol, result.Service)
		}

		finding := models.Finding{
			OrganizationID: orgID,
			AssetID:        assetID,
			ScanID:         scanID,
			Title:          title,
			Description:    s.generatePortDescription(host, result),
			Severity:       severity,
			Status:         models.FindingStatusOpen,
			Type:           "open_port",
			Category:       "network",
			Evidence:       string(evidenceJSON),
			RawData:        string(evidenceJSON),
			Port:           result.Port,
			Protocol:       result.Protocol,
			Service:        result.Service,
			Banner:         result.Banner,
			Remediation:    s.generatePortRemediation(result),
			References:     string(referencesJSON),
			FirstSeenAt:    now,
			LastSeenAt:     now,
			Hash:           hash,
		}

		findings = append(findings, finding)
	}

	return findings
}

// determinePortSeverity assigns severity based on port and service
func (s *PortScanner) determinePortSeverity(port int, service string) models.Severity {
	// High-risk services
	highRisk := map[string]bool{
		"telnet": true, "ftp": true, "rpcbind": true,
		"netbios-ssn": true, "msrpc": true, "vnc": true,
	}

	// Medium-risk (databases, management interfaces)
	mediumRisk := map[string]bool{
		"mysql": true, "postgresql": true, "mssql": true, "oracle": true,
		"mongodb": true, "redis": true, "elasticsearch": true, "rdp": true,
	}

	if highRisk[service] {
		return models.SeverityHigh
	}
	if mediumRisk[service] {
		return models.SeverityMedium
	}

	// Default based on port ranges
	if port < 1024 {
		return models.SeverityLow
	}
	return models.SeverityInfo
}

// generatePortDescription creates a human-readable description
func (s *PortScanner) generatePortDescription(host string, result PortScanResult) string {
	var desc strings.Builder

	desc.WriteString(fmt.Sprintf("Port %d/%s is open on %s", result.Port, result.Protocol, host))

	if result.Service != "" {
		desc.WriteString(fmt.Sprintf(", identified as %s service", result.Service))
	}

	desc.WriteString(". ")

	if result.Banner != "" {
		desc.WriteString(fmt.Sprintf("Banner: %s", result.Banner))
	}

	return desc.String()
}

// generatePortRemediation creates remediation advice
func (s *PortScanner) generatePortRemediation(result PortScanResult) string {
	remediations := map[string]string{
		"telnet": "Disable Telnet and use SSH for secure remote access. Telnet transmits data in plaintext.",
		"ftp":    "Consider using SFTP or FTPS instead of FTP. If FTP is required, restrict access to specific IP addresses.",
		"rdp":    "Restrict RDP access using firewall rules. Enable Network Level Authentication (NLA). Consider using a VPN.",
		"ssh":    "Ensure SSH is using key-based authentication. Disable root login. Keep SSH updated.",
		"mysql":  "Restrict database access to application servers only. Do not expose databases to the internet.",
		"postgresql": "Restrict database access to application servers only. Use strong authentication.",
		"redis":  "Enable authentication for Redis. Bind to localhost or use firewall rules to restrict access.",
		"mongodb": "Enable authentication. Restrict network access. Bind to localhost or trusted networks.",
		"vnc":    "VNC is inherently insecure. Use SSH tunneling or a VPN for remote access.",
	}

	if advice, ok := remediations[result.Service]; ok {
		return advice
	}

	return "Review whether this port needs to be publicly accessible. Restrict access using firewall rules if not required."
}

// generatePortFindingHash creates a deterministic hash for port findings
func generatePortFindingHash(assetID uuid.UUID, port int, protocol string) string {
	data := fmt.Sprintf("%s:open_port:%d:%s", assetID.String(), port, protocol)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
