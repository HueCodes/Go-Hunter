//go:build ignore

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/auth"
	"github.com/hugh/go-hunter/internal/database"
	"github.com/hugh/go-hunter/internal/database/models"
	"github.com/hugh/go-hunter/pkg/config"
	"github.com/hugh/go-hunter/pkg/util"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
)

func main() {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	logger := util.NewLogger(cfg.Server.Env)

	db, err := database.Connect(&cfg.Database, logger)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	// Skip AutoMigrate - migrations are handled by golang-migrate
	// If you need to run migrations, use: make db-migrate

	ctx := context.Background()

	// Seed demo data
	fmt.Println("=== Seeding Demo Data ===")

	// 1. Create Demo Organization
	org, err := seedDemoOrganization(ctx, db)
	if err != nil {
		log.Fatalf("failed to seed organization: %v", err)
	}

	// 2. Create Demo User
	user, err := seedDemoUser(ctx, db, org.ID)
	if err != nil {
		log.Fatalf("failed to seed user: %v", err)
	}

	// 3. Create Sample Assets
	assets, err := seedSampleAssets(ctx, db, org.ID)
	if err != nil {
		log.Fatalf("failed to seed assets: %v", err)
	}

	// 4. Create Sample Scans
	scans, err := seedSampleScans(ctx, db, org.ID, assets)
	if err != nil {
		log.Fatalf("failed to seed scans: %v", err)
	}

	// 5. Create Sample Findings
	if err := seedSampleFindings(ctx, db, org.ID, assets, scans); err != nil {
		log.Fatalf("failed to seed findings: %v", err)
	}

	// 6. Create admin user from env (legacy behavior)
	if err := seedAdminUser(ctx, db, cfg); err != nil {
		log.Fatalf("failed to seed admin user: %v", err)
	}

	fmt.Println("\n=== Seed Complete ===")
	fmt.Printf("Demo login: demo@gohunter.dev / GoHunter2026!\n")
	fmt.Printf("Organization: %s (slug: %s)\n", org.Name, org.Slug)
	fmt.Printf("User: %s (%s)\n", user.Name, user.Email)
}

// seedDemoOrganization creates the demo organization if it doesn't exist
func seedDemoOrganization(ctx context.Context, db *gorm.DB) (*models.Organization, error) {
	fmt.Print("Creating demo organization... ")

	var org models.Organization
	err := db.WithContext(ctx).Where("slug = ?", "demo").First(&org).Error
	if err == nil {
		fmt.Println("already exists, skipping")
		return &org, nil
	}

	org = models.Organization{
		Name:        "Demo Company",
		Slug:        "demo",
		Plan:        "pro",
		MaxUsers:    50,
		MaxAssets:   1000,
		MaxScansDay: 100,
	}

	if err := db.WithContext(ctx).Create(&org).Error; err != nil {
		return nil, err
	}

	fmt.Println("done")
	fmt.Printf("  - ID: %s\n", org.ID)
	fmt.Printf("  - Name: %s\n", org.Name)
	fmt.Printf("  - Slug: %s\n", org.Slug)
	fmt.Printf("  - Plan: %s\n", org.Plan)

	return &org, nil
}

// seedDemoUser creates the demo user if it doesn't exist
func seedDemoUser(ctx context.Context, db *gorm.DB, orgID uuid.UUID) (*models.User, error) {
	fmt.Print("Creating demo user... ")

	email := "demo@gohunter.dev"
	var user models.User
	err := db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if err == nil {
		fmt.Println("already exists, skipping")
		return &user, nil
	}

	// Hash password using bcrypt
	passwordHash, err := auth.HashPassword("GoHunter2026!")
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user = models.User{
		Email:          email,
		PasswordHash:   passwordHash,
		Name:           "Demo User",
		OrganizationID: orgID,
		Role:           "owner",
		IsActive:       true,
		EmailVerified:  true,
	}

	if err := db.WithContext(ctx).Create(&user).Error; err != nil {
		return nil, err
	}

	fmt.Println("done")
	fmt.Printf("  - ID: %s\n", user.ID)
	fmt.Printf("  - Email: %s\n", user.Email)
	fmt.Printf("  - Name: %s\n", user.Name)
	fmt.Printf("  - Role: %s\n", user.Role)

	return &user, nil
}

// seedSampleAssets creates sample assets for the demo organization
func seedSampleAssets(ctx context.Context, db *gorm.DB, orgID uuid.UUID) ([]models.Asset, error) {
	fmt.Print("Creating sample assets... ")

	// Check if assets already exist for this org
	var count int64
	db.WithContext(ctx).Model(&models.Asset{}).Where("organization_id = ?", orgID).Count(&count)
	if count > 0 {
		fmt.Printf("already have %d assets, skipping\n", count)
		var assets []models.Asset
		db.WithContext(ctx).Where("organization_id = ?", orgID).Find(&assets)
		return assets, nil
	}

	now := time.Now().Unix()

	assetData := []struct {
		Type   models.AssetType
		Value  string
		Source string
	}{
		// Domains
		{models.AssetTypeDomain, "example.com", "manual"},
		{models.AssetTypeDomain, "demo-company.io", "manual"},
		{models.AssetTypeDomain, "internal.demo-company.io", "dns_enum"},

		// Subdomains
		{models.AssetTypeSubdomain, "api.example.com", "dns_enum"},
		{models.AssetTypeSubdomain, "admin.example.com", "dns_enum"},
		{models.AssetTypeSubdomain, "staging.example.com", "certificate_transparency"},
		{models.AssetTypeSubdomain, "mail.demo-company.io", "dns_enum"},
		{models.AssetTypeSubdomain, "dev.example.com", "certificate_transparency"},
		{models.AssetTypeSubdomain, "beta.example.com", "certificate_transparency"},
		{models.AssetTypeSubdomain, "cdn.example.com", "dns_enum"},
		{models.AssetTypeSubdomain, "auth.example.com", "certificate_transparency"},
		{models.AssetTypeSubdomain, "payments.example.com", "certificate_transparency"},
		{models.AssetTypeSubdomain, "blog.demo-company.io", "dns_enum"},
		{models.AssetTypeSubdomain, "docs.demo-company.io", "dns_enum"},

		// IPs
		{models.AssetTypeIP, "192.168.1.1", "aws_discovery"},
		{models.AssetTypeIP, "10.0.0.50", "aws_discovery"},
		{models.AssetTypeIP, "203.0.113.42", "manual"},
		{models.AssetTypeIP, "52.14.88.91", "aws_discovery"},
		{models.AssetTypeIP, "34.201.55.12", "aws_discovery"},
		{models.AssetTypeIP, "18.222.103.44", "aws_discovery"},

		// Cloud Buckets
		{models.AssetTypeBucket, "example-uploads", "aws_discovery"},
		{models.AssetTypeBucket, "example-backups", "aws_discovery"},
		{models.AssetTypeBucket, "demo-static-assets", "aws_discovery"},
	}

	var assets []models.Asset
	for _, data := range assetData {
		asset := models.Asset{
			OrganizationID: orgID,
			Type:           data.Type,
			Value:          data.Value,
			Source:         data.Source,
			DiscoveredAt:   now - int64(86400*7), // 7 days ago
			LastSeenAt:     now,
			IsActive:       true,
			Metadata:       "{}",
		}
		assets = append(assets, asset)
	}

	if err := db.WithContext(ctx).Create(&assets).Error; err != nil {
		return nil, err
	}

	fmt.Printf("done (%d assets)\n", len(assets))
	for _, asset := range assets {
		fmt.Printf("  - [%s] %s (source: %s)\n", asset.Type, asset.Value, asset.Source)
	}

	return assets, nil
}

// seedSampleScans creates sample scans for the demo organization
func seedSampleScans(ctx context.Context, db *gorm.DB, orgID uuid.UUID, assets []models.Asset) ([]models.Scan, error) {
	fmt.Print("Creating sample scans... ")

	// Check if scans already exist for this org
	var count int64
	db.WithContext(ctx).Model(&models.Scan{}).Where("organization_id = ?", orgID).Count(&count)
	if count > 0 {
		fmt.Printf("already have %d scans, skipping\n", count)
		var scans []models.Scan
		db.WithContext(ctx).Where("organization_id = ?", orgID).Find(&scans)
		return scans, nil
	}

	now := time.Now().Unix()

	// Get asset IDs for targeting
	var assetIDs []uuid.UUID
	for _, a := range assets {
		assetIDs = append(assetIDs, a.ID)
	}

	scans := []models.Scan{
		// Completed full scan with good stats
		{
			OrganizationID: orgID,
			Type:           models.ScanTypeFull,
			Status:         models.ScanStatusCompleted,
			TargetAssetIDs: assetIDs,
			StartedAt:      now - 7200, // 2 hours ago
			CompletedAt:    now - 3600, // 1 hour ago
			AssetsScanned:  15,
			FindingsCount:  12,
			PortsOpen:      25,
			ServicesFound:  11,
			Config:         `{"ports": "1-1000", "aggressive": false}`,
		},
		// Running port scan
		{
			OrganizationID: orgID,
			Type:           models.ScanTypePortScan,
			Status:         models.ScanStatusRunning,
			TargetAssetIDs: assetIDs[:5], // First 5 assets
			StartedAt:      now - 300,    // 5 minutes ago
			AssetsScanned:  2,
			FindingsCount:  3,
			PortsOpen:      8,
			ServicesFound:  4,
			Config:         `{"ports": "1-65535", "aggressive": true}`,
			TaskID:         "demo-task-001",
		},
		// Completed port scan with good stats
		{
			OrganizationID: orgID,
			Type:           models.ScanTypePortScan,
			Status:         models.ScanStatusCompleted,
			TargetAssetIDs: assetIDs[:10],
			StartedAt:      now - 86400,      // 1 day ago
			CompletedAt:    now - 86400 + 900, // 15 minutes later
			AssetsScanned:  10,
			FindingsCount:  8,
			PortsOpen:      18,
			ServicesFound:  9,
			Config:         `{"ports": "1-10000", "aggressive": false}`,
		},
		// Completed discovery scan
		{
			OrganizationID: orgID,
			Type:           models.ScanTypeDiscovery,
			Status:         models.ScanStatusCompleted,
			TargetAssetIDs: assetIDs[:3], // Just the domains
			StartedAt:      now - 172800,       // 2 days ago
			CompletedAt:    now - 172800 + 1800, // 30 minutes later
			AssetsScanned:  3,
			FindingsCount:  5,
			PortsOpen:      0,
			ServicesFound:  0,
			Config:         `{"enumerate_subdomains": true, "check_dns": true}`,
		},
		// Failed scan
		{
			OrganizationID: orgID,
			Type:           models.ScanTypePortScan,
			Status:         models.ScanStatusFailed,
			TargetAssetIDs: assetIDs[len(assetIDs)-3:], // Last 3 assets
			StartedAt:      now - 259200,                // 3 days ago
			CompletedAt:    now - 259200 + 120,          // 2 minutes later (failed)
			AssetsScanned:  0,
			FindingsCount:  0,
			PortsOpen:      0,
			ServicesFound:  0,
			Config:         `{"ports": "1-1000", "aggressive": true}`,
			Error:          "Connection timeout to target host",
		},
	}

	if err := db.WithContext(ctx).Create(&scans).Error; err != nil {
		return nil, err
	}

	fmt.Printf("done (%d scans)\n", len(scans))
	for _, scan := range scans {
		fmt.Printf("  - [%s] %s - %d findings\n", scan.Type, scan.Status, scan.FindingsCount)
	}

	return scans, nil
}

// seedSampleFindings creates sample findings for the demo organization
func seedSampleFindings(ctx context.Context, db *gorm.DB, orgID uuid.UUID, assets []models.Asset, scans []models.Scan) error {
	fmt.Print("Creating sample findings... ")

	// Check if findings already exist for this org
	var count int64
	db.WithContext(ctx).Model(&models.Finding{}).Where("organization_id = ?", orgID).Count(&count)
	if count > 0 {
		fmt.Printf("already have %d findings, skipping\n", count)
		return nil
	}

	now := time.Now().Unix()

	// Get the completed scan ID for associating findings
	var completedScanID uuid.UUID
	for _, s := range scans {
		if s.Status == models.ScanStatusCompleted {
			completedScanID = s.ID
			break
		}
	}

	findingsData := []struct {
		AssetIdx    int
		Title       string
		Description string
		Severity    models.Severity
		Status      models.FindingStatus
		Type        string
		Category    string
		Port        int
		Protocol    string
		Service     string
		Evidence    string
		Remediation string
	}{
		{
			AssetIdx:    0, // example.com
			Title:       "Open SSH Port",
			Description: "SSH service detected on port 22. While SSH is commonly used for secure remote access, an open SSH port increases the attack surface.",
			Severity:    models.SeverityMedium,
			Status:      models.FindingStatusOpen,
			Type:        "open_port",
			Category:    "network",
			Port:        22,
			Protocol:    "tcp",
			Service:     "ssh",
			Evidence:    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
			Remediation: "Consider restricting SSH access to specific IP ranges using firewall rules. Ensure SSH is configured with key-based authentication and disable password login.",
		},
		{
			AssetIdx:    0, // example.com
			Title:       "Outdated TLS Version Supported",
			Description: "The server supports TLS 1.0 and TLS 1.1, which are deprecated and have known vulnerabilities.",
			Severity:    models.SeverityHigh,
			Status:      models.FindingStatusOpen,
			Type:        "tls_version",
			Category:    "web",
			Port:        443,
			Protocol:    "tcp",
			Service:     "https",
			Evidence:    "Supported versions: TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3",
			Remediation: "Disable TLS 1.0 and TLS 1.1 on the server. Only allow TLS 1.2 and TLS 1.3 connections.",
		},
		{
			AssetIdx:    3, // api.example.com
			Title:       "Missing Security Headers",
			Description: "The web application is missing important security headers including X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy.",
			Severity:    models.SeverityLow,
			Status:      models.FindingStatusOpen,
			Type:        "missing_headers",
			Category:    "web",
			Port:        443,
			Protocol:    "tcp",
			Service:     "https",
			Evidence:    "Missing headers: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, Strict-Transport-Security",
			Remediation: "Add the following headers to your web server configuration: X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Content-Security-Policy: default-src 'self', Strict-Transport-Security: max-age=31536000; includeSubDomains",
		},
		{
			AssetIdx:    4, // admin.example.com
			Title:       "Exposed Admin Panel",
			Description: "An administrative interface is publicly accessible without IP restrictions.",
			Severity:    models.SeverityCritical,
			Status:      models.FindingStatusAcknowledged,
			Type:        "exposed_admin",
			Category:    "web",
			Port:        443,
			Protocol:    "tcp",
			Service:     "https",
			Evidence:    "Admin login page detected at /admin with no IP restrictions",
			Remediation: "Restrict access to the admin panel by implementing IP allowlisting, VPN requirements, or moving to an internal network.",
		},
		{
			AssetIdx:    14, // 192.168.1.1
			Title:       "MySQL Port Exposed",
			Description: "MySQL database port 3306 is accessible from the public internet.",
			Severity:    models.SeverityHigh,
			Status:      models.FindingStatusOpen,
			Type:        "open_port",
			Category:    "network",
			Port:        3306,
			Protocol:    "tcp",
			Service:     "mysql",
			Evidence:    "MySQL 8.0.32 detected, accepts connections from any source",
			Remediation: "Configure MySQL to only listen on localhost (127.0.0.1) or use firewall rules to restrict access to trusted IP addresses only.",
		},
		{
			AssetIdx:    15, // 10.0.0.50
			Title:       "Redis Without Authentication",
			Description: "Redis server is running without authentication enabled, allowing anyone with network access to read and modify data.",
			Severity:    models.SeverityCritical,
			Status:      models.FindingStatusOpen,
			Type:        "no_auth",
			Category:    "network",
			Port:        6379,
			Protocol:    "tcp",
			Service:     "redis",
			Evidence:    "Redis 7.0.5 - AUTH not required, INFO command executed successfully",
			Remediation: "Enable Redis authentication by setting a strong password with the 'requirepass' directive in redis.conf. Consider using Redis ACLs for more granular access control.",
		},
		{
			AssetIdx:    5, // staging.example.com
			Title:       "Staging Environment Publicly Accessible",
			Description: "A staging/development environment is accessible from the public internet without authentication.",
			Severity:    models.SeverityMedium,
			Status:      models.FindingStatusOpen,
			Type:        "exposed_staging",
			Category:    "web",
			Port:        443,
			Protocol:    "tcp",
			Service:     "https",
			Evidence:    "Response headers indicate staging environment: X-Environment: staging",
			Remediation: "Implement basic authentication or IP restrictions on staging environments. Consider using a VPN for developer access.",
		},
		{
			AssetIdx:    1, // demo-company.io
			Title:       "DNSSEC Not Enabled",
			Description: "Domain does not have DNSSEC enabled, which could allow DNS spoofing attacks.",
			Severity:    models.SeverityInfo,
			Status:      models.FindingStatusOpen,
			Type:        "dns_config",
			Category:    "dns",
			Evidence:    "No DNSKEY records found for demo-company.io",
			Remediation: "Enable DNSSEC for the domain through your DNS provider to protect against DNS cache poisoning and spoofing attacks.",
		},
		{
			AssetIdx:    16, // 203.0.113.42
			Title:       "FTP Service Detected",
			Description: "FTP service is running on standard port. FTP transmits credentials in plaintext.",
			Severity:    models.SeverityMedium,
			Status:      models.FindingStatusFixed,
			Type:        "insecure_service",
			Category:    "network",
			Port:        21,
			Protocol:    "tcp",
			Service:     "ftp",
			Evidence:    "vsftpd 3.0.5 detected",
			Remediation: "Replace FTP with SFTP or SCP for secure file transfers. If FTP is required, ensure it uses TLS (FTPS).",
		},
		{
			AssetIdx:    6, // mail.demo-company.io
			Title:       "SPF Record Not Configured",
			Description: "The domain does not have an SPF record configured, which could allow email spoofing.",
			Severity:    models.SeverityLow,
			Status:      models.FindingStatusOpen,
			Type:        "dns_config",
			Category:    "dns",
			Evidence:    "No SPF record found for mail.demo-company.io",
			Remediation: "Add an SPF record to the domain's DNS configuration. Example: v=spf1 mx ip4:YOUR_MAIL_SERVER_IP -all",
		},
		// New findings for portfolio screenshots
		{
			AssetIdx:    10, // auth.example.com
			Title:       "SSL Certificate Expiring in 30 Days",
			Description: "The SSL certificate for this domain will expire within the next 30 days. Failure to renew will cause service disruption and browser warnings.",
			Severity:    models.SeverityMedium,
			Status:      models.FindingStatusOpen,
			Type:        "ssl_expiry",
			Category:    "web",
			Port:        443,
			Protocol:    "tcp",
			Service:     "https",
			Evidence:    "Certificate expires: 2026-02-28. Issuer: Let's Encrypt Authority X3. Days remaining: 32",
			Remediation: "Renew the SSL certificate before expiration. Consider implementing automated certificate renewal using certbot or similar tools.",
		},
		{
			AssetIdx:    9, // cdn.example.com
			Title:       "HTTP Strict Transport Security Not Enabled",
			Description: "The web server does not send the Strict-Transport-Security header, leaving users vulnerable to protocol downgrade attacks and cookie hijacking.",
			Severity:    models.SeverityMedium,
			Status:      models.FindingStatusOpen,
			Type:        "missing_hsts",
			Category:    "web",
			Port:        443,
			Protocol:    "tcp",
			Service:     "https",
			Evidence:    "Response headers do not include Strict-Transport-Security",
			Remediation: "Add the HSTS header to your web server configuration: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		},
		{
			AssetIdx:    12, // blog.demo-company.io
			Title:       "X-Frame-Options Header Missing",
			Description: "The X-Frame-Options header is not set, which could allow clickjacking attacks where the site is embedded in a malicious iframe.",
			Severity:    models.SeverityLow,
			Status:      models.FindingStatusOpen,
			Type:        "missing_xfo",
			Category:    "web",
			Port:        443,
			Protocol:    "tcp",
			Service:     "https",
			Evidence:    "X-Frame-Options header not present in response",
			Remediation: "Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN to your web server configuration.",
		},
		{
			AssetIdx:    7, // dev.example.com
			Title:       "Exposed .git Directory",
			Description: "The .git directory is publicly accessible, potentially exposing source code, commit history, and sensitive configuration files.",
			Severity:    models.SeverityCritical,
			Status:      models.FindingStatusOpen,
			Type:        "exposed_git",
			Category:    "web",
			Port:        443,
			Protocol:    "tcp",
			Service:     "https",
			Evidence:    "GET /.git/config returned 200 OK with git config contents. Repository URL and branch information exposed.",
			Remediation: "Block access to .git directories in your web server configuration. For nginx: location ~ /\\.git { deny all; }. Also consider removing the .git directory from production deployments entirely.",
		},
		{
			AssetIdx:    12, // blog.demo-company.io
			Title:       "WordPress Version Outdated",
			Description: "WordPress installation is running an outdated version with known security vulnerabilities including XSS and privilege escalation.",
			Severity:    models.SeverityHigh,
			Status:      models.FindingStatusOpen,
			Type:        "outdated_software",
			Category:    "web",
			Port:        443,
			Protocol:    "tcp",
			Service:     "https",
			Evidence:    "WordPress version 5.9.3 detected via meta generator tag. Current stable: 6.4.2. Multiple CVEs affect this version.",
			Remediation: "Update WordPress to the latest stable version immediately. Enable automatic updates for minor releases and regularly check for major version updates.",
		},
		{
			AssetIdx:    4, // admin.example.com
			Title:       "Default Credentials Detected",
			Description: "The application accepts default or commonly known credentials, allowing unauthorized access to administrative functions.",
			Severity:    models.SeverityCritical,
			Status:      models.FindingStatusAcknowledged,
			Type:        "default_creds",
			Category:    "web",
			Port:        443,
			Protocol:    "tcp",
			Service:     "https",
			Evidence:    "Successful login with admin:admin credentials at /admin/login endpoint",
			Remediation: "Immediately change all default credentials. Implement password complexity requirements and account lockout policies. Consider using SSO or MFA for admin access.",
		},
		{
			AssetIdx:    17, // 52.14.88.91
			Title:       "Open MongoDB Port (27017)",
			Description: "MongoDB database port is accessible from the public internet. Historically, exposed MongoDB instances have been targets for ransomware attacks.",
			Severity:    models.SeverityHigh,
			Status:      models.FindingStatusOpen,
			Type:        "open_port",
			Category:    "network",
			Port:        27017,
			Protocol:    "tcp",
			Service:     "mongodb",
			Evidence:    "MongoDB 5.0.14 detected on port 27017. Connection accepted without authentication.",
			Remediation: "Enable MongoDB authentication with strong credentials. Bind MongoDB to localhost or internal network interfaces only. Use firewall rules to restrict access to trusted IP addresses.",
		},
		{
			AssetIdx:    3, // api.example.com
			Title:       "Exposed API Documentation",
			Description: "Swagger/OpenAPI documentation is publicly accessible, revealing API endpoints, parameters, and potentially sensitive business logic.",
			Severity:    models.SeverityLow,
			Status:      models.FindingStatusOpen,
			Type:        "exposed_docs",
			Category:    "web",
			Port:        443,
			Protocol:    "tcp",
			Service:     "https",
			Evidence:    "Swagger UI accessible at /api/docs and /swagger.json. 47 endpoints documented including /api/admin/* routes.",
			Remediation: "Restrict access to API documentation in production environments. Use authentication or IP allowlisting, or disable documentation endpoints entirely in production.",
		},
		{
			AssetIdx:    11, // payments.example.com
			Title:       "Insecure CORS Configuration",
			Description: "The Cross-Origin Resource Sharing policy allows requests from any origin, potentially enabling cross-site data theft.",
			Severity:    models.SeverityMedium,
			Status:      models.FindingStatusOpen,
			Type:        "cors_misconfiguration",
			Category:    "web",
			Port:        443,
			Protocol:    "tcp",
			Service:     "https",
			Evidence:    "Access-Control-Allow-Origin: * header present on sensitive endpoints. Access-Control-Allow-Credentials: true also set.",
			Remediation: "Configure CORS to only allow specific trusted origins. Never use wildcard (*) with Access-Control-Allow-Credentials. Implement a whitelist of allowed origins.",
		},
		{
			AssetIdx:    18, // 34.201.55.12
			Title:       "Server Version Disclosure",
			Description: "The web server discloses detailed version information in response headers, helping attackers identify known vulnerabilities.",
			Severity:    models.SeverityInfo,
			Status:      models.FindingStatusOpen,
			Type:        "info_disclosure",
			Category:    "web",
			Port:        80,
			Protocol:    "tcp",
			Service:     "http",
			Evidence:    "Server: Apache/2.4.41 (Ubuntu), X-Powered-By: PHP/7.4.3",
			Remediation: "Configure the web server to suppress version information. For Apache: ServerTokens Prod and ServerSignature Off. For PHP: expose_php = Off in php.ini.",
		},
		{
			AssetIdx:    1, // demo-company.io
			Title:       "DNS Zone Transfer Enabled",
			Description: "The DNS server allows zone transfers (AXFR) to any host, exposing the complete DNS zone data including all subdomains and internal hostnames.",
			Severity:    models.SeverityHigh,
			Status:      models.FindingStatusOpen,
			Type:        "dns_zone_transfer",
			Category:    "dns",
			Evidence:    "AXFR query successful. Zone contains 47 records including internal hostnames: db-master.internal, redis-cluster.internal, vpn.internal",
			Remediation: "Restrict zone transfers to authorized secondary DNS servers only. Configure allow-transfer directive with specific IP addresses or use TSIG keys for authentication.",
		},
		{
			AssetIdx:    8, // beta.example.com
			Title:       "Subdomain Takeover Possible",
			Description: "This subdomain points to an unclaimed external service, allowing an attacker to claim the service and serve malicious content from your domain.",
			Severity:    models.SeverityCritical,
			Status:      models.FindingStatusOpen,
			Type:        "subdomain_takeover",
			Category:    "dns",
			Evidence:    "CNAME record points to beta-app.herokuapp.com which returns 'No such app' error. Service is unclaimed and available for registration.",
			Remediation: "Remove the DNS record if the service is no longer needed, or claim the external service resource. Regularly audit DNS records for dangling references.",
		},
		{
			AssetIdx:    20, // example-uploads bucket
			Title:       "S3 Bucket Public Read Access",
			Description: "This S3 bucket allows public read access, potentially exposing sensitive uploaded files to unauthorized users.",
			Severity:    models.SeverityHigh,
			Status:      models.FindingStatusOpen,
			Type:        "bucket_public",
			Category:    "cloud",
			Evidence:    "Bucket ACL allows public read. 1,247 objects accessible including user-uploads/*.pdf and documents/*.docx",
			Remediation: "Review and restrict bucket ACL permissions. Enable S3 Block Public Access settings. Use presigned URLs for temporary access to private objects.",
		},
		{
			AssetIdx:    21, // example-backups bucket
			Title:       "S3 Bucket Logging Disabled",
			Description: "Server access logging is not enabled for this S3 bucket, making it difficult to audit access patterns and detect unauthorized access.",
			Severity:    models.SeverityLow,
			Status:      models.FindingStatusFixed,
			Type:        "bucket_no_logging",
			Category:    "cloud",
			Evidence:    "Bucket logging configuration is not set. No access logs being generated.",
			Remediation: "Enable server access logging for the bucket. Configure a separate logging bucket and set appropriate log retention policies.",
		},
		{
			AssetIdx:    19, // 18.222.103.44
			Title:       "Elasticsearch Cluster Exposed",
			Description: "Elasticsearch HTTP API is accessible without authentication, potentially exposing indexed data and allowing remote code execution via scripting.",
			Severity:    models.SeverityHigh,
			Status:      models.FindingStatusOpen,
			Type:        "open_port",
			Category:    "network",
			Port:        9200,
			Protocol:    "tcp",
			Service:     "elasticsearch",
			Evidence:    "Elasticsearch 7.17.0 cluster 'production-logs' accessible. Contains indices: app-logs-*, user-events-*, error-tracking-*",
			Remediation: "Enable Elasticsearch security features (X-Pack). Configure authentication and TLS. Restrict network access to trusted clients only using firewall rules.",
		},
	}

	var findings []models.Finding
	for _, data := range findingsData {
		// Ensure we don't exceed asset array bounds
		assetIdx := data.AssetIdx
		if assetIdx >= len(assets) {
			assetIdx = len(assets) - 1
		}

		// Generate unique hash for deduplication
		hashInput := fmt.Sprintf("%s:%s:%s:%d", assets[assetIdx].ID, data.Title, data.Type, data.Port)
		hashBytes := sha256.Sum256([]byte(hashInput))
		hash := hex.EncodeToString(hashBytes[:])

		finding := models.Finding{
			OrganizationID: orgID,
			AssetID:        assets[assetIdx].ID,
			ScanID:         completedScanID,
			Title:          data.Title,
			Description:    data.Description,
			Severity:       data.Severity,
			Status:         data.Status,
			Type:           data.Type,
			Category:       data.Category,
			Port:           data.Port,
			Protocol:       data.Protocol,
			Service:        data.Service,
			Evidence:       data.Evidence,
			Remediation:    data.Remediation,
			FirstSeenAt:    now - int64(86400*3), // 3 days ago
			LastSeenAt:     now,
			Hash:           hash,
			RawData:        "{}",
			References:     "[]",
		}
		findings = append(findings, finding)
	}

	if err := db.WithContext(ctx).Create(&findings).Error; err != nil {
		return err
	}

	fmt.Printf("done (%d findings)\n", len(findings))

	// Print severity breakdown
	severityCounts := map[models.Severity]int{}
	for _, f := range findings {
		severityCounts[f.Severity]++
	}
	fmt.Printf("  - Critical: %d\n", severityCounts[models.SeverityCritical])
	fmt.Printf("  - High: %d\n", severityCounts[models.SeverityHigh])
	fmt.Printf("  - Medium: %d\n", severityCounts[models.SeverityMedium])
	fmt.Printf("  - Low: %d\n", severityCounts[models.SeverityLow])
	fmt.Printf("  - Info: %d\n", severityCounts[models.SeverityInfo])

	return nil
}

// seedAdminUser creates the admin user from environment variables (legacy behavior)
func seedAdminUser(ctx context.Context, db *gorm.DB, cfg *config.Config) error {
	email := os.Getenv("ADMIN_EMAIL")
	password := os.Getenv("ADMIN_PASSWORD")
	name := os.Getenv("ADMIN_NAME")

	// Skip if no admin env vars set
	if email == "" && password == "" && name == "" {
		return nil
	}

	// Apply defaults
	if email == "" {
		email = "admin@example.com"
	}
	if password == "" {
		password = "admin123!"
	}
	if name == "" {
		name = "Admin"
	}

	fmt.Print("Creating admin user from environment... ")

	// Check if user exists
	var existing models.User
	if err := db.WithContext(ctx).Where("email = ?", email).First(&existing).Error; err == nil {
		fmt.Printf("already exists (%s), skipping\n", email)
		return nil
	}

	// Use auth service to create admin with their own organization
	jwtService := auth.NewJWTService(cfg.JWT.Secret, cfg.JWT.Expiry())
	authService := auth.NewService(db, jwtService)

	resp, err := authService.Register(ctx, auth.RegisterInput{
		Email:    email,
		Password: password,
		Name:     name,
		OrgName:  "Default Organization",
	})
	if err != nil {
		if err == auth.ErrUserExists {
			fmt.Printf("already exists (%s), skipping\n", email)
			return nil
		}
		return err
	}

	fmt.Println("done")
	fmt.Printf("  - Email: %s\n", resp.User.Email)
	fmt.Printf("  - Organization: %s\n", resp.User.Organization.Name)

	return nil
}
