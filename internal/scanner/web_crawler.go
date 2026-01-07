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
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/database/models"
)

// WebCrawler performs basic web crawling for discovered HTTP services
type WebCrawler struct {
	logger      *slog.Logger
	client      *http.Client
	maxDepth    int
	maxPages    int
	concurrency int
}

// WebCrawlerConfig configures the web crawler behavior
type WebCrawlerConfig struct {
	Timeout     time.Duration
	MaxDepth    int
	MaxPages    int
	Concurrency int
}

// CrawlResult represents discovered items from crawling
type CrawlResult struct {
	BaseURL      string
	Links        []DiscoveredLink
	Forms        []DiscoveredForm
	Scripts      []DiscoveredScript
	Parameters   []DiscoveredParameter
	Endpoints    []DiscoveredEndpoint
	PagesCrawled int
}

// DiscoveredLink represents a discovered link
type DiscoveredLink struct {
	URL      string
	Text     string
	Internal bool
}

// DiscoveredForm represents a discovered HTML form
type DiscoveredForm struct {
	Action  string
	Method  string
	Inputs  []FormInput
	PageURL string
}

// FormInput represents a form input field
type FormInput struct {
	Name     string
	Type     string
	Value    string
	Required bool
}

// DiscoveredScript represents a discovered JavaScript file
type DiscoveredScript struct {
	URL      string
	Internal bool
	Inline   bool
}

// DiscoveredParameter represents a URL parameter
type DiscoveredParameter struct {
	URL     string
	Name    string
	Value   string
	PageURL string
}

// DiscoveredEndpoint represents a discovered API endpoint
type DiscoveredEndpoint struct {
	URL    string
	Method string
	Source string // Where it was discovered (form, link, js)
}

// NewWebCrawler creates a new web crawler instance
func NewWebCrawler(logger *slog.Logger, cfg *WebCrawlerConfig) *WebCrawler {
	timeout := 15 * time.Second
	maxDepth := 3
	maxPages := 100
	concurrency := 10

	if cfg != nil {
		if cfg.Timeout > 0 {
			timeout = cfg.Timeout
		}
		if cfg.MaxDepth > 0 {
			maxDepth = cfg.MaxDepth
		}
		if cfg.MaxPages > 0 {
			maxPages = cfg.MaxPages
		}
		if cfg.Concurrency > 0 {
			concurrency = cfg.Concurrency
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		MaxIdleConnsPerHost: 10,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &WebCrawler{
		logger:      logger,
		client:      client,
		maxDepth:    maxDepth,
		maxPages:    maxPages,
		concurrency: concurrency,
	}
}

// CrawlURL crawls a URL and returns discovered items
func (c *WebCrawler) CrawlURL(ctx context.Context, startURL string) (*CrawlResult, error) {
	parsedURL, err := url.Parse(startURL)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}

	result := &CrawlResult{
		BaseURL: startURL,
	}

	visited := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, c.concurrency)

	// Queue for URLs to visit with their depth
	type crawlItem struct {
		url   string
		depth int
	}
	queue := []crawlItem{{url: startURL, depth: 0}}
	queueMu := sync.Mutex{}

	// Process queue
	for len(queue) > 0 && result.PagesCrawled < c.maxPages {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		queueMu.Lock()
		if len(queue) == 0 {
			queueMu.Unlock()
			break
		}
		item := queue[0]
		queue = queue[1:]
		queueMu.Unlock()

		// Skip if already visited or too deep
		mu.Lock()
		if visited[item.url] || item.depth > c.maxDepth {
			mu.Unlock()
			continue
		}
		visited[item.url] = true
		mu.Unlock()

		sem <- struct{}{}
		wg.Add(1)

		go func(item crawlItem) {
			defer wg.Done()
			defer func() { <-sem }()

			// Crawl the page
			pageResult := c.crawlPage(ctx, item.url, parsedURL)
			if pageResult == nil {
				return
			}

			mu.Lock()
			result.PagesCrawled++
			result.Links = append(result.Links, pageResult.Links...)
			result.Forms = append(result.Forms, pageResult.Forms...)
			result.Scripts = append(result.Scripts, pageResult.Scripts...)
			result.Parameters = append(result.Parameters, pageResult.Parameters...)
			result.Endpoints = append(result.Endpoints, pageResult.Endpoints...)

			// Add internal links to queue
			for _, link := range pageResult.Links {
				if link.Internal && !visited[link.URL] {
					queueMu.Lock()
					queue = append(queue, crawlItem{url: link.URL, depth: item.depth + 1})
					queueMu.Unlock()
				}
			}
			mu.Unlock()
		}(item)

		// Wait a bit to not overwhelm the server
		time.Sleep(100 * time.Millisecond)
	}

	wg.Wait()

	// Deduplicate results
	result.Links = deduplicateLinks(result.Links)
	result.Forms = deduplicateForms(result.Forms)
	result.Scripts = deduplicateScripts(result.Scripts)
	result.Endpoints = deduplicateEndpoints(result.Endpoints)

	return result, nil
}

// crawlPage crawls a single page and extracts information
func (c *WebCrawler) crawlPage(ctx context.Context, pageURL string, baseURL *url.URL) *CrawlResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Go-Hunter/1.0 (Security Scanner)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Only process HTML responses
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "application/xhtml") {
		return nil
	}

	// Read body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB limit
	if err != nil {
		return nil
	}

	bodyStr := string(body)
	result := &CrawlResult{}

	// Extract links
	result.Links = c.extractLinks(bodyStr, pageURL, baseURL)

	// Extract forms
	result.Forms = c.extractForms(bodyStr, pageURL, baseURL)

	// Extract scripts
	result.Scripts = c.extractScripts(bodyStr, pageURL, baseURL)

	// Extract URL parameters
	result.Parameters = c.extractParameters(result.Links, pageURL)

	// Identify potential API endpoints from JavaScript
	result.Endpoints = c.extractEndpoints(bodyStr, pageURL, baseURL)

	return result
}

// extractLinks extracts all links from HTML
func (c *WebCrawler) extractLinks(body, pageURL string, baseURL *url.URL) []DiscoveredLink {
	var links []DiscoveredLink

	// Match href attributes
	hrefRe := regexp.MustCompile(`<a[^>]+href=["']([^"']+)["'][^>]*>([^<]*)`)
	matches := hrefRe.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		href := strings.TrimSpace(match[1])
		text := ""
		if len(match) > 2 {
			text = strings.TrimSpace(match[2])
		}

		// Skip javascript:, mailto:, tel:, etc.
		if strings.HasPrefix(href, "javascript:") ||
			strings.HasPrefix(href, "mailto:") ||
			strings.HasPrefix(href, "tel:") ||
			strings.HasPrefix(href, "#") ||
			href == "" {
			continue
		}

		// Resolve relative URLs
		resolvedURL := resolveURL(href, pageURL, baseURL)
		if resolvedURL == "" {
			continue
		}

		links = append(links, DiscoveredLink{
			URL:      resolvedURL,
			Text:     text,
			Internal: isInternalURL(resolvedURL, baseURL),
		})
	}

	return links
}

// extractForms extracts HTML forms
func (c *WebCrawler) extractForms(body, pageURL string, baseURL *url.URL) []DiscoveredForm {
	var forms []DiscoveredForm

	// Simple form extraction
	formRe := regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	formMatches := formRe.FindAllStringSubmatch(body, -1)

	for _, formMatch := range formMatches {
		if len(formMatch) < 3 {
			continue
		}

		formAttrs := formMatch[1]
		formBody := formMatch[2]

		form := DiscoveredForm{
			PageURL: pageURL,
			Method:  "GET", // Default
		}

		// Extract action
		actionRe := regexp.MustCompile(`action=["']([^"']+)["']`)
		if actionMatch := actionRe.FindStringSubmatch(formAttrs); len(actionMatch) > 1 {
			form.Action = resolveURL(actionMatch[1], pageURL, baseURL)
		} else {
			form.Action = pageURL
		}

		// Extract method
		methodRe := regexp.MustCompile(`(?i)method=["']([^"']+)["']`)
		if methodMatch := methodRe.FindStringSubmatch(formAttrs); len(methodMatch) > 1 {
			form.Method = strings.ToUpper(methodMatch[1])
		}

		// Extract inputs
		inputRe := regexp.MustCompile(`<input([^>]*)>`)
		inputMatches := inputRe.FindAllStringSubmatch(formBody, -1)

		for _, inputMatch := range inputMatches {
			if len(inputMatch) < 2 {
				continue
			}

			inputAttrs := inputMatch[1]
			input := FormInput{}

			// Extract name
			nameRe := regexp.MustCompile(`name=["']([^"']+)["']`)
			if nameMatch := nameRe.FindStringSubmatch(inputAttrs); len(nameMatch) > 1 {
				input.Name = nameMatch[1]
			}

			// Extract type
			typeRe := regexp.MustCompile(`type=["']([^"']+)["']`)
			if typeMatch := typeRe.FindStringSubmatch(inputAttrs); len(typeMatch) > 1 {
				input.Type = typeMatch[1]
			} else {
				input.Type = "text"
			}

			// Extract value
			valueRe := regexp.MustCompile(`value=["']([^"']+)["']`)
			if valueMatch := valueRe.FindStringSubmatch(inputAttrs); len(valueMatch) > 1 {
				input.Value = valueMatch[1]
			}

			// Check required
			input.Required = strings.Contains(inputAttrs, "required")

			if input.Name != "" {
				form.Inputs = append(form.Inputs, input)
			}
		}

		forms = append(forms, form)
	}

	return forms
}

// extractScripts extracts JavaScript references
func (c *WebCrawler) extractScripts(body, pageURL string, baseURL *url.URL) []DiscoveredScript {
	var scripts []DiscoveredScript

	// External scripts
	scriptRe := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptRe.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		src := strings.TrimSpace(match[1])
		resolvedURL := resolveURL(src, pageURL, baseURL)
		if resolvedURL == "" {
			continue
		}

		scripts = append(scripts, DiscoveredScript{
			URL:      resolvedURL,
			Internal: isInternalURL(resolvedURL, baseURL),
			Inline:   false,
		})
	}

	return scripts
}

// extractParameters extracts URL parameters
func (c *WebCrawler) extractParameters(links []DiscoveredLink, pageURL string) []DiscoveredParameter {
	var params []DiscoveredParameter

	for _, link := range links {
		parsedURL, err := url.Parse(link.URL)
		if err != nil {
			continue
		}

		for name, values := range parsedURL.Query() {
			for _, value := range values {
				params = append(params, DiscoveredParameter{
					URL:     link.URL,
					Name:    name,
					Value:   value,
					PageURL: pageURL,
				})
			}
		}
	}

	return params
}

// extractEndpoints tries to find API endpoints from JavaScript and HTML
func (c *WebCrawler) extractEndpoints(body, pageURL string, baseURL *url.URL) []DiscoveredEndpoint {
	var endpoints []DiscoveredEndpoint

	// Common API patterns
	apiPatterns := []string{
		`["'](/api/[^"'\s]+)["']`,
		`["'](/v[0-9]+/[^"'\s]+)["']`,
		`["'](\./api/[^"'\s]+)["']`,
		`fetch\(["']([^"']+)["']`,
		`axios\.[a-z]+\(["']([^"']+)["']`,
		`\$\.ajax\([^)]*url:\s*["']([^"']+)["']`,
		`XMLHttpRequest[^)]*open\([^,]+,\s*["']([^"']+)["']`,
	}

	for _, pattern := range apiPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(body, -1)

		for _, match := range matches {
			if len(match) < 2 {
				continue
			}

			endpoint := strings.TrimSpace(match[1])
			if endpoint == "" {
				continue
			}

			resolvedURL := resolveURL(endpoint, pageURL, baseURL)
			if resolvedURL == "" {
				continue
			}

			endpoints = append(endpoints, DiscoveredEndpoint{
				URL:    resolvedURL,
				Method: "GET", // Default, actual method unknown
				Source: "javascript",
			})
		}
	}

	return endpoints
}

// resolveURL resolves a potentially relative URL to an absolute URL
func resolveURL(href, pageURL string, baseURL *url.URL) string {
	if href == "" {
		return ""
	}

	// Already absolute
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}

	// Protocol-relative
	if strings.HasPrefix(href, "//") {
		return baseURL.Scheme + ":" + href
	}

	// Parse the page URL to get the base
	page, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}

	// Resolve relative to page
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}

	return page.ResolveReference(ref).String()
}

// isInternalURL checks if a URL belongs to the same host
func isInternalURL(testURL string, baseURL *url.URL) bool {
	parsed, err := url.Parse(testURL)
	if err != nil {
		return false
	}
	return parsed.Host == baseURL.Host
}

// Deduplication helpers
func deduplicateLinks(links []DiscoveredLink) []DiscoveredLink {
	seen := make(map[string]bool)
	var result []DiscoveredLink
	for _, link := range links {
		if !seen[link.URL] {
			seen[link.URL] = true
			result = append(result, link)
		}
	}
	return result
}

func deduplicateForms(forms []DiscoveredForm) []DiscoveredForm {
	seen := make(map[string]bool)
	var result []DiscoveredForm
	for _, form := range forms {
		key := form.Action + ":" + form.Method
		if !seen[key] {
			seen[key] = true
			result = append(result, form)
		}
	}
	return result
}

func deduplicateScripts(scripts []DiscoveredScript) []DiscoveredScript {
	seen := make(map[string]bool)
	var result []DiscoveredScript
	for _, script := range scripts {
		if !seen[script.URL] {
			seen[script.URL] = true
			result = append(result, script)
		}
	}
	return result
}

func deduplicateEndpoints(endpoints []DiscoveredEndpoint) []DiscoveredEndpoint {
	seen := make(map[string]bool)
	var result []DiscoveredEndpoint
	for _, endpoint := range endpoints {
		key := endpoint.URL + ":" + endpoint.Method
		if !seen[key] {
			seen[key] = true
			result = append(result, endpoint)
		}
	}
	return result
}

// ResultsToFindings converts crawl results to Finding models
func (c *WebCrawler) ResultsToFindings(result *CrawlResult, assetID, scanID, orgID uuid.UUID) []models.Finding {
	var findings []models.Finding
	now := time.Now().Unix()

	// Create summary finding
	summaryEvidence := map[string]interface{}{
		"base_url":        result.BaseURL,
		"pages_crawled":   result.PagesCrawled,
		"links_found":     len(result.Links),
		"forms_found":     len(result.Forms),
		"scripts_found":   len(result.Scripts),
		"endpoints_found": len(result.Endpoints),
	}
	summaryJSON, _ := json.Marshal(summaryEvidence)

	findings = append(findings, models.Finding{
		OrganizationID: orgID,
		AssetID:        assetID,
		ScanID:         scanID,
		Title:          fmt.Sprintf("Web Crawl Summary: %s", result.BaseURL),
		Description:    fmt.Sprintf("Crawled %d pages and discovered %d links, %d forms, %d scripts, and %d potential endpoints.", result.PagesCrawled, len(result.Links), len(result.Forms), len(result.Scripts), len(result.Endpoints)),
		Severity:       models.SeverityInfo,
		Status:         models.FindingStatusOpen,
		Type:           "crawl_summary",
		Category:       "web",
		Evidence:       string(summaryJSON),
		FirstSeenAt:    now,
		LastSeenAt:     now,
		Hash:           generateCrawlFindingHash(assetID, result.BaseURL, "crawl_summary"),
	})

	// Create findings for forms (potential attack vectors)
	for _, form := range result.Forms {
		if len(form.Inputs) == 0 {
			continue
		}

		formEvidence := map[string]interface{}{
			"action":   form.Action,
			"method":   form.Method,
			"page_url": form.PageURL,
			"inputs":   form.Inputs,
		}
		formJSON, _ := json.Marshal(formEvidence)

		// Determine severity based on input types
		severity := models.SeverityInfo
		hasPassword := false
		for _, input := range form.Inputs {
			if input.Type == "password" {
				hasPassword = true
				break
			}
		}
		if hasPassword {
			severity = models.SeverityLow
		}

		findings = append(findings, models.Finding{
			OrganizationID: orgID,
			AssetID:        assetID,
			ScanID:         scanID,
			Title:          fmt.Sprintf("HTML Form: %s %s", form.Method, form.Action),
			Description:    fmt.Sprintf("Discovered HTML form with %d input fields. Method: %s, Action: %s", len(form.Inputs), form.Method, form.Action),
			Severity:       severity,
			Status:         models.FindingStatusOpen,
			Type:           "web_form",
			Category:       "web",
			Evidence:       string(formJSON),
			Remediation:    "Review form for proper input validation and CSRF protection.",
			FirstSeenAt:    now,
			LastSeenAt:     now,
			Hash:           generateCrawlFindingHash(assetID, form.Action, "web_form"),
		})
	}

	// Create findings for discovered API endpoints
	for _, endpoint := range result.Endpoints {
		endpointEvidence := map[string]interface{}{
			"url":    endpoint.URL,
			"method": endpoint.Method,
			"source": endpoint.Source,
		}
		endpointJSON, _ := json.Marshal(endpointEvidence)

		findings = append(findings, models.Finding{
			OrganizationID: orgID,
			AssetID:        assetID,
			ScanID:         scanID,
			Title:          fmt.Sprintf("API Endpoint: %s", endpoint.URL),
			Description:    fmt.Sprintf("Discovered API endpoint from %s: %s", endpoint.Source, endpoint.URL),
			Severity:       models.SeverityInfo,
			Status:         models.FindingStatusOpen,
			Type:           "api_endpoint",
			Category:       "web",
			Evidence:       string(endpointJSON),
			Remediation:    "Review API endpoint for proper authentication and authorization.",
			FirstSeenAt:    now,
			LastSeenAt:     now,
			Hash:           generateCrawlFindingHash(assetID, endpoint.URL, "api_endpoint"),
		})
	}

	return findings
}

// ResultsToAssets converts crawl results to new Asset models for discovered endpoints
func (c *WebCrawler) ResultsToAssets(result *CrawlResult, orgID uuid.UUID, parentAssetID *uuid.UUID) []models.Asset {
	var assets []models.Asset
	now := time.Now().Unix()
	seen := make(map[string]bool)

	// Add discovered endpoints as assets
	for _, endpoint := range result.Endpoints {
		if seen[endpoint.URL] {
			continue
		}
		seen[endpoint.URL] = true

		metadata := map[string]interface{}{
			"source": endpoint.Source,
			"method": endpoint.Method,
		}
		metadataJSON, _ := json.Marshal(metadata)

		assets = append(assets, models.Asset{
			OrganizationID: orgID,
			Type:           models.AssetTypeEndpoint,
			Value:          endpoint.URL,
			Source:         "crawler",
			Metadata:       string(metadataJSON),
			DiscoveredAt:   now,
			LastSeenAt:     now,
			IsActive:       true,
			ParentID:       parentAssetID,
		})
	}

	return assets
}

func generateCrawlFindingHash(assetID uuid.UUID, identifier, findingType string) string {
	data := fmt.Sprintf("%s:%s:%s", assetID.String(), findingType, identifier)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
