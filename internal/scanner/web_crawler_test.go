package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hugh/go-hunter/internal/database/models"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// ---------------------------------------------------------------------------
// NewWebCrawler
// ---------------------------------------------------------------------------

func TestNewWebCrawler_NilConfig(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	if c == nil {
		t.Fatal("expected non-nil crawler")
	}
	if c.maxDepth != 3 {
		t.Errorf("expected default maxDepth 3, got %d", c.maxDepth)
	}
	if c.maxPages != 100 {
		t.Errorf("expected default maxPages 100, got %d", c.maxPages)
	}
	if c.concurrency != 10 {
		t.Errorf("expected default concurrency 10, got %d", c.concurrency)
	}
}

func TestNewWebCrawler_CustomConfig(t *testing.T) {
	cfg := &WebCrawlerConfig{
		Timeout:     5 * time.Second,
		MaxDepth:    2,
		MaxPages:    50,
		Concurrency: 5,
	}
	c := NewWebCrawler(testLogger(), cfg)
	if c.maxDepth != 2 {
		t.Errorf("expected maxDepth 2, got %d", c.maxDepth)
	}
	if c.maxPages != 50 {
		t.Errorf("expected maxPages 50, got %d", c.maxPages)
	}
	if c.concurrency != 5 {
		t.Errorf("expected concurrency 5, got %d", c.concurrency)
	}
}

func TestNewWebCrawler_ZeroValuesUseDefaults(t *testing.T) {
	cfg := &WebCrawlerConfig{} // all zeros
	c := NewWebCrawler(testLogger(), cfg)
	if c.maxDepth != 3 {
		t.Errorf("expected default maxDepth 3, got %d", c.maxDepth)
	}
	if c.maxPages != 100 {
		t.Errorf("expected default maxPages 100, got %d", c.maxPages)
	}
	if c.concurrency != 10 {
		t.Errorf("expected default concurrency 10, got %d", c.concurrency)
	}
}

// ---------------------------------------------------------------------------
// resolveURL
// ---------------------------------------------------------------------------

func TestResolveURL(t *testing.T) {
	base, _ := url.Parse("https://example.com/dir/page.html")

	tests := []struct {
		name    string
		href    string
		pageURL string
		want    string
	}{
		{"empty href", "", "https://example.com/", ""},
		{"absolute http", "http://other.com/path", "https://example.com/", "http://other.com/path"},
		{"absolute https", "https://other.com/path", "https://example.com/", "https://other.com/path"},
		{"protocol relative", "//cdn.example.com/js/app.js", "https://example.com/", "https://cdn.example.com/js/app.js"},
		{"relative path", "about.html", "https://example.com/dir/page.html", "https://example.com/dir/about.html"},
		{"root relative", "/contact", "https://example.com/dir/page.html", "https://example.com/contact"},
		{"dot relative", "./other", "https://example.com/dir/page.html", "https://example.com/dir/other"},
		{"parent relative", "../root", "https://example.com/dir/page.html", "https://example.com/root"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveURL(tt.href, tt.pageURL, base)
			if got != tt.want {
				t.Errorf("resolveURL(%q, %q) = %q, want %q", tt.href, tt.pageURL, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isInternalURL
// ---------------------------------------------------------------------------

func TestIsInternalURL(t *testing.T) {
	base, _ := url.Parse("https://example.com")

	tests := []struct {
		testURL  string
		internal bool
	}{
		{"https://example.com/page", true},
		{"https://example.com:443/page", false}, // host includes port, differs
		{"https://other.com/page", false},
		{"https://sub.example.com/page", false},
	}

	for _, tt := range tests {
		t.Run(tt.testURL, func(t *testing.T) {
			got := isInternalURL(tt.testURL, base)
			if got != tt.internal {
				t.Errorf("isInternalURL(%q) = %v, want %v", tt.testURL, got, tt.internal)
			}
		})
	}
}

func TestIsInternalURL_InvalidURL(t *testing.T) {
	base, _ := url.Parse("https://example.com")
	got := isInternalURL("://bad", base)
	if got {
		t.Error("expected false for invalid URL")
	}
}

// ---------------------------------------------------------------------------
// extractLinks
// ---------------------------------------------------------------------------

func TestExtractLinks(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	base, _ := url.Parse("https://example.com")

	body := `
		<a href="/about">About</a>
		<a href="https://external.com/page">External</a>
		<a href="/contact?q=hello">Contact</a>
		<a href="javascript:void(0)">JS Link</a>
		<a href="mailto:test@example.com">Email</a>
		<a href="tel:+1234567890">Phone</a>
		<a href="#">Hash</a>
		<a href="">Empty</a>
	`

	links := c.extractLinks(body, "https://example.com/index.html", base)

	// Should have 3 valid links: /about, external, /contact
	if len(links) != 3 {
		t.Fatalf("expected 3 links, got %d: %+v", len(links), links)
	}

	// Check internal vs external
	internalCount := 0
	externalCount := 0
	for _, l := range links {
		if l.Internal {
			internalCount++
		} else {
			externalCount++
		}
	}
	if internalCount != 2 {
		t.Errorf("expected 2 internal links, got %d", internalCount)
	}
	if externalCount != 1 {
		t.Errorf("expected 1 external link, got %d", externalCount)
	}
}

func TestExtractLinks_RelativeURLs(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	base, _ := url.Parse("https://example.com")

	body := `<a href="page2.html">Page 2</a>`
	links := c.extractLinks(body, "https://example.com/dir/page1.html", base)

	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}
	if links[0].URL != "https://example.com/dir/page2.html" {
		t.Errorf("unexpected resolved URL: %s", links[0].URL)
	}
}

func TestExtractLinks_TextExtraction(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	base, _ := url.Parse("https://example.com")

	body := `<a href="/about">About Us</a>`
	links := c.extractLinks(body, "https://example.com/", base)

	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}
	if links[0].Text != "About Us" {
		t.Errorf("expected text 'About Us', got %q", links[0].Text)
	}
}

// ---------------------------------------------------------------------------
// extractForms
// ---------------------------------------------------------------------------

func TestExtractForms(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	base, _ := url.Parse("https://example.com")
	pageURL := "https://example.com/login"

	body := `
		<form action="/submit" method="POST">
			<input type="text" name="username" required>
			<input type="password" name="password" required>
			<input type="hidden" name="csrf" value="token123">
			<input type="submit" value="Login">
		</form>
	`

	forms := c.extractForms(body, pageURL, base)
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}

	form := forms[0]
	if form.Action != "https://example.com/submit" {
		t.Errorf("expected action https://example.com/submit, got %s", form.Action)
	}
	if form.Method != "POST" {
		t.Errorf("expected method POST, got %s", form.Method)
	}
	if form.PageURL != pageURL {
		t.Errorf("expected pageURL %s, got %s", pageURL, form.PageURL)
	}

	// submit input has no name attr in this HTML, so it should be excluded
	// Only username, password, csrf have name attributes
	if len(form.Inputs) != 3 {
		t.Fatalf("expected 3 inputs with names, got %d: %+v", len(form.Inputs), form.Inputs)
	}

	// Check the password field
	var passwordInput *FormInput
	for i, inp := range form.Inputs {
		if inp.Name == "password" {
			passwordInput = &form.Inputs[i]
			break
		}
	}
	if passwordInput == nil {
		t.Fatal("expected to find password input")
	}
	if passwordInput.Type != "password" {
		t.Errorf("expected type password, got %s", passwordInput.Type)
	}
	if !passwordInput.Required {
		t.Error("expected password input to be required")
	}

	// Check hidden csrf field
	var csrfInput *FormInput
	for i, inp := range form.Inputs {
		if inp.Name == "csrf" {
			csrfInput = &form.Inputs[i]
			break
		}
	}
	if csrfInput == nil {
		t.Fatal("expected to find csrf input")
	}
	if csrfInput.Value != "token123" {
		t.Errorf("expected csrf value token123, got %s", csrfInput.Value)
	}
}

func TestExtractForms_DefaultMethod(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	base, _ := url.Parse("https://example.com")

	body := `<form action="/search"><input type="text" name="q"></form>`
	forms := c.extractForms(body, "https://example.com/", base)

	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	if forms[0].Method != "GET" {
		t.Errorf("expected default method GET, got %s", forms[0].Method)
	}
}

func TestExtractForms_NoAction(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	base, _ := url.Parse("https://example.com")
	pageURL := "https://example.com/page"

	body := `<form method="post"><input type="text" name="data"></form>`
	forms := c.extractForms(body, pageURL, base)

	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	if forms[0].Action != pageURL {
		t.Errorf("expected action to default to pageURL %s, got %s", pageURL, forms[0].Action)
	}
}

// ---------------------------------------------------------------------------
// extractScripts
// ---------------------------------------------------------------------------

func TestExtractScripts(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	base, _ := url.Parse("https://example.com")
	pageURL := "https://example.com/"

	body := `
		<script src="/js/app.js"></script>
		<script src="https://cdn.external.com/lib.js"></script>
		<script>var x = 1;</script>
	`

	scripts := c.extractScripts(body, pageURL, base)

	// Only external script tags with src are extracted, inline scripts are not
	if len(scripts) != 2 {
		t.Fatalf("expected 2 scripts, got %d: %+v", len(scripts), scripts)
	}

	internalCount := 0
	externalCount := 0
	for _, s := range scripts {
		if s.Internal {
			internalCount++
		} else {
			externalCount++
		}
		if s.Inline {
			t.Error("external scripts should not be marked inline")
		}
	}
	if internalCount != 1 {
		t.Errorf("expected 1 internal script, got %d", internalCount)
	}
	if externalCount != 1 {
		t.Errorf("expected 1 external script, got %d", externalCount)
	}
}

func TestExtractScripts_ResolvesRelativeURLs(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	base, _ := url.Parse("https://example.com")

	body := `<script src="lib/utils.js"></script>`
	scripts := c.extractScripts(body, "https://example.com/app/index.html", base)

	if len(scripts) != 1 {
		t.Fatalf("expected 1 script, got %d", len(scripts))
	}
	if scripts[0].URL != "https://example.com/app/lib/utils.js" {
		t.Errorf("unexpected resolved script URL: %s", scripts[0].URL)
	}
}

// ---------------------------------------------------------------------------
// extractEndpoints
// ---------------------------------------------------------------------------

func TestExtractEndpoints(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	base, _ := url.Parse("https://example.com")
	pageURL := "https://example.com/"

	body := `
		<script>
			fetch('/api/users')
			axios.get('/api/items')
			var url = '/v2/data/list'
		</script>
	`

	endpoints := c.extractEndpoints(body, pageURL, base)
	if len(endpoints) == 0 {
		t.Fatal("expected at least one endpoint to be discovered")
	}

	foundURLs := make(map[string]bool)
	for _, ep := range endpoints {
		foundURLs[ep.URL] = true
		if ep.Source != "javascript" {
			t.Errorf("expected source 'javascript', got %q", ep.Source)
		}
		if ep.Method != "GET" {
			t.Errorf("expected default method GET, got %q", ep.Method)
		}
	}

	if !foundURLs["https://example.com/api/users"] {
		t.Error("expected to find /api/users endpoint")
	}
	if !foundURLs["https://example.com/api/items"] {
		t.Error("expected to find /api/items endpoint")
	}
	if !foundURLs["https://example.com/v2/data/list"] {
		t.Error("expected to find /v2/data/list endpoint")
	}
}

func TestExtractEndpoints_AjaxPattern(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	base, _ := url.Parse("https://example.com")

	body := `$.ajax({url: '/api/search', method: 'POST'})`
	endpoints := c.extractEndpoints(body, "https://example.com/", base)

	if len(endpoints) == 0 {
		t.Fatal("expected to find ajax endpoint")
	}

	found := false
	for _, ep := range endpoints {
		if ep.URL == "https://example.com/api/search" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find /api/search endpoint from ajax pattern")
	}
}

// ---------------------------------------------------------------------------
// Deduplication helpers
// ---------------------------------------------------------------------------

func TestDeduplicateLinks(t *testing.T) {
	links := []DiscoveredLink{
		{URL: "https://example.com/a", Text: "A"},
		{URL: "https://example.com/b", Text: "B"},
		{URL: "https://example.com/a", Text: "A duplicate"},
	}
	result := deduplicateLinks(links)
	if len(result) != 2 {
		t.Errorf("expected 2 unique links, got %d", len(result))
	}
	// First occurrence should be kept
	if result[0].Text != "A" {
		t.Errorf("expected first occurrence to be kept, got text %q", result[0].Text)
	}
}

func TestDeduplicateForms(t *testing.T) {
	forms := []DiscoveredForm{
		{Action: "/login", Method: "POST"},
		{Action: "/search", Method: "GET"},
		{Action: "/login", Method: "POST"},
		{Action: "/login", Method: "GET"}, // same action, different method
	}
	result := deduplicateForms(forms)
	if len(result) != 3 {
		t.Errorf("expected 3 unique forms, got %d", len(result))
	}
}

func TestDeduplicateScripts(t *testing.T) {
	scripts := []DiscoveredScript{
		{URL: "https://example.com/a.js"},
		{URL: "https://example.com/b.js"},
		{URL: "https://example.com/a.js"},
	}
	result := deduplicateScripts(scripts)
	if len(result) != 2 {
		t.Errorf("expected 2 unique scripts, got %d", len(result))
	}
}

func TestDeduplicateEndpoints(t *testing.T) {
	endpoints := []DiscoveredEndpoint{
		{URL: "/api/users", Method: "GET"},
		{URL: "/api/items", Method: "GET"},
		{URL: "/api/users", Method: "GET"},
		{URL: "/api/users", Method: "POST"}, // same URL, different method
	}
	result := deduplicateEndpoints(endpoints)
	if len(result) != 3 {
		t.Errorf("expected 3 unique endpoints, got %d", len(result))
	}
}

func TestDeduplicateLinks_Nil(t *testing.T) {
	result := deduplicateLinks(nil)
	if result != nil {
		t.Errorf("expected nil result for nil input, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// CrawlURL with httptest
// ---------------------------------------------------------------------------

func testHTML() string {
	return `<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
	<a href="/about">About</a>
	<a href="/contact?ref=home">Contact</a>
	<a href="https://external.com/page">External</a>

	<form action="/login" method="POST">
		<input type="text" name="username" required>
		<input type="password" name="password" required>
	</form>

	<script src="/js/app.js"></script>
	<script src="https://cdn.example.com/lib.js"></script>
	<script>
		fetch('/api/v1/data')
	</script>
</body>
</html>`
}

func TestCrawlURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, testHTML())
	}))
	defer srv.Close()

	cfg := &WebCrawlerConfig{
		Timeout:     5 * time.Second,
		MaxDepth:    1,
		MaxPages:    10,
		Concurrency: 2,
	}
	c := NewWebCrawler(testLogger(), cfg)

	result, err := c.CrawlURL(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("CrawlURL returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.BaseURL != srv.URL {
		t.Errorf("expected BaseURL %s, got %s", srv.URL, result.BaseURL)
	}
	if result.PagesCrawled < 1 {
		t.Errorf("expected at least 1 page crawled, got %d", result.PagesCrawled)
	}

	// Should discover links
	if len(result.Links) == 0 {
		t.Error("expected at least one link")
	}
	// Should discover forms
	if len(result.Forms) == 0 {
		t.Error("expected at least one form")
	}
	// Should discover scripts
	if len(result.Scripts) == 0 {
		t.Error("expected at least one script")
	}
}

func TestCrawlURL_RespectsMaxPages(t *testing.T) {
	pageCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageCount++
		w.Header().Set("Content-Type", "text/html")
		// Generate links to many pages
		body := "<html><body>"
		for i := 0; i < 20; i++ {
			body += fmt.Sprintf(`<a href="/page%d">Page %d</a>`, i, i)
		}
		body += "</body></html>"
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	cfg := &WebCrawlerConfig{
		Timeout:     5 * time.Second,
		MaxDepth:    5,
		MaxPages:    3,
		Concurrency: 1,
	}
	c := NewWebCrawler(testLogger(), cfg)

	result, err := c.CrawlURL(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("CrawlURL returned error: %v", err)
	}
	if result.PagesCrawled > 3 {
		t.Errorf("expected at most 3 pages crawled, got %d", result.PagesCrawled)
	}
}

func TestCrawlURL_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Slow response
		time.Sleep(200 * time.Millisecond)
		body := `<html><body>`
		for i := 0; i < 50; i++ {
			body += fmt.Sprintf(`<a href="/page%d">Page %d</a>`, i, i)
		}
		body += `</body></html>`
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	cfg := &WebCrawlerConfig{
		Timeout:     5 * time.Second,
		MaxDepth:    5,
		MaxPages:    100,
		Concurrency: 1,
	}
	c := NewWebCrawler(testLogger(), cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	result, _ := c.CrawlURL(ctx, srv.URL)
	// Should return partial results without error panic
	if result == nil {
		t.Fatal("expected non-nil result even on cancellation")
	}
}

func TestCrawlURL_NonHTMLContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"key": "value"}`)
	}))
	defer srv.Close()

	cfg := &WebCrawlerConfig{
		Timeout:  5 * time.Second,
		MaxDepth: 1,
		MaxPages: 10,
	}
	c := NewWebCrawler(testLogger(), cfg)

	result, err := c.CrawlURL(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("CrawlURL returned error: %v", err)
	}
	// Non-HTML page should not yield any extracted items
	if len(result.Links) != 0 {
		t.Errorf("expected 0 links from JSON response, got %d", len(result.Links))
	}
}

func TestCrawlURL_InvalidURL(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	_, err := c.CrawlURL(context.Background(), "://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestCrawlURL_Deduplication(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
			<a href="/page">Link 1</a>
			<a href="/page">Link 2</a>
			<a href="/page">Link 3</a>
			<script src="/app.js"></script>
			<script src="/app.js"></script>
		</body></html>`)
	}))
	defer srv.Close()

	cfg := &WebCrawlerConfig{MaxDepth: 1, MaxPages: 5, Concurrency: 1, Timeout: 5 * time.Second}
	c := NewWebCrawler(testLogger(), cfg)

	result, err := c.CrawlURL(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("CrawlURL returned error: %v", err)
	}

	// Links should be deduplicated
	linkURLs := make(map[string]int)
	for _, l := range result.Links {
		linkURLs[l.URL]++
	}
	for u, count := range linkURLs {
		if count > 1 {
			t.Errorf("link %s appears %d times after deduplication", u, count)
		}
	}

	// Scripts should be deduplicated
	scriptURLs := make(map[string]int)
	for _, s := range result.Scripts {
		scriptURLs[s.URL]++
	}
	for u, count := range scriptURLs {
		if count > 1 {
			t.Errorf("script %s appears %d times after deduplication", u, count)
		}
	}
}

// ---------------------------------------------------------------------------
// ResultsToFindings
// ---------------------------------------------------------------------------

func TestResultsToFindings_Summary(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	assetID := uuid.New()
	scanID := uuid.New()
	orgID := uuid.New()

	result := &CrawlResult{
		BaseURL:      "https://example.com",
		PagesCrawled: 5,
		Links:        []DiscoveredLink{{URL: "https://example.com/a"}},
		Forms:        nil,
		Scripts:      []DiscoveredScript{{URL: "https://example.com/app.js"}},
		Endpoints:    nil,
	}

	findings := c.ResultsToFindings(result, assetID, scanID, orgID)

	// Should have at least the summary finding
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	summary := findings[0]
	if summary.Type != "crawl_summary" {
		t.Errorf("expected type crawl_summary, got %s", summary.Type)
	}
	if summary.Severity != models.SeverityInfo {
		t.Errorf("expected severity info, got %s", summary.Severity)
	}
	if summary.Status != models.FindingStatusOpen {
		t.Errorf("expected status open, got %s", summary.Status)
	}
	if summary.OrganizationID != orgID {
		t.Error("organization ID mismatch")
	}
	if summary.AssetID != assetID {
		t.Error("asset ID mismatch")
	}
	if summary.ScanID != scanID {
		t.Error("scan ID mismatch")
	}
	if summary.Category != "web" {
		t.Errorf("expected category 'web', got %q", summary.Category)
	}
	if !strings.Contains(summary.Title, "Web Crawl Summary") {
		t.Errorf("expected title to contain 'Web Crawl Summary', got %q", summary.Title)
	}
	if summary.Hash == "" {
		t.Error("expected non-empty hash")
	}
	if summary.FirstSeenAt == 0 {
		t.Error("expected non-zero FirstSeenAt")
	}
}

func TestResultsToFindings_FormWithPassword(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	assetID := uuid.New()
	scanID := uuid.New()
	orgID := uuid.New()

	result := &CrawlResult{
		BaseURL:      "https://example.com",
		PagesCrawled: 1,
		Forms: []DiscoveredForm{
			{
				Action:  "https://example.com/login",
				Method:  "POST",
				PageURL: "https://example.com/login",
				Inputs: []FormInput{
					{Name: "username", Type: "text"},
					{Name: "password", Type: "password"},
				},
			},
		},
	}

	findings := c.ResultsToFindings(result, assetID, scanID, orgID)

	// Should have summary + form finding
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	formFinding := findings[1]
	if formFinding.Type != "web_form" {
		t.Errorf("expected type web_form, got %s", formFinding.Type)
	}
	// Forms with password fields should be SeverityLow
	if formFinding.Severity != models.SeverityLow {
		t.Errorf("expected severity low for password form, got %s", formFinding.Severity)
	}
	if formFinding.Remediation == "" {
		t.Error("expected non-empty remediation for form finding")
	}
}

func TestResultsToFindings_FormWithoutPassword(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)

	result := &CrawlResult{
		BaseURL: "https://example.com",
		Forms: []DiscoveredForm{
			{
				Action: "/search",
				Method: "GET",
				Inputs: []FormInput{
					{Name: "q", Type: "text"},
				},
			},
		},
	}

	findings := c.ResultsToFindings(result, uuid.New(), uuid.New(), uuid.New())

	// Summary + form
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[1].Severity != models.SeverityInfo {
		t.Errorf("expected severity info for non-password form, got %s", findings[1].Severity)
	}
}

func TestResultsToFindings_FormWithNoInputsSkipped(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)

	result := &CrawlResult{
		BaseURL: "https://example.com",
		Forms: []DiscoveredForm{
			{Action: "/empty", Method: "GET", Inputs: nil},
		},
	}

	findings := c.ResultsToFindings(result, uuid.New(), uuid.New(), uuid.New())
	// Only summary, no form finding since inputs is empty
	if len(findings) != 1 {
		t.Errorf("expected 1 finding (summary only), got %d", len(findings))
	}
}

func TestResultsToFindings_Endpoints(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)

	result := &CrawlResult{
		BaseURL: "https://example.com",
		Endpoints: []DiscoveredEndpoint{
			{URL: "https://example.com/api/users", Method: "GET", Source: "javascript"},
			{URL: "https://example.com/api/items", Method: "GET", Source: "javascript"},
		},
	}

	findings := c.ResultsToFindings(result, uuid.New(), uuid.New(), uuid.New())
	// Summary + 2 endpoint findings
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	for _, f := range findings[1:] {
		if f.Type != "api_endpoint" {
			t.Errorf("expected type api_endpoint, got %s", f.Type)
		}
		if f.Severity != models.SeverityInfo {
			t.Errorf("expected severity info, got %s", f.Severity)
		}
		if !strings.Contains(f.Title, "API Endpoint") {
			t.Errorf("expected title to contain 'API Endpoint', got %q", f.Title)
		}
	}
}

// ---------------------------------------------------------------------------
// ResultsToAssets
// ---------------------------------------------------------------------------

func TestResultsToAssets(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	orgID := uuid.New()
	parentID := uuid.New()

	result := &CrawlResult{
		Endpoints: []DiscoveredEndpoint{
			{URL: "https://example.com/api/users", Method: "GET", Source: "javascript"},
			{URL: "https://example.com/api/items", Method: "POST", Source: "javascript"},
			{URL: "https://example.com/api/users", Method: "GET", Source: "javascript"}, // duplicate
		},
	}

	assets := c.ResultsToAssets(result, orgID, &parentID)

	// Should deduplicate, so 2 unique endpoints
	if len(assets) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(assets))
	}

	for _, a := range assets {
		if a.OrganizationID != orgID {
			t.Error("organization ID mismatch")
		}
		if a.Type != models.AssetTypeEndpoint {
			t.Errorf("expected type endpoint, got %s", a.Type)
		}
		if a.Source != "crawler" {
			t.Errorf("expected source 'crawler', got %s", a.Source)
		}
		if !a.IsActive {
			t.Error("expected asset to be active")
		}
		if a.ParentID == nil || *a.ParentID != parentID {
			t.Error("expected parent ID to be set")
		}
		if a.DiscoveredAt == 0 {
			t.Error("expected non-zero DiscoveredAt")
		}
		if a.Metadata == "" {
			t.Error("expected non-empty metadata")
		}
	}
}

func TestResultsToAssets_NilParent(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)

	result := &CrawlResult{
		Endpoints: []DiscoveredEndpoint{
			{URL: "https://example.com/api/test", Method: "GET", Source: "javascript"},
		},
	}

	assets := c.ResultsToAssets(result, uuid.New(), nil)
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	if assets[0].ParentID != nil {
		t.Error("expected nil parent ID")
	}
}

func TestResultsToAssets_Empty(t *testing.T) {
	c := NewWebCrawler(testLogger(), nil)
	result := &CrawlResult{}
	assets := c.ResultsToAssets(result, uuid.New(), nil)
	if len(assets) != 0 {
		t.Errorf("expected 0 assets, got %d", len(assets))
	}
}

// ---------------------------------------------------------------------------
// generateCrawlFindingHash
// ---------------------------------------------------------------------------

func TestGenerateCrawlFindingHash(t *testing.T) {
	assetID := uuid.New()
	hash1 := generateCrawlFindingHash(assetID, "https://example.com", "crawl_summary")
	hash2 := generateCrawlFindingHash(assetID, "https://example.com", "crawl_summary")

	// Same inputs produce same hash
	if hash1 != hash2 {
		t.Error("expected identical hashes for same input")
	}
	if len(hash1) != 64 {
		t.Errorf("expected 64 char hex hash, got length %d", len(hash1))
	}

	// Different inputs produce different hashes
	hash3 := generateCrawlFindingHash(assetID, "https://other.com", "crawl_summary")
	if hash1 == hash3 {
		t.Error("expected different hashes for different identifiers")
	}

	hash4 := generateCrawlFindingHash(assetID, "https://example.com", "web_form")
	if hash1 == hash4 {
		t.Error("expected different hashes for different finding types")
	}

	hash5 := generateCrawlFindingHash(uuid.New(), "https://example.com", "crawl_summary")
	if hash1 == hash5 {
		t.Error("expected different hashes for different asset IDs")
	}
}
