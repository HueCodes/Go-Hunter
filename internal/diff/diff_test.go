package diff

import (
	"testing"
	"time"
)

func TestCalculate_NoChanges(t *testing.T) {
	assets := []AssetSnapshot{
		{ID: "1", Type: "domain", Value: "example.com"},
	}
	findings := []FindingSnapshot{
		{ID: "f1", AssetID: "1", Title: "Open port 22", Severity: "medium", Status: "open"},
	}

	d := Calculate(assets, assets, findings, findings, time.Now(), time.Now())

	if d.Summary.AssetsAdded != 0 {
		t.Errorf("AssetsAdded = %d, want 0", d.Summary.AssetsAdded)
	}
	if d.Summary.AssetsRemoved != 0 {
		t.Errorf("AssetsRemoved = %d, want 0", d.Summary.AssetsRemoved)
	}
	if d.Summary.FindingsNew != 0 {
		t.Errorf("FindingsNew = %d, want 0", d.Summary.FindingsNew)
	}
	if d.Summary.FindingsFixed != 0 {
		t.Errorf("FindingsFixed = %d, want 0", d.Summary.FindingsFixed)
	}
}

func TestCalculate_AssetsAdded(t *testing.T) {
	from := []AssetSnapshot{
		{ID: "1", Type: "domain", Value: "example.com"},
	}
	to := []AssetSnapshot{
		{ID: "1", Type: "domain", Value: "example.com"},
		{ID: "2", Type: "subdomain", Value: "api.example.com"},
		{ID: "3", Type: "ip", Value: "1.2.3.4"},
	}

	d := Calculate(from, to, nil, nil, time.Now(), time.Now())

	if d.Summary.AssetsAdded != 2 {
		t.Fatalf("AssetsAdded = %d, want 2", d.Summary.AssetsAdded)
	}
	if d.AssetsAdded[0].Value != "api.example.com" {
		t.Errorf("first added = %q", d.AssetsAdded[0].Value)
	}
}

func TestCalculate_AssetsRemoved(t *testing.T) {
	from := []AssetSnapshot{
		{ID: "1", Type: "domain", Value: "example.com"},
		{ID: "2", Type: "subdomain", Value: "old.example.com"},
	}
	to := []AssetSnapshot{
		{ID: "1", Type: "domain", Value: "example.com"},
	}

	d := Calculate(from, to, nil, nil, time.Now(), time.Now())

	if d.Summary.AssetsRemoved != 1 {
		t.Fatalf("AssetsRemoved = %d, want 1", d.Summary.AssetsRemoved)
	}
	if d.AssetsRemoved[0].Value != "old.example.com" {
		t.Errorf("removed = %q", d.AssetsRemoved[0].Value)
	}
}

func TestCalculate_NewFindings(t *testing.T) {
	fromFindings := []FindingSnapshot{
		{ID: "f1", AssetID: "1", Title: "Port 22 open", Severity: "medium", Status: "open"},
	}
	toFindings := []FindingSnapshot{
		{ID: "f1", AssetID: "1", Title: "Port 22 open", Severity: "medium", Status: "open"},
		{ID: "f2", AssetID: "1", Title: "Weak TLS", Severity: "high", Status: "open"},
	}

	d := Calculate(nil, nil, fromFindings, toFindings, time.Now(), time.Now())

	if d.Summary.FindingsNew != 1 {
		t.Fatalf("FindingsNew = %d, want 1", d.Summary.FindingsNew)
	}
	if d.FindingsNew[0].Title != "Weak TLS" {
		t.Errorf("new finding = %q", d.FindingsNew[0].Title)
	}
}

func TestCalculate_FixedFindings(t *testing.T) {
	fromFindings := []FindingSnapshot{
		{ID: "f1", AssetID: "1", Title: "Port 22 open", Severity: "medium", Status: "open"},
		{ID: "f2", AssetID: "1", Title: "Weak TLS", Severity: "high", Status: "open"},
	}
	toFindings := []FindingSnapshot{
		{ID: "f1", AssetID: "1", Title: "Port 22 open", Severity: "medium", Status: "open"},
		{ID: "f2", AssetID: "1", Title: "Weak TLS", Severity: "high", Status: "fixed"},
	}

	d := Calculate(nil, nil, fromFindings, toFindings, time.Now(), time.Now())

	if d.Summary.FindingsFixed != 1 {
		t.Fatalf("FindingsFixed = %d, want 1", d.Summary.FindingsFixed)
	}
	if d.FindingsFixed[0].Title != "Weak TLS" {
		t.Errorf("fixed finding = %q", d.FindingsFixed[0].Title)
	}
}

func TestCalculate_FindingReopened(t *testing.T) {
	fromFindings := []FindingSnapshot{
		{ID: "f1", AssetID: "1", Title: "Port 22 open", Severity: "medium", Status: "fixed"},
	}
	toFindings := []FindingSnapshot{
		{ID: "f1", AssetID: "1", Title: "Port 22 open", Severity: "medium", Status: "open"},
	}

	d := Calculate(nil, nil, fromFindings, toFindings, time.Now(), time.Now())

	if d.Summary.FindingsNew != 1 {
		t.Fatalf("FindingsNew = %d, want 1 (reopened)", d.Summary.FindingsNew)
	}
}

func TestCalculate_EmptyInputs(t *testing.T) {
	d := Calculate(nil, nil, nil, nil, time.Now(), time.Now())

	if d.Summary.AssetsAdded != 0 || d.Summary.AssetsRemoved != 0 ||
		d.Summary.FindingsNew != 0 || d.Summary.FindingsFixed != 0 {
		t.Error("empty inputs should produce zero summary")
	}
}

func TestCalculate_ComplexScenario(t *testing.T) {
	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()

	fromAssets := []AssetSnapshot{
		{ID: "1", Type: "domain", Value: "example.com"},
		{ID: "2", Type: "subdomain", Value: "old.example.com"},
		{ID: "3", Type: "ip", Value: "1.1.1.1"},
	}
	toAssets := []AssetSnapshot{
		{ID: "1", Type: "domain", Value: "example.com"},
		{ID: "4", Type: "subdomain", Value: "new.example.com"},
		{ID: "3", Type: "ip", Value: "1.1.1.1"},
	}

	fromFindings := []FindingSnapshot{
		{ID: "f1", AssetID: "1", Title: "Port 22 open", Severity: "medium", Status: "open"},
		{ID: "f2", AssetID: "2", Title: "Weak cipher", Severity: "high", Status: "open"},
	}
	toFindings := []FindingSnapshot{
		{ID: "f1", AssetID: "1", Title: "Port 22 open", Severity: "medium", Status: "fixed"},
		{ID: "f3", AssetID: "4", Title: "Missing HSTS", Severity: "medium", Status: "open"},
	}

	d := Calculate(fromAssets, toAssets, fromFindings, toFindings, from, to)

	if d.Summary.AssetsAdded != 1 {
		t.Errorf("AssetsAdded = %d, want 1", d.Summary.AssetsAdded)
	}
	if d.Summary.AssetsRemoved != 1 {
		t.Errorf("AssetsRemoved = %d, want 1", d.Summary.AssetsRemoved)
	}
	if d.Summary.FindingsNew != 1 {
		t.Errorf("FindingsNew = %d, want 1", d.Summary.FindingsNew)
	}
	if d.Summary.FindingsFixed != 2 {
		t.Errorf("FindingsFixed = %d, want 2 (one fixed, one removed with asset)", d.Summary.FindingsFixed)
	}
}
