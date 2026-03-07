package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTemplate_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	os.WriteFile(path, []byte(`
id: test-check
info:
  name: Test Check
  severity: high
  category: test
checks:
  - type: metadata_match
    match:
      key: value
remediation: Fix it
`), 0644)

	tmpl, err := LoadTemplate(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl.ID != "test-check" {
		t.Errorf("ID = %q, want test-check", tmpl.ID)
	}
	if tmpl.Info.Severity != "high" {
		t.Errorf("Severity = %q, want high", tmpl.Info.Severity)
	}
}

func TestLoadTemplate_DefaultSeverity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	os.WriteFile(path, []byte(`
id: test
info:
  name: Test
checks: []
`), 0644)

	tmpl, err := LoadTemplate(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl.Info.Severity != "info" {
		t.Errorf("Severity = %q, want info (default)", tmpl.Info.Severity)
	}
}

func TestLoadTemplate_MissingID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	os.WriteFile(path, []byte(`
info:
  name: Test
`), 0644)

	_, err := LoadTemplate(path)
	if err == nil {
		t.Fatal("expected error for missing ID")
	}
}

func TestLoadTemplate_MissingName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	os.WriteFile(path, []byte(`
id: test
info:
  severity: high
`), 0644)

	_, err := LoadTemplate(path)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestLoadTemplatesDir(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.yaml", "b.yml", "c.txt"} {
		content := `id: ` + name + "\ninfo:\n  name: " + name
		os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
	}

	templates, err := LoadTemplatesDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(templates) != 2 {
		t.Errorf("got %d templates, want 2 (yaml + yml only)", len(templates))
	}
}

func TestRunner_MetadataMatch(t *testing.T) {
	tmpl := &CheckTemplate{
		ID:   "s3-public",
		Info: Info{Name: "S3 Public", Severity: "critical", Category: "storage"},
		Checks: []Check{
			{Type: "metadata_match", Match: map[string]interface{}{"public_access": "true"}},
		},
	}

	runner := NewRunner([]*CheckTemplate{tmpl})

	// Should match
	asset := AssetContext{
		Type:     "bucket",
		Value:    "my-bucket",
		Metadata: map[string]interface{}{"public_access": "true"},
	}
	results := runner.RunAll(context.Background(), asset)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if !results[0].Matched {
		t.Error("expected Matched = true")
	}
	if results[0].Evidence["public_access"] != "true" {
		t.Error("expected evidence for public_access")
	}

	// Should not match
	asset.Metadata["public_access"] = "false"
	results = runner.RunAll(context.Background(), asset)
	if len(results) != 0 {
		t.Errorf("got %d results, want 0", len(results))
	}
}

func TestRunner_MetadataWildcard(t *testing.T) {
	tmpl := &CheckTemplate{
		ID:   "check",
		Info: Info{Name: "Check", Severity: "info"},
		Checks: []Check{
			{Type: "metadata_match", Match: map[string]interface{}{"region": "*"}},
		},
	}

	runner := NewRunner([]*CheckTemplate{tmpl})
	asset := AssetContext{
		Metadata: map[string]interface{}{"region": "us-east-1"},
	}
	results := runner.RunAll(context.Background(), asset)
	if len(results) != 1 {
		t.Fatal("wildcard should match any value")
	}
}

func TestRunner_MetadataNilMetadata(t *testing.T) {
	tmpl := &CheckTemplate{
		ID:   "check",
		Info: Info{Name: "Check", Severity: "info"},
		Checks: []Check{
			{Type: "metadata_match", Match: map[string]interface{}{"key": "val"}},
		},
	}

	runner := NewRunner([]*CheckTemplate{tmpl})
	results := runner.RunAll(context.Background(), AssetContext{})
	if len(results) != 0 {
		t.Error("nil metadata should not match")
	}
}

func TestRunner_TagMatch(t *testing.T) {
	tmpl := &CheckTemplate{
		ID:   "missing-env",
		Info: Info{Name: "Missing env tag", Severity: "medium"},
		Checks: []Check{
			{Type: "tag_match", Match: map[string]interface{}{"environment": "!exists"}},
		},
	}

	runner := NewRunner([]*CheckTemplate{tmpl})

	// Should match when tag is missing
	asset := AssetContext{Tags: map[string]string{"team": "backend"}}
	results := runner.RunAll(context.Background(), asset)
	if len(results) != 1 {
		t.Fatal("expected match for missing tag")
	}

	// Should not match when tag exists
	asset.Tags["environment"] = "production"
	results = runner.RunAll(context.Background(), asset)
	if len(results) != 0 {
		t.Error("should not match when tag exists")
	}
}

func TestRunner_TagMatchNilTags(t *testing.T) {
	tmpl := &CheckTemplate{
		ID:   "check",
		Info: Info{Name: "Check", Severity: "info"},
		Checks: []Check{
			{Type: "tag_match", Match: map[string]interface{}{"key": "val"}},
		},
	}

	runner := NewRunner([]*CheckTemplate{tmpl})
	results := runner.RunAll(context.Background(), AssetContext{})
	if len(results) != 0 {
		t.Error("nil tags should not match")
	}
}

func TestRunner_AssetType(t *testing.T) {
	tmpl := &CheckTemplate{
		ID:   "check",
		Info: Info{Name: "IP Check", Severity: "info"},
		Checks: []Check{
			{Type: "asset_type", Match: map[string]interface{}{"type": "ip"}},
		},
	}

	runner := NewRunner([]*CheckTemplate{tmpl})

	results := runner.RunAll(context.Background(), AssetContext{Type: "ip"})
	if len(results) != 1 {
		t.Fatal("expected match for ip type")
	}

	results = runner.RunAll(context.Background(), AssetContext{Type: "domain"})
	if len(results) != 0 {
		t.Error("should not match domain type")
	}
}

func TestRunner_ValuePattern(t *testing.T) {
	tmpl := &CheckTemplate{
		ID:   "check",
		Info: Info{Name: "Pattern Check", Severity: "info"},
		Checks: []Check{
			{Type: "value_pattern", Match: map[string]interface{}{"contains": ".internal"}},
		},
	}

	runner := NewRunner([]*CheckTemplate{tmpl})

	results := runner.RunAll(context.Background(), AssetContext{Value: "db.internal.corp"})
	if len(results) != 1 {
		t.Fatal("expected match for contains pattern")
	}

	results = runner.RunAll(context.Background(), AssetContext{Value: "public.example.com"})
	if len(results) != 0 {
		t.Error("should not match")
	}
}

func TestRunner_ValuePatternPrefix(t *testing.T) {
	tmpl := &CheckTemplate{
		ID:   "check",
		Info: Info{Name: "Check", Severity: "info"},
		Checks: []Check{
			{Type: "value_pattern", Match: map[string]interface{}{"prefix": "admin"}},
		},
	}

	runner := NewRunner([]*CheckTemplate{tmpl})
	results := runner.RunAll(context.Background(), AssetContext{Value: "admin.example.com"})
	if len(results) != 1 {
		t.Fatal("expected match for prefix")
	}
}

func TestRunner_ValuePatternSuffix(t *testing.T) {
	tmpl := &CheckTemplate{
		ID:   "check",
		Info: Info{Name: "Check", Severity: "info"},
		Checks: []Check{
			{Type: "value_pattern", Match: map[string]interface{}{"suffix": ".dev"}},
		},
	}

	runner := NewRunner([]*CheckTemplate{tmpl})
	results := runner.RunAll(context.Background(), AssetContext{Value: "app.dev"})
	if len(results) != 1 {
		t.Fatal("expected match for suffix")
	}
}

func TestRunner_UnknownCheckType(t *testing.T) {
	tmpl := &CheckTemplate{
		ID:   "check",
		Info: Info{Name: "Check", Severity: "info"},
		Checks: []Check{
			{Type: "unknown_type", Match: map[string]interface{}{}},
		},
	}

	runner := NewRunner([]*CheckTemplate{tmpl})
	results := runner.RunAll(context.Background(), AssetContext{})
	if len(results) != 0 {
		t.Error("unknown type should not match")
	}
}

func TestAssetContextFromJSON(t *testing.T) {
	ac := AssetContextFromJSON("bucket", "my-bucket",
		`{"region":"us-east-1","public_access":true}`,
		`{"team":"backend"}`)

	if ac.Type != "bucket" {
		t.Errorf("Type = %q", ac.Type)
	}
	if ac.Value != "my-bucket" {
		t.Errorf("Value = %q", ac.Value)
	}
	if ac.Metadata["region"] != "us-east-1" {
		t.Error("metadata not parsed")
	}
	if ac.Tags["team"] != "backend" {
		t.Error("tags not parsed")
	}
}

func TestAssetContextFromJSON_Empty(t *testing.T) {
	ac := AssetContextFromJSON("ip", "1.2.3.4", "{}", "{}")
	if ac.Metadata != nil {
		t.Error("expected nil metadata for empty JSON")
	}
	if ac.Tags != nil {
		t.Error("expected nil tags for empty JSON")
	}
}

func TestRunner_MultipleChecks_FirstMatchWins(t *testing.T) {
	tmpl := &CheckTemplate{
		ID:   "check",
		Info: Info{Name: "Check", Severity: "high"},
		Checks: []Check{
			{Type: "metadata_match", Match: map[string]interface{}{"a": "1"}},
			{Type: "metadata_match", Match: map[string]interface{}{"b": "2"}},
		},
	}

	runner := NewRunner([]*CheckTemplate{tmpl})

	// Only second check matches
	asset := AssetContext{Metadata: map[string]interface{}{"b": "2"}}
	results := runner.RunAll(context.Background(), asset)
	if len(results) != 1 {
		t.Fatal("expected one match")
	}
}
