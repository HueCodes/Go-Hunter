package compliance

import (
	"testing"
)

func TestGenerateReport_NoFindings(t *testing.T) {
	report := GenerateReport("cis-aws", nil)
	if report == nil {
		t.Fatal("expected report")
	}
	if report.FailedControls != 0 {
		t.Errorf("FailedControls = %d, want 0", report.FailedControls)
	}
	if report.Coverage != 100 {
		t.Errorf("Coverage = %f, want 100", report.Coverage)
	}
}

func TestGenerateReport_WithFindings(t *testing.T) {
	findings := []FindingInfo{
		{ID: "f1", Category: "encryption", Status: "open"},
		{ID: "f2", Category: "encryption", Status: "open"},
		{ID: "f3", Category: "network-security", Status: "open"},
		{ID: "f4", Category: "logging", Status: "fixed"}, // fixed, should not fail
	}

	report := GenerateReport("cis-aws", findings)
	if report == nil {
		t.Fatal("expected report")
	}
	if report.FailedControls == 0 {
		t.Error("expected some failed controls")
	}
	if report.PassedControls+report.FailedControls != report.TotalControls {
		t.Error("passed + failed should equal total")
	}
}

func TestGenerateReport_UnknownFramework(t *testing.T) {
	report := GenerateReport("unknown-framework", nil)
	if report != nil {
		t.Error("expected nil for unknown framework")
	}
}

func TestGenerateReport_AllFrameworks(t *testing.T) {
	for _, fw := range DefaultFrameworks() {
		report := GenerateReport(fw.ID, nil)
		if report == nil {
			t.Errorf("expected report for framework %s", fw.ID)
			continue
		}
		if report.Framework.ID != fw.ID {
			t.Errorf("framework ID = %q, want %q", report.Framework.ID, fw.ID)
		}
	}
}

func TestDefaultMappings_NotEmpty(t *testing.T) {
	mappings := DefaultMappings()
	if len(mappings) == 0 {
		t.Error("expected non-empty mappings")
	}
	for _, m := range mappings {
		if m.Category == "" {
			t.Error("mapping has empty category")
		}
		if len(m.Frameworks) == 0 {
			t.Errorf("mapping %q has no framework mappings", m.Category)
		}
	}
}

func TestGenerateReport_CoverageCalculation(t *testing.T) {
	// One control fails, rest pass
	findings := []FindingInfo{
		{ID: "f1", Category: "encryption", Status: "open"},
	}

	report := GenerateReport("soc2", findings)
	if report == nil {
		t.Fatal("expected report")
	}
	if report.Coverage >= 100 {
		t.Errorf("Coverage = %f, should be < 100 with open findings", report.Coverage)
	}
	if report.Coverage <= 0 {
		t.Errorf("Coverage = %f, should be > 0 with only one failing category", report.Coverage)
	}
}
