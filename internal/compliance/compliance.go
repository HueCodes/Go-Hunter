package compliance

// Framework represents a compliance standard.
type Framework struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Controls    []Control `json:"controls"`
}

// Control is a single requirement within a framework.
type Control struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Categories  []string `json:"categories"`
}

// Mapping links a finding category to compliance controls.
type Mapping struct {
	Category   string            `json:"category"`
	Frameworks map[string]string `json:"frameworks"` // framework_id -> control_id
}

// Report summarizes compliance posture.
type Report struct {
	Framework      Framework       `json:"framework"`
	TotalControls  int             `json:"total_controls"`
	PassedControls int             `json:"passed_controls"`
	FailedControls int             `json:"failed_controls"`
	Coverage       float64         `json:"coverage_pct"`
	ControlStatus  []ControlStatus `json:"control_status"`
}

// ControlStatus is the pass/fail status of a single control.
type ControlStatus struct {
	Control      Control  `json:"control"`
	Status       string   `json:"status"` // "pass", "fail", "not_assessed"
	FindingCount int      `json:"finding_count"`
	FindingIDs   []string `json:"finding_ids,omitempty"`
}

// DefaultMappings returns built-in category-to-compliance-control mappings.
func DefaultMappings() []Mapping {
	return []Mapping{
		{Category: "encryption", Frameworks: map[string]string{
			"cis-aws":  "2.1",
			"soc2":     "CC6.1",
			"pci-dss":  "3.4",
			"nist-csf": "PR.DS-1",
		}},
		{Category: "access-control", Frameworks: map[string]string{
			"cis-aws":  "1.1",
			"soc2":     "CC6.1",
			"pci-dss":  "7.1",
			"nist-csf": "PR.AC-1",
		}},
		{Category: "network-security", Frameworks: map[string]string{
			"cis-aws":  "4.1",
			"soc2":     "CC6.6",
			"pci-dss":  "1.1",
			"nist-csf": "PR.AC-5",
		}},
		{Category: "logging", Frameworks: map[string]string{
			"cis-aws":  "3.1",
			"soc2":     "CC7.2",
			"pci-dss":  "10.1",
			"nist-csf": "DE.AE-3",
		}},
		{Category: "data-protection", Frameworks: map[string]string{
			"cis-aws":  "2.1",
			"soc2":     "CC6.1",
			"pci-dss":  "3.4",
			"nist-csf": "PR.DS-1",
		}},
		{Category: "vulnerability-management", Frameworks: map[string]string{
			"soc2":     "CC7.1",
			"pci-dss":  "6.1",
			"nist-csf": "ID.RA-1",
		}},
		{Category: "configuration", Frameworks: map[string]string{
			"cis-aws":  "5.1",
			"soc2":     "CC8.1",
			"pci-dss":  "2.2",
			"nist-csf": "PR.IP-1",
		}},
		{Category: "exposed-service", Frameworks: map[string]string{
			"cis-aws":  "4.1",
			"soc2":     "CC6.6",
			"pci-dss":  "1.2",
			"nist-csf": "PR.AC-5",
		}},
	}
}

// DefaultFrameworks returns built-in compliance frameworks.
func DefaultFrameworks() []Framework {
	return []Framework{
		{
			ID:          "cis-aws",
			Name:        "CIS AWS Foundations Benchmark",
			Description: "Center for Internet Security AWS Foundations Benchmark v1.5",
		},
		{
			ID:          "soc2",
			Name:        "SOC 2 Type II",
			Description: "AICPA Service Organization Control 2",
		},
		{
			ID:          "pci-dss",
			Name:        "PCI DSS v4.0",
			Description: "Payment Card Industry Data Security Standard",
		},
		{
			ID:          "nist-csf",
			Name:        "NIST Cybersecurity Framework",
			Description: "NIST CSF v1.1",
		},
	}
}

// FindingInfo is the minimal finding data needed for compliance mapping.
type FindingInfo struct {
	ID       string
	Category string
	Status   string // "open", "fixed", etc.
}

// GenerateReport generates a compliance report for a given framework.
func GenerateReport(frameworkID string, findings []FindingInfo) *Report {
	mappings := DefaultMappings()
	frameworks := DefaultFrameworks()

	var framework Framework
	for _, f := range frameworks {
		if f.ID == frameworkID {
			framework = f
			break
		}
	}
	if framework.ID == "" {
		return nil
	}

	// Build category -> control mapping for this framework
	controlFindings := make(map[string][]string) // control_id -> finding IDs
	controlFailed := make(map[string]bool)

	for _, m := range mappings {
		controlID, ok := m.Frameworks[frameworkID]
		if !ok {
			continue
		}

		for _, f := range findings {
			if f.Category == m.Category && f.Status == "open" {
				controlFindings[controlID] = append(controlFindings[controlID], f.ID)
				controlFailed[controlID] = true
			}
		}

		// Initialize even if no findings
		if _, exists := controlFindings[controlID]; !exists {
			controlFindings[controlID] = nil
		}
	}

	// Build report
	report := &Report{
		Framework:     framework,
		TotalControls: len(controlFindings),
	}

	for controlID, findingIDs := range controlFindings {
		status := "pass"
		if controlFailed[controlID] {
			status = "fail"
			report.FailedControls++
		} else {
			report.PassedControls++
		}

		report.ControlStatus = append(report.ControlStatus, ControlStatus{
			Control:      Control{ID: controlID},
			Status:       status,
			FindingCount: len(findingIDs),
			FindingIDs:   findingIDs,
		})
	}

	if report.TotalControls > 0 {
		report.Coverage = float64(report.PassedControls) / float64(report.TotalControls) * 100
	}

	return report
}
