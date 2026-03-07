package scoring

import (
	"testing"
	"time"
)

func TestCalculate_NoFindings(t *testing.T) {
	score := Calculate(RiskInput{
		DiscoveredAt: time.Now().Add(-90 * 24 * time.Hour),
	})
	if score.Score != 0 {
		t.Errorf("score = %f, want 0", score.Score)
	}
	if score.Grade != "A" {
		t.Errorf("grade = %s, want A", score.Grade)
	}
}

func TestCalculate_CriticalFindings(t *testing.T) {
	score := Calculate(RiskInput{
		Findings:     SeverityCount{Critical: 3},
		IsPublic:     true,
		DiscoveredAt: time.Now().Add(-90 * 24 * time.Hour),
	})
	// 3*15 = 45 findings + 25 exposure = 70
	if score.Score != 70 {
		t.Errorf("score = %f, want 70", score.Score)
	}
	if score.Grade != "D" {
		t.Errorf("grade = %s, want D", score.Grade)
	}
}

func TestCalculate_NewAsset(t *testing.T) {
	score := Calculate(RiskInput{
		DiscoveredAt: time.Now(),
	})
	if score.Breakdown.AgeScore != 15 {
		t.Errorf("age score = %f, want 15", score.Breakdown.AgeScore)
	}
}

func TestCalculate_PublicExposure(t *testing.T) {
	score := Calculate(RiskInput{
		IsPublic:     true,
		DiscoveredAt: time.Now().Add(-90 * 24 * time.Hour),
	})
	if score.Breakdown.ExposureScore != 25 {
		t.Errorf("exposure score = %f, want 25", score.Breakdown.ExposureScore)
	}
}

func TestCalculate_MaxCap(t *testing.T) {
	score := Calculate(RiskInput{
		Findings:     SeverityCount{Critical: 10, High: 10},
		IsPublic:     true,
		DiscoveredAt: time.Now(),
	})
	if score.Score > 100 {
		t.Errorf("score = %f, should be capped at 100", score.Score)
	}
}

func TestScoreToGrade(t *testing.T) {
	tests := []struct {
		score float64
		grade string
	}{
		{0, "A"},
		{19, "A"},
		{20, "B"},
		{39, "B"},
		{40, "C"},
		{59, "C"},
		{60, "D"},
		{79, "D"},
		{80, "F"},
		{100, "F"},
	}

	for _, tt := range tests {
		got := scoreToGrade(tt.score)
		if got != tt.grade {
			t.Errorf("scoreToGrade(%f) = %s, want %s", tt.score, got, tt.grade)
		}
	}
}

func TestCalculateOrgRisk_Empty(t *testing.T) {
	score := CalculateOrgRisk(nil)
	if score.Score != 0 {
		t.Errorf("score = %f, want 0", score.Score)
	}
}

func TestCalculateOrgRisk_MultipleAssets(t *testing.T) {
	scores := []RiskScore{
		{Score: 80},
		{Score: 40},
		{Score: 20},
	}
	org := CalculateOrgRisk(scores)
	// max=80, avg=46.67, result = 80*0.6 + 46.67*0.4 = 48 + 18.67 = 66.67
	if org.Score < 60 || org.Score > 70 {
		t.Errorf("org score = %f, expected ~66.67", org.Score)
	}
}
