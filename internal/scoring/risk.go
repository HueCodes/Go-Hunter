package scoring

import (
	"time"
)

type SeverityCount struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

type RiskInput struct {
	Findings     SeverityCount
	IsPublic     bool
	DiscoveredAt time.Time
	Tags         map[string]string
}

type RiskScore struct {
	Score       float64 `json:"score"`
	Grade       string  `json:"grade"`
	Breakdown   Breakdown `json:"breakdown"`
}

type Breakdown struct {
	FindingsScore float64 `json:"findings_score"`
	ExposureScore float64 `json:"exposure_score"`
	AgeScore      float64 `json:"age_score"`
	Total         float64 `json:"total"`
}

// Calculate computes a risk score from 0 (no risk) to 100 (critical risk).
func Calculate(input RiskInput) RiskScore {
	// Findings contribute up to 60 points
	findingsScore := float64(input.Findings.Critical)*15 +
		float64(input.Findings.High)*8 +
		float64(input.Findings.Medium)*3 +
		float64(input.Findings.Low)*1 +
		float64(input.Findings.Info)*0.1
	if findingsScore > 60 {
		findingsScore = 60
	}

	// Public exposure contributes up to 25 points
	var exposureScore float64
	if input.IsPublic {
		exposureScore = 25
	}

	// Asset age: new assets get higher score (unknown attack surface)
	// Up to 15 points for assets discovered in the last 7 days
	var ageScore float64
	daysSinceDiscovery := time.Since(input.DiscoveredAt).Hours() / 24
	if daysSinceDiscovery < 1 {
		ageScore = 15
	} else if daysSinceDiscovery < 7 {
		ageScore = 10
	} else if daysSinceDiscovery < 30 {
		ageScore = 5
	}

	total := findingsScore + exposureScore + ageScore
	if total > 100 {
		total = 100
	}

	return RiskScore{
		Score: total,
		Grade: scoreToGrade(total),
		Breakdown: Breakdown{
			FindingsScore: findingsScore,
			ExposureScore: exposureScore,
			AgeScore:      ageScore,
			Total:         total,
		},
	}
}

func scoreToGrade(score float64) string {
	switch {
	case score >= 80:
		return "F"
	case score >= 60:
		return "D"
	case score >= 40:
		return "C"
	case score >= 20:
		return "B"
	default:
		return "A"
	}
}

// CalculateOrgRisk aggregates risk scores for an organization.
func CalculateOrgRisk(assetScores []RiskScore) RiskScore {
	if len(assetScores) == 0 {
		return RiskScore{Score: 0, Grade: "A"}
	}

	var total float64
	var maxScore float64
	for _, s := range assetScores {
		total += s.Score
		if s.Score > maxScore {
			maxScore = s.Score
		}
	}

	// Org risk is weighted: 60% max asset risk + 40% average risk
	avgScore := total / float64(len(assetScores))
	orgScore := maxScore*0.6 + avgScore*0.4
	if orgScore > 100 {
		orgScore = 100
	}

	return RiskScore{
		Score: orgScore,
		Grade: scoreToGrade(orgScore),
	}
}
