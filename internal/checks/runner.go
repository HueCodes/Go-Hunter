package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
)

type CheckResult struct {
	TemplateID  string            `json:"template_id"`
	Name        string            `json:"name"`
	Severity    string            `json:"severity"`
	Category    string            `json:"category"`
	Matched     bool              `json:"matched"`
	Evidence    map[string]string `json:"evidence,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
}

type AssetContext struct {
	Type     string
	Value    string
	Metadata map[string]interface{}
	Tags     map[string]string
}

type Runner struct {
	templates []*CheckTemplate
}

func NewRunner(templates []*CheckTemplate) *Runner {
	return &Runner{templates: templates}
}

func (r *Runner) RunAll(ctx context.Context, asset AssetContext) []CheckResult {
	var results []CheckResult
	for _, tmpl := range r.templates {
		result := r.RunTemplate(ctx, tmpl, asset)
		if result.Matched {
			results = append(results, result)
		}
	}
	return results
}

func (r *Runner) RunTemplate(_ context.Context, tmpl *CheckTemplate, asset AssetContext) CheckResult {
	result := CheckResult{
		TemplateID:  tmpl.ID,
		Name:        tmpl.Info.Name,
		Severity:    tmpl.Info.Severity,
		Category:    tmpl.Info.Category,
		Remediation: tmpl.Remediation,
		Evidence:    make(map[string]string),
	}

	for _, check := range tmpl.Checks {
		if matchCheck(check, asset, result.Evidence) {
			result.Matched = true
			return result
		}
	}

	return result
}

func matchCheck(check Check, asset AssetContext, evidence map[string]string) bool {
	switch check.Type {
	case "metadata_match":
		return matchMetadata(check.Match, asset.Metadata, evidence)
	case "tag_match":
		return matchTags(check.Match, asset.Tags, evidence)
	case "asset_type":
		return matchAssetType(check.Match, asset)
	case "value_pattern":
		return matchValuePattern(check.Match, asset, evidence)
	default:
		slog.Warn("unknown check type", "type", check.Type)
		return false
	}
}

func matchMetadata(match map[string]interface{}, metadata map[string]interface{}, evidence map[string]string) bool {
	if metadata == nil {
		return false
	}

	for key, expected := range match {
		actual, ok := metadata[key]
		if !ok {
			return false
		}

		expectedStr := fmt.Sprintf("%v", expected)
		actualStr := fmt.Sprintf("%v", actual)

		if expectedStr == "*" {
			evidence[key] = actualStr
			continue
		}

		if actualStr != expectedStr {
			return false
		}
		evidence[key] = actualStr
	}
	return true
}

func matchTags(match map[string]interface{}, tags map[string]string, evidence map[string]string) bool {
	if tags == nil {
		return false
	}

	for key, expected := range match {
		actual, ok := tags[key]
		if !ok {
			if fmt.Sprintf("%v", expected) == "!exists" {
				evidence[key] = "missing"
				continue
			}
			return false
		}

		expectedStr := fmt.Sprintf("%v", expected)
		if expectedStr == "*" {
			evidence[key] = actual
			continue
		}
		if actual != expectedStr {
			return false
		}
		evidence[key] = actual
	}
	return true
}

func matchAssetType(match map[string]interface{}, asset AssetContext) bool {
	typeVal, ok := match["type"]
	if !ok {
		return false
	}
	return fmt.Sprintf("%v", typeVal) == asset.Type
}

func matchValuePattern(match map[string]interface{}, asset AssetContext, evidence map[string]string) bool {
	pattern, ok := match["contains"]
	if ok {
		if strings.Contains(asset.Value, fmt.Sprintf("%v", pattern)) {
			evidence["value"] = asset.Value
			evidence["pattern"] = fmt.Sprintf("%v", pattern)
			return true
		}
	}

	prefix, ok := match["prefix"]
	if ok {
		if strings.HasPrefix(asset.Value, fmt.Sprintf("%v", prefix)) {
			evidence["value"] = asset.Value
			evidence["prefix"] = fmt.Sprintf("%v", prefix)
			return true
		}
	}

	suffix, ok := match["suffix"]
	if ok {
		if strings.HasSuffix(asset.Value, fmt.Sprintf("%v", suffix)) {
			evidence["value"] = asset.Value
			evidence["suffix"] = fmt.Sprintf("%v", suffix)
			return true
		}
	}

	return false
}

func AssetContextFromJSON(assetType, value, metadataJSON, tagsJSON string) AssetContext {
	ac := AssetContext{
		Type:  assetType,
		Value: value,
	}

	if metadataJSON != "" && metadataJSON != "{}" {
		_ = json.Unmarshal([]byte(metadataJSON), &ac.Metadata)
	}
	if tagsJSON != "" && tagsJSON != "{}" {
		_ = json.Unmarshal([]byte(tagsJSON), &ac.Tags)
	}

	return ac
}
