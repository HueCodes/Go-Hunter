package checks

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type CheckTemplate struct {
	ID          string   `yaml:"id" json:"id"`
	Info        Info     `yaml:"info" json:"info"`
	Checks      []Check  `yaml:"checks" json:"checks"`
	Remediation string   `yaml:"remediation" json:"remediation"`
}

type Info struct {
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Severity    string   `yaml:"severity" json:"severity"`
	Category    string   `yaml:"category" json:"category"`
	Tags        []string `yaml:"tags" json:"tags"`
	References  []string `yaml:"references" json:"references"`
}

type Check struct {
	Type  string                 `yaml:"type" json:"type"`
	Match map[string]interface{} `yaml:"match" json:"match"`
}

func LoadTemplate(path string) (*CheckTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading check template %s: %w", path, err)
	}

	var tmpl CheckTemplate
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parsing check template %s: %w", path, err)
	}

	if tmpl.ID == "" {
		return nil, fmt.Errorf("check template %s: missing id", path)
	}
	if tmpl.Info.Name == "" {
		return nil, fmt.Errorf("check template %s: missing info.name", path)
	}
	if tmpl.Info.Severity == "" {
		tmpl.Info.Severity = "info"
	}

	return &tmpl, nil
}

func LoadTemplatesDir(dir string) ([]*CheckTemplate, error) {
	var templates []*CheckTemplate

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		tmpl, err := LoadTemplate(path)
		if err != nil {
			return err
		}
		templates = append(templates, tmpl)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return templates, nil
}
