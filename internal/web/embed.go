package web

import (
	"embed"
	"html/template"
	"io/fs"
)

//go:embed templates
var TemplatesFS embed.FS

//go:embed static
var StaticFS embed.FS

// LoadTemplates parses all templates from the embedded filesystem
func LoadTemplates() (*template.Template, error) {
	tmpl := template.New("")

	// Parse layout templates
	entries, err := fs.ReadDir(TemplatesFS, "templates/layouts")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			content, err := fs.ReadFile(TemplatesFS, "templates/layouts/"+entry.Name())
			if err != nil {
				return nil, err
			}
			_, err = tmpl.Parse(string(content))
			if err != nil {
				return nil, err
			}
		}
	}

	// Parse page templates
	entries, err = fs.ReadDir(TemplatesFS, "templates/pages")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			content, err := fs.ReadFile(TemplatesFS, "templates/pages/"+entry.Name())
			if err != nil {
				return nil, err
			}
			_, err = tmpl.New(entry.Name()).Parse(string(content))
			if err != nil {
				return nil, err
			}
		}
	}

	return tmpl, nil
}

// GetStaticFS returns the static file system for serving static files
func GetStaticFS() (fs.FS, error) {
	return fs.Sub(StaticFS, "static")
}
