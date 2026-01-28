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
// Each page gets its own template set with the base layout
func LoadTemplates() (*template.Template, error) {
	// Read base layout
	baseContent, err := fs.ReadFile(TemplatesFS, "templates/layouts/base.html")
	if err != nil {
		return nil, err
	}

	// Create a template collection
	tmpl := template.New("")

	// Parse page templates - each page is a separate template with the base included
	entries, err := fs.ReadDir(TemplatesFS, "templates/pages")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			pageContent, err := fs.ReadFile(TemplatesFS, "templates/pages/"+entry.Name())
			if err != nil {
				return nil, err
			}

			// Create a new template for this page that includes base + page content
			// Parse base first, then page content which overrides the blocks
			pageTmpl := tmpl.New(entry.Name())
			_, err = pageTmpl.Parse(string(baseContent))
			if err != nil {
				return nil, err
			}
			_, err = pageTmpl.Parse(string(pageContent))
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
