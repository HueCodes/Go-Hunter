# ADR-002: HTMX + Alpine.js for Frontend

## Status

Accepted

## Context

Go-Hunter requires an interactive web dashboard for:

1. **Asset Management**: Viewing, filtering, and managing discovered assets
2. **Scan Execution**: Triggering scans and viewing progress in real-time
3. **Finding Review**: Reviewing security findings, updating statuses, adding notes
4. **Dashboard Statistics**: Displaying metrics with periodic updates
5. **Credential Management**: Securely managing cloud provider credentials

The dashboard needs to feel responsive and modern while remaining maintainable by a small team focused primarily on backend development.

### Requirements

- Interactive UI without full page reloads
- Real-time updates for scan progress
- Form validation and submission handling
- Responsive design for different screen sizes
- Maintainable by Go developers (minimal JavaScript expertise required)
- Fast initial page loads
- SEO-friendly (not critical but nice to have)

### Alternatives Considered

1. **React/Next.js**
   - Pros: Rich ecosystem, component reusability, large community
   - Cons: Separate build pipeline, Node.js dependency, significant JavaScript

2. **Vue.js + Nuxt**
   - Pros: Gentler learning curve than React, good documentation
   - Cons: Still requires separate frontend build, JavaScript focus

3. **Svelte/SvelteKit**
   - Pros: Less boilerplate than React, compiles to vanilla JS
   - Cons: Smaller ecosystem, still a JavaScript-centric approach

4. **Go + Templ**
   - Pros: Type-safe templates, Go-native
   - Cons: Less mature, requires additional library for interactivity

5. **HTMX + Alpine.js**
   - Pros: Server-side rendering, minimal JavaScript, Go template integration
   - Cons: Different mental model, less suitable for highly complex UIs

## Decision

We chose **HTMX** for server-driven interactivity combined with **Alpine.js** for client-side reactivity, styled with **Tailwind CSS**.

### Implementation Details

**Template Embedding** (`internal/web/embed.go`):
```go
//go:embed templates
var TemplatesFS embed.FS

//go:embed static
var StaticFS embed.FS

func LoadTemplates() (*template.Template, error) {
    tmpl := template.New("")
    // Parse layouts and pages from embedded filesystem
    // ...
    return tmpl, nil
}
```

**Dashboard Handler** (`internal/api/handlers/dashboard.go`):
```go
func (h *DashboardHandler) Index(w http.ResponseWriter, r *http.Request) {
    // Fetch stats scoped to user's organization
    orgID := middleware.GetOrganizationID(r.Context())

    var stats struct {
        TotalAssets   int64
        TotalFindings int64
        CriticalCount int64
        HighCount     int64
        ActiveScans   int64
    }

    h.db.Table("assets").Where("organization_id = ?", orgID).Count(&stats.TotalAssets)
    // ... more queries

    h.render(w, "dashboard.html", map[string]interface{}{
        "User":  user,
        "Stats": stats,
    })
}
```

**Static File Serving** (`internal/api/router.go`):
```go
if cfg.StaticFS != nil {
    fileServer := http.FileServer(http.FS(cfg.StaticFS))
    r.Handle("/static/*", http.StripPrefix("/static/", fileServer))
}
```

### HTMX Patterns Used

**1. Partial Page Updates**:
```html
<button hx-get="/api/v1/scans"
        hx-target="#scan-list"
        hx-swap="innerHTML">
    Refresh Scans
</button>
<div id="scan-list">
    <!-- Scan list rendered here -->
</div>
```

**2. Form Submissions**:
```html
<form hx-post="/api/v1/scans"
      hx-target="#scan-list"
      hx-swap="afterbegin">
    <input type="hidden" name="type" value="port_scan">
    <button type="submit">Start Scan</button>
</form>
```

**3. Polling for Updates**:
```html
<div hx-get="/api/v1/scans/{{.ID}}/status"
     hx-trigger="every 2s"
     hx-swap="outerHTML">
    Status: {{.Status}}
</div>
```

### Alpine.js Patterns Used

**1. Toggle States**:
```html
<div x-data="{ open: false }">
    <button @click="open = !open">Toggle Details</button>
    <div x-show="open">
        <!-- Expandable content -->
    </div>
</div>
```

**2. Form Validation**:
```html
<form x-data="{ valid: false }" @submit="valid && $el.submit()">
    <input x-model="email" @input="valid = email.includes('@')">
    <button :disabled="!valid">Submit</button>
</form>
```

## Consequences

### Positive

1. **Simpler Codebase**: No separate frontend repository, no Node.js build pipeline, no npm dependencies for the frontend.

2. **Go Template Integration**: Templates are rendered server-side with full access to Go's type system:
   ```go
   data := map[string]interface{}{
       "User":     user,
       "Findings": findings,
   }
   h.templates.ExecuteTemplate(w, "findings.html", data)
   ```

3. **Embedded Static Assets**: Using `embed.FS`, all static files are compiled into the binary:
   ```go
   //go:embed static
   var StaticFS embed.FS
   ```

4. **Less JavaScript to Maintain**: Most interactivity is handled by HTMX declaratively. Alpine.js is used only for client-side state that doesn't need server round-trips.

5. **Fast Initial Page Load**: Server-rendered HTML means content is immediately visible. No JavaScript bundle to download and execute before showing content.

6. **SEO-Friendly**: Search engines can index the HTML content directly.

7. **Progressive Enhancement**: Core functionality works without JavaScript. HTMX enhances the experience.

8. **Familiar Technology**: Go templates are well-documented and familiar to Go developers.

### Negative

1. **Different Mental Model**: Developers familiar with React/Vue may find HTMX's server-driven approach unfamiliar initially.

2. **Limited Client-Side State**: Complex client-side interactions (drag-and-drop, rich text editing) would require additional JavaScript or libraries.

3. **More Server Requests**: HTMX makes HTTP requests for partial updates, increasing server load compared to client-side state management.

4. **Template Duplication**: Some HTML may be duplicated between full page renders and partial responses.

5. **Less Rich Ecosystem**: Fewer pre-built components compared to React's ecosystem. However, Tailwind UI provides sufficient components.

6. **Real-Time Limitations**: WebSocket support exists but is less straightforward than in SPA frameworks. We use polling for scan status updates.

### When to Reconsider

This decision should be revisited if:
- We need highly interactive features (collaborative editing, complex drag-and-drop)
- The dashboard requires offline functionality
- Client-side performance becomes critical (heavy data visualization)
- Team composition shifts to frontend specialists

## References

- [HTMX Documentation](https://htmx.org/docs/)
- [Alpine.js Documentation](https://alpinejs.dev/start-here)
- [Tailwind CSS](https://tailwindcss.com/)
- [Go html/template Package](https://pkg.go.dev/html/template)
- [Hypermedia Systems Book](https://hypermedia.systems/) - Conceptual foundation for HTMX
