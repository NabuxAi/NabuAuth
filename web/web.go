// Package web holds the embedded HTML templates and static assets for the
// NabuAuth account UI. Embedding them keeps the deployed artifact a single
// binary — there is no asset directory to forget to copy into the image.
package web

import (
	"embed"
	"html/template"
	"io/fs"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Templates parses every page template.
func Templates() (*template.Template, error) {
	return template.New("nabuauth").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
}

// Static returns the asset filesystem rooted at static/.
func Static() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// Only reachable if the embed directive above stops matching, which is a
		// build-time mistake rather than a runtime condition.
		panic(err)
	}
	return sub
}

var funcs = template.FuncMap{
	// initials renders an avatar fallback from a display name.
	"initials": func(name string) string {
		out := []rune{}
		prev := ' '
		for _, r := range name {
			if prev == ' ' && r != ' ' {
				out = append(out, r)
			}
			prev = r
			if len(out) == 2 {
				break
			}
		}
		return string(out)
	},
}
