package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// dist is populated by the production build before the Go binary is compiled.
// The checked-in fallback keeps normal Go tooling usable in a fresh checkout.
//
//go:embed all:dist
var embedded embed.FS

// Handler serves the embedded SPA. It deliberately refuses reserved server
// namespaces so an unknown API or access route can never be mistaken for HTML.
func Handler() http.Handler {
	dist, err := fs.Sub(embedded, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		for _, prefix := range []string{"/api/", "/access/", "/health/"} {
			if strings.HasPrefix(r.URL.Path, prefix) {
				http.NotFound(w, r)
				return
			}
		}

		requested := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if requested == "." || requested == "" {
			requested = "index.html"
		}
		if info, statErr := fs.Stat(dist, requested); statErr == nil && !info.IsDir() {
			setCacheHeader(w, requested)
			files.ServeHTTP(w, r)
			return
		}
		if path.Ext(requested) != "" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Cache-Control", "no-cache")
		request := r.Clone(r.Context())
		request.URL.Path = "/"
		files.ServeHTTP(w, request)
	})
}

func setCacheHeader(w http.ResponseWriter, name string) {
	if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
}
