package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler returns an HTTP handler for serving the web UI
func Handler() (http.Handler, error) {
	// Strip the "dist" prefix from embedded files
	fsys, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, err
	}

	fileServer := http.FileServer(http.FS(fsys))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// API ve WebSocket isteklerini yönlendirme
		if strings.HasPrefix(r.URL.Path, "/api/") ||
			strings.HasPrefix(r.URL.Path, "/ws") {
			http.NotFound(w, r)
			return
		}

		// Check if the file exists in the embedded FS
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}

		// Try to open the file (strip leading slash for embed FS compatibility)
		_, err := fsys.Open(strings.TrimPrefix(path, "/"))
		if err != nil {
			// File not found, serve index.html for SPA routing
			r.URL.Path = "/"
		}

		fileServer.ServeHTTP(w, r)
	}), nil
}

// FS returns the embedded filesystem for the web UI
func FS() (fs.FS, error) {
	return fs.Sub(distFS, "dist")
}
