package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// staticContentTypes is the allowlist of extensions the UI layer may serve.
// Anything else is a 404: the embedded tree must never expose source, dotfiles or
// an accidentally embedded secret.
var staticContentTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".json":        "application/json; charset=utf-8",
	".map":         "application/json; charset=utf-8",
	".png":         "image/png",
	".jpg":         "image/jpeg",
	".jpeg":        "image/jpeg",
	".webp":        "image/webp",
	".gif":         "image/gif",
	".svg":         "image/svg+xml",
	".ico":         "image/x-icon",
	".woff":        "font/woff",
	".woff2":       "font/woff2",
	".ttf":         "font/ttf",
	".txt":         "text/plain; charset=utf-8",
	".webmanifest": "application/manifest+json",
}

// serveStatic delivers the embedded UI. There is no directory listing, no path
// traversal and no extension outside the allowlist.
func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		s.fail(w, r, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}
	if s.deps.Static == nil {
		s.fail(w, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}

	if r.URL.Path == "/setup" || strings.HasPrefix(r.URL.Path, "/setup/") {
		if s.setup == nil || s.setup.Completed() {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		r.URL.Path = "/"
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = "index.html"
	}
	if !fs.ValidPath(name) || strings.Contains(name, "..") {
		s.fail(w, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	extension := strings.ToLower(path.Ext(name))
	contentType, allowed := staticContentTypes[extension]
	if !allowed {
		s.fail(w, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}

	file, err := s.deps.Static.Open(name)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			s.logger.Warn("close static file failed", "request_id", requestID(r), "file", name, "error", cerr)
		}
	}()

	info, err := file.Stat()
	if err != nil || info.IsDir() {
		s.fail(w, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if info.Size() > maxStaticBytes {
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	data, err := fs.ReadFile(s.deps.Static, name)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, werr := w.Write(data); werr != nil {
		s.logger.Warn("write static file failed", "request_id", requestID(r), "file", name, "error", werr)
	}
}
