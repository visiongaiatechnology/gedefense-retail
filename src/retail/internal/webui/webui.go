// Package webui embeds the GeDefense Retail dashboard assets.
//
// The dashboard is a build-free single-page application: hand-written CSS
// (layered design tokens) and native ES modules, served straight from this
// embedded file system. It never talks to third-party origins, loads no CDN
// assets and contains no inline script or style, so it satisfies the API
// Content-Security-Policy (`script-src 'self'; style-src 'self'`).
//
// Layout of the embedded tree:
//
//	web/index.html          application shell (no inline script/style)
//	web/css/*.css           @layer reset, tokens, base, layout, components, views
//	web/js/*.js             ES modules (core, components, views)
//	web/mock/*              offline design-QA harness + JSON fixtures
//	web/assets/             brand assets referenced by the UI
package webui

import (
	"embed"
	"io/fs"
)

// all:web keeps the mock/ design-QA harness inside the binary as well. It is
// only reachable by an explicit path and never loaded by the production shell;
// keeping it embedded makes offline design review possible without a backend.
//
//go:embed all:web
var embedded embed.FS

// webFS is the dashboard tree rooted at "web" (so index.html lives at the root
// of the returned file system, as expected by internal/api's static handler).
var webFS fs.FS

func init() {
	sub, err := fs.Sub(embedded, "web")
	if err != nil {
		// fs.Sub only fails for an invalid path; "web" is a compile-time
		// constant. Falling back to the unrooted tree keeps the server alive
		// (fail-safe: the dashboard may 404, the detection pipeline must not).
		webFS = embedded
		return
	}
	webFS = sub
}

// FS returns the embedded dashboard file tree rooted at the web directory.
// The returned file system is read-only and safe for concurrent use.
func FS() fs.FS { return webFS }
