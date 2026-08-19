package server

import (
	"net/http"
	"net/url"
	"strings"
)

// Browser clients hold no secret, so they run the token exchange from the page
// itself: NabuPilot's office posts to /oauth/token and reads /oauth/userinfo
// straight from https://pilot.nabuxai.com. Without CORS headers the browser
// sends those requests and then refuses to let the page read the answer, and
// the preflight for the Authorization header got a 405 from the mux — so a
// sign-in completed here and died on the way back.
//
// Only the endpoints a browser client legitimately calls are opened, and only
// to the origins of the public clients this deployment registered. Confidential
// clients exchange codes from their own servers, where CORS does not apply, so
// nothing else gains an origin here. Credentials are never allowed: these
// endpoints authenticate by bearer token or client id, never by cookie, and
// allowing cookies would turn the session into a cross-origin capability.

// corsPaths are the endpoints a browser-based client has to reach directly.
var corsPaths = map[string]bool{
	"/.well-known/openid-configuration":       true,
	"/.well-known/oauth-authorization-server": true,
	"/oauth/jwks.json":                        true,
	"/oauth/token":                            true,
	"/oauth/userinfo":                         true,
	"/oauth/revoke":                           true,
	"/api/v1/user":                            true,
}

// publicClientOrigins collects the web origin of every redirect URI belonging to
// a public client. A registered redirect URI is already a statement that this
// origin is the app, so it needs no second list to drift from apps.yaml.
func (s *Server) publicClientOrigins() map[string]bool {
	origins := map[string]bool{}
	for _, app := range s.cfg.Apps {
		if !app.Public {
			continue
		}
		for _, raw := range app.RedirectURIs {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme == "" || u.Host == "" {
				continue
			}
			origins[strings.ToLower(u.Scheme+"://"+u.Host)] = true
		}
	}
	return origins
}

// cors answers preflights and marks responses readable for the origins above.
func (s *Server) cors(next http.Handler) http.Handler {
	allowed := s.publicClientOrigins()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.ToLower(strings.TrimSuffix(r.Header.Get("Origin"), "/"))

		if origin != "" && allowed[origin] && corsPaths[r.URL.Path] {
			// Vary, or a cache hands one origin's response to another.
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "600")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		// A preflight for anything else is refused here rather than reaching the
		// mux, which answers OPTIONS with 405 and no explanation.
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
