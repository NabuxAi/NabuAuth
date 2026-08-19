package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"nabuauth/internal/config"
)

// corsServer is a Server with nothing but the app registry filled in — the CORS
// decision reads the config and nothing else, so this needs no database.
func corsServer() *Server {
	return &Server{cfg: &config.Config{
		Apps: []config.App{
			{
				ID:           "office",
				Public:       true,
				RedirectURIs: []string{"https://office.test/app/"},
			},
			{
				ID:           "backend-app",
				SecretEnv:    "SOME_SECRET",
				RedirectURIs: []string{"https://backend.test/callback"},
			},
		},
	}}
}

func corsProbe(t *testing.T, method, path, origin string) *http.Response {
	t.Helper()
	handler := corsServer().cors(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(method, path, nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

func TestAPublicClientsOriginMayReadTheTokenEndpoint(t *testing.T) {
	res := corsProbe(t, http.MethodPost, "/oauth/token", "https://office.test")

	if got := res.Header.Get("Access-Control-Allow-Origin"); got != "https://office.test" {
		t.Fatalf("Access-Control-Allow-Origin = %q; a browser client cannot read the "+
			"token response without it, so sign-in dies after the redirect back", got)
	}
	if got := res.Header.Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin: without it a cache serves one origin's response to another", got)
	}
}

func TestThePreflightForTheAuthorizationHeaderIsAnswered(t *testing.T) {
	res := corsProbe(t, http.MethodOptions, "/oauth/userinfo", "https://office.test")

	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204; the mux answers OPTIONS with 405 "+
			"and the browser then never sends the real request", res.StatusCode)
	}
	if got := res.Header.Get("Access-Control-Allow-Headers"); got == "" {
		t.Error("preflight allows no headers, so Authorization is refused")
	}
}

func TestAConfidentialClientsOriginGetsNothing(t *testing.T) {
	res := corsProbe(t, http.MethodPost, "/oauth/token", "https://backend.test")

	if got := res.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q for a confidential client; it "+
			"exchanges codes from its own server, where CORS does not apply", got)
	}
}

func TestAnUnregisteredOriginGetsNothing(t *testing.T) {
	res := corsProbe(t, http.MethodPost, "/oauth/token", "https://evil.test")

	if got := res.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q for an unregistered origin", got)
	}
}

func TestOnlyTheEndpointsABrowserClientNeedsAreOpened(t *testing.T) {
	// The sign-in form, the consent decision and the admin pages are cookie
	// authenticated; opening them cross-origin would make the session reachable
	// from another site.
	for _, path := range []string{"/login", "/oauth/authorize", "/admin/users", "/dashboard"} {
		res := corsProbe(t, http.MethodPost, path, "https://office.test")
		if got := res.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("%s answered with Access-Control-Allow-Origin %q", path, got)
		}
	}
}

func TestCredentialsAreNeverAllowed(t *testing.T) {
	res := corsProbe(t, http.MethodPost, "/oauth/token", "https://office.test")

	if got := res.Header.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("Access-Control-Allow-Credentials = %q; these endpoints authenticate "+
			"by bearer token, and allowing cookies would hand the session across origins", got)
	}
}
