package server

import (
	"net/http"
	"strings"
	"testing"

	"nabuauth/internal/config"
)

// Signing in with Google is offered where it can actually be completed, and
// nowhere else. A button that starts an exchange this deployment cannot finish
// is worse than no button: it fails after the visitor has already handed their
// Google account over.

func googleProvider() config.Provider {
	return config.Provider{
		ID:           "google",
		Name:         "Google",
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserinfoURL:  "https://openidconnect.googleapis.com/v1/userinfo",
		ClientID:     "test-client-id.apps.googleusercontent.com",
		Scopes:       []string{"openid", "email", "profile"},
		SecretEnv:    "TEST_SECRET_GOOGLE",
	}
}

func TestTheGoogleButtonIsOnTheFormOnceItIsConfigured(t *testing.T) {
	t.Setenv("TEST_SECRET_GOOGLE", "test-google-secret")

	ts, _ := newTestServer(t, func(cfg *config.Config) {
		cfg.LoginMethods = []config.Provider{googleProvider()}
	})

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	defer resp.Body.Close()

	body := readBody(t, resp)

	for _, want := range []string{`href="/login/google"`, "Continue with Google", "provider-google", "provider-mark"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the form is missing %s: %s", want, truncate(body))
		}
	}
}

func TestTheGoogleButtonIsAbsentWithoutItsSecret(t *testing.T) {
	// Client id in the file, secret nowhere — which is exactly the state a
	// deployment is in between listing the provider and being given its keys.
	ts, _ := newTestServer(t, func(cfg *config.Config) {
		cfg.LoginMethods = []config.Provider{googleProvider()}
	})

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	defer resp.Body.Close()

	if body := readBody(t, resp); strings.Contains(body, "Continue with Google") {
		t.Fatalf("an unconfigured provider was offered: %s", truncate(body))
	}
}

func TestAnUnconfiguredProviderRouteIsNotThere(t *testing.T) {
	ts, _ := newTestServer(t, func(cfg *config.Config) {
		cfg.LoginMethods = []config.Provider{googleProvider()}
	})

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	resp, err := client.Get(ts.URL + "/login/google")
	if err != nil {
		t.Fatalf("get provider: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404 for a provider this deployment cannot complete", resp.StatusCode)
	}
}

func TestTheConfiguredProviderSendsTheBrowserToGoogle(t *testing.T) {
	t.Setenv("TEST_SECRET_GOOGLE", "test-google-secret")

	ts, _ := newTestServer(t, func(cfg *config.Config) {
		cfg.LoginMethods = []config.Provider{googleProvider()}
	})

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	resp, err := client.Get(ts.URL + "/login/google")
	if err != nil {
		t.Fatalf("get provider: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want a redirect to Google", resp.StatusCode)
	}

	location := resp.Header.Get("Location")

	// The redirect_uri is the one Google has to be told about, and it is built
	// from the issuer — so a deployment that moves hostname does not silently
	// keep sending people back to the old one.
	for _, want := range []string{
		"https://accounts.google.com/o/oauth2/v2/auth",
		"redirect_uri=http%3A%2F%2Fnabuauth.test%2Flogin%2Fgoogle%2Fcallback",
		"client_id=test-client-id",
	} {
		if !strings.Contains(location, want) {
			t.Fatalf("the redirect is missing %s: %s", want, location)
		}
	}
}
