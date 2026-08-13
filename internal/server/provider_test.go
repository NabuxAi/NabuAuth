package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"nabuauth/internal/config"
)

// An external sign-in method is an ordinary OIDC client, so these run against a
// stub provider rather than a real one: what matters here is what this server
// does with what a provider says — including when it says something it should
// not be believed about.

// fakeProvider is a stand-in identity provider. Its userinfo response is
// whatever the test sets.
func fakeProvider(t *testing.T, profile map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostFormValue("code") == "" || r.PostFormValue("client_secret") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "provider-access-token", "token_type": "Bearer"})
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer provider-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, profile)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// withProvider registers the stub as a login method on the server under test.
func withProvider(idp *httptest.Server) func(*config.Config) {
	return func(cfg *config.Config) {
		cfg.LoginMethods = []config.Provider{{
			ID:           "stub",
			Name:         "Stub ID",
			AuthorizeURL: idp.URL + "/authorize",
			TokenURL:     idp.URL + "/token",
			UserinfoURL:  idp.URL + "/userinfo",
			ClientID:     "nabuauth-test",
			SecretEnv:    "TEST_PROVIDER_SECRET",
			Scopes:       []string{"openid", "email", "profile"},
		}}
	}
}

// startProviderSignIn follows the first hop and returns the state the server
// generated, along with a client holding the round-trip cookie.
func startProviderSignIn(t *testing.T, ts *httptest.Server, next string) (*http.Client, string) {
	t.Helper()
	client := &http.Client{
		Jar:           &cookieJar{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	target := ts.URL + "/login/stub"
	if next != "" {
		target += "?next=" + url.QueryEscape(next)
	}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("start provider sign-in: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want a redirect to the provider", resp.StatusCode)
	}
	away, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse provider redirect: %v", err)
	}
	return client, away.Query().Get("state")
}

func TestAVerifiedExternalIdentitySignsInAndIsGivenAnAccount(t *testing.T) {
	t.Setenv("TEST_PROVIDER_SECRET", "provider-secret")
	idp := fakeProvider(t, map[string]any{"email": "Someone@Nabuxai.com", "email_verified": true, "name": "Someone"})
	ts, st := newTestServer(t, withProvider(idp))

	client, state := startProviderSignIn(t, ts, "/dashboard")

	resp, err := client.Get(ts.URL + "/login/stub/callback?code=provider-code&state=" + state)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want a redirect into the account", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/dashboard" {
		t.Fatalf("landed on %q, want /dashboard", loc)
	}
	// Matched on the email, lower-cased, so the same person is one account
	// however the provider capitalises it.
	if _, err := st.UserByEmail(context.Background(), "someone@nabuxai.com"); err != nil {
		t.Fatalf("no account was created for the external identity: %v", err)
	}
}

func TestAnUnverifiedExternalEmailIsRefused(t *testing.T) {
	// Otherwise any provider that lets somebody type an address is a way into
	// the Nabu account that already uses it.
	t.Setenv("TEST_PROVIDER_SECRET", "provider-secret")
	idp := fakeProvider(t, map[string]any{"email": "user@nabuxai.com", "email_verified": false})
	ts, st := newTestServer(t, withProvider(idp))
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	client, state := startProviderSignIn(t, ts, "")

	resp, err := client.Get(ts.URL + "/login/stub/callback?code=provider-code&state=" + state)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("an unverified external email started a session")
		}
	}
}

func TestACallbackThisBrowserDidNotStartIsRefused(t *testing.T) {
	t.Setenv("TEST_PROVIDER_SECRET", "provider-secret")
	idp := fakeProvider(t, map[string]any{"email": "user@nabuxai.com", "email_verified": true})
	ts, _ := newTestServer(t, withProvider(idp))

	client, _ := startProviderSignIn(t, ts, "")

	resp, err := client.Get(ts.URL + "/login/stub/callback?code=provider-code&state=not-the-state")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.StatusCode)
	}
}

func TestAProviderWithNoSecretIsNotOffered(t *testing.T) {
	// A button that leads to an exchange the deployment cannot complete is worse
	// than no button at all.
	idp := fakeProvider(t, map[string]any{"email": "user@nabuxai.com", "email_verified": true})
	ts, _ := newTestServer(t, withProvider(idp))

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	defer resp.Body.Close()
	if body := readBody(t, resp); strings.Contains(body, "Stub ID") {
		t.Fatal("an unconfigured provider is being offered on the form")
	}

	away, err := http.Get(ts.URL + "/login/stub")
	if err != nil {
		t.Fatalf("get provider start: %v", err)
	}
	defer away.Body.Close()
	if away.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404 for a provider this deployment has not configured", away.StatusCode)
	}
}

func TestTheFormOffersEveryConfiguredMethod(t *testing.T) {
	t.Setenv("TEST_PROVIDER_SECRET", "provider-secret")
	idp := fakeProvider(t, map[string]any{"email": "user@nabuxai.com", "email_verified": true})
	ts, _ := newTestServer(t, withProvider(idp))

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	defer resp.Body.Close()

	body := readBody(t, resp)
	if !strings.Contains(body, "Stub ID") || !strings.Contains(body, "/login/stub") {
		t.Fatalf("the configured method is not on the form: %s", body)
	}
}
