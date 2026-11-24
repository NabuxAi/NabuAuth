package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"nabuauth/internal/config"
)

// An MCP gateway is registered in apps.yaml before its secret reaches the
// deployment. Until it does, NabuAuth must still boot and sign everybody else
// in; only that gateway's token exchange is refused.
func TestAnAppWithoutItsSecretYetDoesNotStopTheServer(t *testing.T) {
	ts, st := newTestServer(t, func(c *config.Config) {
		c.Apps = append(c.Apps, config.App{
			ID:           "pending-mcp",
			Name:         "Pending",
			Brand:        "telegram",
			URL:          "https://pending.test",
			RedirectURIs: []string{"https://pending.test/auth/nabu/callback"},
			Scopes:       []string{"openid", "profile", "email"},
			SecretEnv:    "NABUAUTH_SECRET_NOT_SET_IN_THIS_TEST",
		})
	})

	// Booting again — a redeploy with the variable still unset — is fine too.
	cfg := &config.Config{Scopes: config.DefaultScopes, Apps: []config.App{{
		ID: "pending-mcp", Name: "Pending", URL: "https://pending.test",
		RedirectURIs: []string{"https://pending.test/auth/nabu/callback"},
		Scopes:       []string{"openid"}, SecretEnv: "NABUAUTH_SECRET_NOT_SET_IN_THIS_TEST",
	}}}
	if err := SyncApps(context.Background(), cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("registering an app whose secret is not set failed: %v", err)
	}

	// Everybody else still signs in end to end.
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")
	code := grantCode(t, ts, client, "testapp", "http://app.test/callback", "openid profile", pkceChallenge, "S256")
	if tok := postForm(t, ts, "/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {pkceVerifier},
		"client_id": {"testapp"}, "client_secret": {"test-confidential-secret"},
	}); tok["access_token"] == nil {
		t.Fatalf("another app could not sign in: %v", tok)
	}

	// The pending gateway's exchange is refused, whatever secret it guesses.
	got := postForm(t, ts, "/oauth/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"pending-mcp"}, "client_secret": {""},
	})
	if got["error"] != "invalid_client" {
		t.Fatalf("a client with no secret configured was let in: %v", got)
	}
}

// Signing in for an app names the app, draws its platform mark, and the
// ecosystem half lists the gateways but never a hidden service client.
func TestTheSignInPageNamesTheAppItLeadsTo(t *testing.T) {
	ts, _ := newTestServer(t, func(c *config.Config) {
		c.Apps = append(c.Apps, config.App{
			ID:           "whatsapp-mcp",
			Name:         "WhatsApp",
			Brand:        "whatsapp",
			URL:          "https://wa.test",
			RedirectURIs: []string{"https://wa.test/auth/nabu/callback"},
			Scopes:       []string{"openid", "profile", "email"},
			SecretEnv:    "TEST_SECRET_CONFIDENTIAL",
		})
	})

	next := "/oauth/authorize?" + url.Values{
		"client_id": {"whatsapp-mcp"}, "redirect_uri": {"https://wa.test/auth/nabu/callback"},
		"response_type": {"code"}, "scope": {"openid profile email"},
	}.Encode()
	resp, err := http.Get(ts.URL + "/login?lang=en&next=" + url.QueryEscape(next))
	if err != nil {
		t.Fatalf("login page: %v", err)
	}
	page := readBody(t, resp)

	for _, want := range []string{
		"Sign in to continue to WhatsApp",
		`class="mark mark-whatsapp"`,
		`class="eco-row"`,
		`class="is-current" title="WhatsApp"`,
		">Test App<",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the sign-in page for an app is missing %q", want)
		}
	}
	if strings.Contains(page, "Metering Service") {
		t.Error("a hidden service client is listed in the ecosystem panel")
	}

	// The Persian page says the same in Persian.
	resp, err = http.Get(ts.URL + "/login?lang=fa&next=" + url.QueryEscape(next))
	if err != nil {
		t.Fatalf("login page: %v", err)
	}
	if page := readBody(t, resp); !strings.Contains(page, "برای ادامه در WhatsApp وارد شوید") {
		t.Errorf("the Persian sign-in page does not name the app: %s", truncate(page))
	}
}

// Signing out lands on the sign-in page, which says so once.
func TestSigningOutIsSaidOnce(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")

	resp, err := client.PostForm(ts.URL+"/logout", url.Values{})
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	resp.Body.Close()
	if loc, _ := resp.Location(); loc == nil || loc.Path != "/login" {
		t.Fatalf("signing out went to %v, want /login", loc)
	}

	signedOut := "You have signed out of Nabu on this browser."
	resp, err = client.Get(ts.URL + "/login?lang=en")
	if err != nil {
		t.Fatal(err)
	}
	if page := readBody(t, resp); !strings.Contains(page, signedOut) {
		t.Errorf("the sign-in page after signing out does not say so: %s", truncate(page))
	}
	resp, err = client.Get(ts.URL + "/login?lang=en")
	if err != nil {
		t.Fatal(err)
	}
	if page := readBody(t, resp); strings.Contains(page, signedOut) {
		t.Error("the signed-out notice is shown again on the next visit")
	}
}

func TestAppInitialsTellTheNabuAppsApart(t *testing.T) {
	for name, want := range map[string]string{
		"NabuDesk":    "De",
		"NabuCRM":     "CR",
		"NabuOS":      "OS",
		"NabuGate AI": "Ga",
		"Nabu Rent":   "NR",
		"ReelMind":    "RM",
		"RASAD GCC":   "RG",
		"Imagen":      "I",
		"":            "?",
	} {
		if got := appInitials(name); got != want {
			t.Errorf("appInitials(%q) = %q, want %q", name, got, want)
		}
	}
}
