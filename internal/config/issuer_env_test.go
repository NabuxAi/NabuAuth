package config

import (
	"strings"
	"testing"

	"nabuauth/internal/store"
)

// The issuer is read from the environment in production. If expansion silently
// produced an empty value the server would fall back to localhost and every
// token it signed would name the wrong issuer, which every verifier rejects.
func TestIssuerComesFromTheEnvironment(t *testing.T) {
	t.Setenv("NABUAUTH_ISSUER", "https://auth.nabuxai.com")

	cfg, err := Load("../../apps.yaml")
	if err != nil {
		t.Fatalf("load apps.yaml: %v", err)
	}
	if cfg.Server.Issuer != "https://auth.nabuxai.com" {
		t.Fatalf("issuer = %q, want the value from NABUAUTH_ISSUER", cfg.Server.Issuer)
	}
}

// Every app in the shipped config must name a redirect URI on its own origin;
// a mismatch there fails every sign-in with "redirect not allowed". The one
// exception is a redirect the app cannot own — a custom scheme or loopback,
// for a native build or a developer's machine. Those are allowed here because
// the server refuses to send a code to them without S256 PKCE
// (store.RedirectIsInterceptable), so listing one does not widen the surface.
func TestShippedAppsAreConsistent(t *testing.T) {
	t.Setenv("NABUAUTH_ISSUER", "https://auth.nabuxai.com")

	cfg, err := Load("../../apps.yaml")
	if err != nil {
		t.Fatalf("load apps.yaml: %v", err)
	}
	if len(cfg.Apps) == 0 {
		t.Fatal("the shipped config registers no apps")
	}
	for _, app := range cfg.Apps {
		if app.SecretEnv == "" && !app.Public {
			t.Errorf("app %q is confidential but names no secret_env", app.ID)
		}
		for _, uri := range app.RedirectURIs {
			if store.RedirectIsInterceptable(uri) {
				continue
			}
			// nabucrm is one client for two deployments. The launcher URL stays
			// on .com; the Iran NabuCRM and NabuPay hosts are the other place
			// this same client is allowed to return.
			if app.ID == "nabucrm" && iranNabuCRMRedirects[uri] {
				continue
			}
			// An Iran mirror of the app is the same product on the same path
			// under nabuxai.ir, and returns to itself (NabuGate deploy/iran).
			if app.URL != "" && hasPrefix(uri, strings.Replace(app.URL, ".nabuxai.com", ".nabuxai.ir", 1)) {
				continue
			}
			// The Iran instances of products whose brand domain is its own
			// .ir (nabugen.ir, nabusto.ir) return to themselves; same client,
			// same product, other server.
			if iranBrandRedirects[uri] {
				continue
			}
			if app.URL != "" && !hasPrefix(uri, app.URL) {
				t.Errorf("app %q: redirect %q is not on its own origin %q", app.ID, uri, app.URL)
			}
		}
	}
}

// iranNabuCRMRedirects are the callbacks of the Iran-hosted NabuCRM/NabuPay
// instance. They are not on the .com launcher origin, and they are listed on
// purpose: the Iran deployment authenticates as client id nabucrm.
var iranNabuCRMRedirects = map[string]bool{
	"https://crm.nabuxai.ir/auth/nabu/callback": true,
	"https://pay.nabuxai.ir/auth/nabu/callback": true,
}

// iranBrandRedirects are the callbacks of Iran instances that live on their
// own brand domain rather than a nabuxai.ir mirror. Listed on purpose, like
// the NabuCRM ones above.
var iranBrandRedirects = map[string]bool{
	"https://nabugen.ir/auth/nabu/callback": true,
	// nabupilot-office builds its three doors from its own origin, and the
	// brand-domain Iran instance has its own.
	"https://nabupilot.ir/virtual-office/": true,
	"https://nabupilot.ir/webapp/":         true,
	"https://nabupilot.ir/oauth/callback":  true,
}

// The .com callback has to stay, in the same place, when the Iran callbacks
// are added. Dropping or reordering it would be a behavior change for the
// existing deployment; an exact-match allow-list only grows by appending.
func TestNabuCRMKeepsTheComCallbackAndAllowsIran(t *testing.T) {
	t.Setenv("NABUAUTH_ISSUER", "https://auth.nabuxai.com")

	cfg, err := Load("../../apps.yaml")
	if err != nil {
		t.Fatalf("load apps.yaml: %v", err)
	}
	var got []string
	for _, app := range cfg.Apps {
		if app.ID == "nabucrm" {
			got = app.RedirectURIs
			break
		}
	}
	want := []string{
		"https://crm.nabuxai.com/auth/nabu/callback",
		"https://crm.nabuxai.ir/auth/nabu/callback",
		"https://pay.nabuxai.ir/auth/nabu/callback",
	}
	if len(got) != len(want) {
		t.Fatalf("nabucrm redirect_uris = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("nabucrm redirect_uris[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
