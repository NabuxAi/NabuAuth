package config

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// brand is optional, and a value the pages cannot draw is refused at load
// rather than drawn as nothing.
func TestAnUnknownBrandIsRefused(t *testing.T) {
	_, err := Load(write(t, `
apps:
  - id: demo
    name: Demo
    brand: myspace
    redirect_uris: [https://demo.example.com/callback]
`))
	if err == nil || !strings.Contains(err.Error(), "unknown brand") {
		t.Fatalf("an unknown brand loaded: %v", err)
	}

	cfg, err := Load(write(t, `
apps:
  - id: plain
    name: Plain
    redirect_uris: [https://plain.example.com/callback]
  - id: tg
    name: Telegram
    brand: telegram
    redirect_uris: [https://tg.example.com/callback]
`))
	if err != nil {
		t.Fatalf("an app without a brand, or with a known one, did not load: %v", err)
	}
	if a, ok := cfg.App("tg"); !ok || a.Brand != "telegram" {
		t.Fatalf("App(tg) = %+v, %v", a, ok)
	}
	if _, ok := cfg.App("nope"); ok {
		t.Fatal("App found an id that is not registered")
	}
}

// Every MCP gateway is registered the same way: its panel's callback on its
// own host, a secret variable of its own, and a platform mark.
func TestTheMCPGatewaysAreRegistered(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "apps.yaml"))
	if err != nil {
		t.Fatalf("loading apps.yaml: %v", err)
	}
	want := map[string]string{
		"instagram-mcp": "https://ig.nabuxai.com",
		"whatsapp-mcp":  "https://wa.nabuxai.com",
		"telegram-mcp":  "https://tm.nabuxai.com",
		"facebook-mcp":  "https://fb.nabuxai.com",
		"x-mcp":         "https://x.nabuxai.com",
		"linkedin-mcp":  "https://linkedin.nabuxai.com",
		"threads-mcp":   "https://threads.nabuxai.com",
		"youtube-mcp":   "https://youtube.nabuxai.com",
		"snapchat-mcp":  "https://snap.nabuxai.com",
		"social-mcp":    "https://social.nabuxai.com",
	}
	secrets := map[string]string{}
	for id, origin := range want {
		a, ok := cfg.App(id)
		if !ok {
			t.Errorf("%s is not registered", id)
			continue
		}
		if a.URL != origin {
			t.Errorf("%s url = %q, want %q", id, a.URL, origin)
		}
		if len(a.RedirectURIs) != 1 || a.RedirectURIs[0] != origin+"/auth/nabu/callback" {
			t.Errorf("%s redirect_uris = %v, want [%s/auth/nabu/callback]", id, a.RedirectURIs, origin)
		}
		if u, _ := url.Parse(a.RedirectURIs[0]); u == nil || u.Scheme != "https" {
			t.Errorf("%s redirects over %v", id, a.RedirectURIs)
		}
		if a.Public || a.Hidden {
			t.Errorf("%s should be a listed confidential client like the others", id)
		}
		if a.Brand == "" {
			t.Errorf("%s has no brand to draw", id)
		}
		wantSecret := "NABUAUTH_SECRET_" + strings.ToUpper(strings.ReplaceAll(id, "-", "_"))
		if a.SecretEnv != wantSecret {
			t.Errorf("%s secret_env = %q, want %q", id, a.SecretEnv, wantSecret)
		}
		if other, dup := secrets[a.SecretEnv]; dup {
			t.Errorf("%s and %s share the secret variable %s", id, other, a.SecretEnv)
		}
		secrets[a.SecretEnv] = id
		if strings.Join(a.Scopes, " ") != "openid profile email" {
			t.Errorf("%s scopes = %v, want [openid profile email]", id, a.Scopes)
		}
	}
}
