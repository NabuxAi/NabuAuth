package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "apps.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadExpandsEnvAndAppliesDefaults(t *testing.T) {
	t.Setenv("TEST_ISSUER", "https://auth.example.com/")
	cfg, err := Load(write(t, `
server:
  issuer: ${TEST_ISSUER}
apps:
  - id: demo
    name: Demo
    redirect_uris: [https://demo.example.com/callback]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.Issuer != "https://auth.example.com" {
		t.Fatalf("issuer = %q, want the env value without its trailing slash", cfg.Server.Issuer)
	}
	if cfg.Server.Port != 8099 {
		t.Fatalf("port = %d, want the 8099 default", cfg.Server.Port)
	}
	if len(cfg.Scopes) == 0 {
		t.Fatal("scope catalogue is empty; the defaults were not applied")
	}
	if got := cfg.Apps[0].Scopes; len(got) != 3 {
		t.Fatalf("app scopes = %v, want the openid/profile/email default", got)
	}
	if !cfg.Server.UseSecureCookies() {
		t.Fatal("an https issuer must imply secure cookies")
	}
}

func TestUseSecureCookiesFollowsIssuerScheme(t *testing.T) {
	cfg, err := Load(write(t, "server:\n  issuer: http://localhost:8099\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.UseSecureCookies() {
		t.Fatal("a plain-http issuer must not set Secure, or local development cannot sign in")
	}
}

func TestValidationRejectsBrokenApps(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "missing redirect uri",
			body: "apps:\n  - id: demo\n    name: Demo\n",
			want: "redirect_uri",
		},
		{
			name: "duplicate id",
			body: `
apps:
  - id: demo
    redirect_uris: [https://a.example/cb]
  - id: demo
    redirect_uris: [https://b.example/cb]
`,
			want: "duplicate id",
		},
		{
			name: "unknown scope",
			body: `
apps:
  - id: demo
    redirect_uris: [https://a.example/cb]
    scopes: [openid, nonsense]
`,
			want: "unknown scope",
		},
		{
			// Redirect URIs are stored space-delimited, so one containing a space
			// would come back split and never match itself.
			name: "redirect uri with whitespace",
			body: "apps:\n  - id: demo\n    redirect_uris: [\"https://a.example/cb with space\"]\n",
			want: "whitespace",
		},
		{
			name: "bad duration",
			body: "server:\n  access_token_ttl: soon\n",
			want: "access_token_ttl",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(write(t, tc.body))
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestDuration(t *testing.T) {
	if got := Duration("", time.Hour); got != time.Hour {
		t.Fatalf("empty value = %v, want the fallback", got)
	}
	if got := Duration("15m", time.Hour); got != 15*time.Minute {
		t.Fatalf("15m parsed as %v", got)
	}
	// A zero or negative TTL would mint tokens that are already expired, so it
	// must fall back rather than be honoured.
	if got := Duration("-5m", time.Hour); got != time.Hour {
		t.Fatalf("negative value = %v, want the fallback", got)
	}
}

func TestSecretComesFromTheEnvironment(t *testing.T) {
	t.Setenv("TEST_APP_SECRET", "s3cr3t")
	app := App{SecretEnv: "TEST_APP_SECRET"}
	if app.Secret() != "s3cr3t" {
		t.Fatalf("secret = %q", app.Secret())
	}
	if (App{}).Secret() != "" {
		t.Fatal("an app with no secret_env must report no secret")
	}
}
