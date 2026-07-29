package config

import "testing"

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
// a mismatch there fails every sign-in with "redirect not allowed".
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
			if app.URL != "" && !hasPrefix(uri, app.URL) {
				t.Errorf("app %q: redirect %q is not on its own origin %q", app.ID, uri, app.URL)
			}
		}
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
