package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The README claimed a user's one account worked in NabuSu, NabuWatch and the
// Nabux store. None of those three repositories contains a single reference to
// NabuAuth — checked by grepping all three. The sentence had been true as an
// intention and was read as a statement of fact.
//
// A README that lists an integration nobody built is worse than one that lists
// none: it is the thing somebody reads before deciding not to build it.
//
// So the list lives between markers and this test compares it to apps.yaml.
// Marker-delimited rather than parsed out of prose, because a test that reads
// English breaks when the English improves and then gets deleted.

const (
	beginMarker = "<!-- registered-apps:begin -->"
	endMarker   = "<!-- registered-apps:end -->"
)

func repoFile(t *testing.T, name string) string {
	t.Helper()
	// internal/config -> repo root
	path := filepath.Join("..", "..", name)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(body)
}

// readmeApps returns the names listed between the markers.
func readmeApps(t *testing.T) []string {
	t.Helper()
	readme := repoFile(t, "README.md")

	start := strings.Index(readme, beginMarker)
	end := strings.Index(readme, endMarker)
	if start < 0 || end < 0 || end < start {
		t.Fatalf("README has no %s / %s block; the list of registered apps must be "+
			"machine-readable or it drifts from apps.yaml again", beginMarker, endMarker)
	}

	var names []string
	block := readme[start+len(beginMarker) : end]
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "- ") {
			continue
		}
		names = append(names, strings.TrimSpace(strings.TrimPrefix(line, "- ")))
	}
	return names
}

// configuredApps returns the app names apps.yaml actually registers.
func configuredApps(t *testing.T) []string {
	t.Helper()
	cfg, err := Load(filepath.Join("..", "..", "apps.yaml"))
	if err != nil {
		t.Fatalf("loading apps.yaml: %v", err)
	}
	names := make([]string, 0, len(cfg.Apps))
	for _, a := range cfg.Apps {
		names = append(names, a.Name)
	}
	return names
}

func TestTheReadmeListsExactlyTheAppsThatAreRegistered(t *testing.T) {
	documented := readmeApps(t)
	configured := configuredApps(t)

	if len(documented) == 0 {
		t.Fatal("the README's app list is empty")
	}

	inConfig := map[string]bool{}
	for _, n := range configured {
		inConfig[n] = true
	}
	inReadme := map[string]bool{}
	for _, n := range documented {
		inReadme[n] = true
	}

	for _, n := range documented {
		if !inConfig[n] {
			t.Errorf("the README says %q signs in with NabuAuth, but apps.yaml does not "+
				"register it — either register it or stop promising it", n)
		}
	}
	for _, n := range configured {
		if !inReadme[n] {
			t.Errorf("apps.yaml registers %q and the README does not mention it; "+
				"somebody integrating will not know it is already possible", n)
		}
	}
}

func TestEveryRegisteredAppNamesASecretVariableRatherThanCarryingOne(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "apps.yaml"))
	if err != nil {
		t.Fatalf("loading apps.yaml: %v", err)
	}

	for _, a := range cfg.Apps {
		// apps.yaml is in version control. A secret written here is a secret in
		// every clone, every fork and every backup, and rotating it means a
		// commit. Naming the variable keeps the file publishable.
		if a.SecretEnv == "" {
			continue // a public client, which carries no secret at all
		}
		if !strings.HasPrefix(a.SecretEnv, "NABUAUTH_SECRET_") {
			t.Errorf("app %q names secret variable %q; the convention is NABUAUTH_SECRET_<APP>, "+
				"and a name outside it is the one nobody sets on deploy", a.ID, a.SecretEnv)
		}
	}
}

func TestEveryRegisteredAppHasAtLeastOneRedirectURI(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "apps.yaml"))
	if err != nil {
		t.Fatalf("loading apps.yaml: %v", err)
	}

	for _, a := range cfg.Apps {
		if len(a.RedirectURIs) == 0 {
			// The authorization code flow has nowhere to send the user. The app
			// appears on the launcher and fails at the last step.
			t.Errorf("app %q registers no redirect_uri, so signing in cannot complete", a.ID)
		}
		for _, u := range a.RedirectURIs {
			if strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "http://localhost") &&
				!strings.HasPrefix(u, "http://127.0.0.1") {
				// A code delivered over plaintext is a code somebody else can
				// read off the wire and exchange first.
				t.Errorf("app %q has an http redirect_uri (%s); an authorization code sent "+
					"in the clear can be exchanged by whoever reads it", a.ID, u)
			}
		}
	}
}
