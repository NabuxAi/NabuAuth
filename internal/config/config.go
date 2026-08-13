// Package config loads apps.yaml: the server settings, the scope catalogue and
// the ecosystem apps allowed to sign users in.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole configuration file.
type Config struct {
	Server Server            `yaml:"server"`
	Scopes map[string]string `yaml:"scopes"`
	Apps   []App             `yaml:"apps"`

	// LoginMethods are the outside identity providers offered beside the email
	// form. Each is an ordinary OIDC provider, so one implementation serves
	// Google, Microsoft, an enterprise IdP or another Nabu deployment.
	LoginMethods []Provider `yaml:"login_methods"`
}

// Provider is one external sign-in method.
type Provider struct {
	ID           string   `yaml:"id"`
	Name         string   `yaml:"name"`
	AuthorizeURL string   `yaml:"authorize_url"`
	TokenURL     string   `yaml:"token_url"`
	UserinfoURL  string   `yaml:"userinfo_url"`
	ClientID     string   `yaml:"client_id"`
	Scopes       []string `yaml:"scopes"`

	// SecretEnv names the env var holding this provider's client secret, on the
	// same terms as an app's: the value never appears in the file.
	SecretEnv string `yaml:"secret_env"`
}

// Secret returns the provider's client secret from its env var.
func (p Provider) Secret() string {
	if p.SecretEnv == "" {
		return ""
	}
	return os.Getenv(p.SecretEnv)
}

// Configured reports whether this provider has everything it needs to be
// offered. A button that leads to a broken exchange is worse than no button.
func (p Provider) Configured() bool {
	return p.ID != "" && p.ClientID != "" && p.Secret() != "" &&
		p.AuthorizeURL != "" && p.TokenURL != "" && p.UserinfoURL != ""
}

// Server holds the listener and token lifetimes.
type Server struct {
	Port            int    `yaml:"port"`
	Issuer          string `yaml:"issuer"`
	AccessTokenTTL  string `yaml:"access_token_ttl"`
	RefreshTokenTTL string `yaml:"refresh_token_ttl"`
	SessionTTL      string `yaml:"session_ttl"`
	CodeTTL         string `yaml:"code_ttl"`

	// AllowRegistration turns the public sign-up form on. Off means accounts are
	// created only by an admin, which is the right default for an internal
	// ecosystem.
	AllowRegistration bool `yaml:"allow_registration"`

	// SecureCookies forces the Secure flag on session cookies. Derived from the
	// issuer scheme when unset.
	SecureCookies *bool `yaml:"secure_cookies"`
}

// App is one registered ecosystem application.
type App struct {
	ID           string   `yaml:"id"`
	Name         string   `yaml:"name"`
	Description  string   `yaml:"description"`
	Icon         string   `yaml:"icon"`
	URL          string   `yaml:"url"`
	Badge        string   `yaml:"badge"`
	RedirectURIs []string `yaml:"redirect_uris"`
	Scopes       []string `yaml:"scopes"`

	// SecretEnv names the env var holding the client secret. The secret itself
	// never appears in the file, so the config can live in the repo.
	SecretEnv string `yaml:"secret_env"`

	// Public marks a client that cannot keep a secret (SPA, mobile). Public
	// clients must use PKCE and get no client_credentials grant.
	Public bool `yaml:"public"`

	// Hidden keeps an app out of the dashboard launcher while still letting it
	// authenticate — for internal service clients.
	Hidden bool `yaml:"hidden"`
}

// DefaultScopes is used when the config lists none, so a minimal file still
// produces a working OIDC server.
var DefaultScopes = map[string]string{
	"openid":       "Confirm your Nabu identity",
	"profile":      "Your name and avatar",
	"email":        "Your email address",
	"wallet":       "Read your wallet balance",
	"wallet.write": "Charge your wallet for the usage you incur",
	"offline":      "Stay signed in when you are away",
}

var envPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Load reads the config file and expands ${ENV_VAR} references.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	expanded := envPattern.ReplaceAllStringFunc(string(raw), func(m string) string {
		return os.Getenv(envPattern.FindStringSubmatch(m)[1])
	})
	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	return &cfg, cfg.validate()
}

func (c *Config) applyDefaults() {
	if c.Server.Port == 0 {
		c.Server.Port = 8099
	}
	if c.Server.Issuer == "" {
		c.Server.Issuer = fmt.Sprintf("http://localhost:%d", c.Server.Port)
	}
	c.Server.Issuer = strings.TrimRight(c.Server.Issuer, "/")
	if len(c.Scopes) == 0 {
		c.Scopes = DefaultScopes
	}
	for i := range c.Apps {
		if len(c.Apps[i].Scopes) == 0 {
			c.Apps[i].Scopes = []string{"openid", "profile", "email"}
		}
	}
	for i := range c.LoginMethods {
		if c.LoginMethods[i].Name == "" {
			c.LoginMethods[i].Name = c.LoginMethods[i].ID
		}
		if len(c.LoginMethods[i].Scopes) == 0 {
			c.LoginMethods[i].Scopes = []string{"openid", "email", "profile"}
		}
	}
}

// EnabledLoginMethods are the providers a deployment has actually configured.
func (c *Config) EnabledLoginMethods() []Provider {
	out := make([]Provider, 0, len(c.LoginMethods))
	for _, p := range c.LoginMethods {
		if p.Configured() {
			out = append(out, p)
		}
	}
	return out
}

// LoginMethod finds a configured provider by id.
func (c *Config) LoginMethod(id string) (Provider, bool) {
	for _, p := range c.LoginMethods {
		if p.ID == id && p.Configured() {
			return p, true
		}
	}
	return Provider{}, false
}

func (c *Config) validate() error {
	seen := map[string]bool{}
	for _, a := range c.Apps {
		if a.ID == "" {
			return fmt.Errorf("app %q: id is required", a.Name)
		}
		if seen[a.ID] {
			return fmt.Errorf("app %q: duplicate id", a.ID)
		}
		seen[a.ID] = true
		if len(a.RedirectURIs) == 0 {
			return fmt.Errorf("app %q: at least one redirect_uri is required", a.ID)
		}
		for _, u := range a.RedirectURIs {
			// A redirect URI containing a space would silently split when stored
			// space-delimited, and the app would then never match its own URI.
			if strings.ContainsAny(u, " \t\n") {
				return fmt.Errorf("app %q: redirect_uri %q contains whitespace", a.ID, u)
			}
		}
		for _, s := range a.Scopes {
			if _, ok := c.Scopes[s]; !ok {
				return fmt.Errorf("app %q: unknown scope %q", a.ID, s)
			}
		}
	}
	seenProvider := map[string]bool{}
	for _, p := range c.LoginMethods {
		if p.ID == "" {
			return fmt.Errorf("login_method %q: id is required", p.Name)
		}
		if seenProvider[p.ID] {
			return fmt.Errorf("login_method %q: duplicate id", p.ID)
		}
		seenProvider[p.ID] = true
		// A provider reached over plaintext hands the code, the secret and the
		// user's identity to whoever is on the wire.
		for _, u := range []string{p.AuthorizeURL, p.TokenURL, p.UserinfoURL} {
			if u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://127.0.0.1") && !strings.HasPrefix(u, "http://localhost") {
				return fmt.Errorf("login_method %q: %q is not https", p.ID, u)
			}
		}
	}

	for _, d := range []struct {
		name  string
		value string
	}{
		{"access_token_ttl", c.Server.AccessTokenTTL},
		{"refresh_token_ttl", c.Server.RefreshTokenTTL},
		{"session_ttl", c.Server.SessionTTL},
		{"code_ttl", c.Server.CodeTTL},
	} {
		if d.value == "" {
			continue
		}
		if _, err := time.ParseDuration(d.value); err != nil {
			return fmt.Errorf("server.%s: %w", d.name, err)
		}
	}
	return nil
}

// Duration parses a configured duration, falling back when unset or invalid.
func Duration(value string, fallback time.Duration) time.Duration {
	if value == "" {
		return fallback
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// Secret returns the app's client secret from its env var.
func (a App) Secret() string {
	if a.SecretEnv == "" {
		return ""
	}
	return os.Getenv(a.SecretEnv)
}

// SecureCookies reports whether session cookies get the Secure flag. Defaults to
// on for an https issuer, which is what production always is.
func (s Server) UseSecureCookies() bool {
	if s.SecureCookies != nil {
		return *s.SecureCookies
	}
	return strings.HasPrefix(s.Issuer, "https://")
}
