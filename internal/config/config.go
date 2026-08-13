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

	// Sms is the gateway that carries one-time codes. Configured on the same
	// terms as a login method: the key is the name of an env var, and the phone
	// field is not offered at all until the deployment has one.
	Sms Sms `yaml:"sms"`
}

// Sms points at the NabuSms gateway and says how to address it.
type Sms struct {
	// BaseURL is the gateway root; the send endpoint is <BaseURL>/v1/messages.
	BaseURL string `yaml:"base_url"`

	// KeyEnv names the env var holding the bearer key, on the same terms as an
	// app's secret: the value never appears in the file.
	KeyEnv string `yaml:"key_env"`

	// Route is the gateway route for Iranian numbers and InternationalRoute the
	// one for everything else. They are two routes rather than one because the
	// domestic panels are declared IR-only at the gateway and refuse a foreign
	// number before any provider is tried, while the international provider
	// carries no message templates at all.
	Route              string `yaml:"route"`
	InternationalRoute string `yaml:"international_route"`

	// Template is the pattern name the domestic route sends, and CodeParam the
	// placeholder inside it that the code fills.
	Template  string `yaml:"template"`
	CodeParam string `yaml:"code_param"`

	// Text is the message body used on the international route, where there are
	// no patterns. {code} is replaced with the code.
	Text string `yaml:"text"`

	// DefaultCountry is the calling code assumed when the visitor picks nothing.
	DefaultCountry string `yaml:"default_country"`

	// CodeTTL is how long a sent code stays usable, and ResendAfter how long a
	// visitor must wait before another one is sent to the same number.
	CodeTTL     string `yaml:"code_ttl"`
	ResendAfter string `yaml:"resend_after"`

	// Countries fills the selector beside the phone field. A deployment can list
	// more; the default is the set the gateway is known to route.
	Countries []Country `yaml:"countries"`
}

// Country is one entry in the selector beside the phone field.
type Country struct {
	// Code is the ISO-3166-1 alpha-2 code, which is what the gateway's own
	// country lookup speaks; Dial is the E.164 calling code with no '+', which
	// is what its default_country field takes.
	Code string `yaml:"code"`
	Dial string `yaml:"dial"`
	Name string `yaml:"name"`
}

// Key returns the gateway's bearer key from its env var.
func (s Sms) Key() string {
	if s.KeyEnv == "" {
		return ""
	}
	return os.Getenv(s.KeyEnv)
}

// Configured reports whether codes can actually be sent. A phone field on a
// deployment with no gateway would claim a code was sent when nothing was, which
// is the failure this whole path exists to avoid.
func (s Sms) Configured() bool { return s.BaseURL != "" && s.Key() != "" }

// DialFor returns the calling code for an ISO country code, falling back to the
// configured default so an unrecognised selection cannot silently mean "no
// country" and turn a national number into a foreign one.
func (s Sms) DialFor(iso string) string {
	iso = strings.ToUpper(strings.TrimSpace(iso))
	for _, c := range s.Countries {
		if c.Code == iso {
			return c.Dial
		}
	}
	return s.DefaultCountry
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
	c.Sms.ApplyDefaults()
}

// DefaultCountries is the selector's contents when the config lists none: the
// calling codes the SMS gateway is known to route. A deployment that sends
// somewhere else lists its own — the point of the selector is that this is a
// setting rather than a country baked into the form.
var DefaultCountries = []Country{
	{Code: "IR", Dial: "98", Name: "Iran"},
	{Code: "OM", Dial: "968", Name: "Oman"},
	{Code: "AE", Dial: "971", Name: "United Arab Emirates"},
	{Code: "QA", Dial: "974", Name: "Qatar"},
	{Code: "BH", Dial: "973", Name: "Bahrain"},
	{Code: "KW", Dial: "965", Name: "Kuwait"},
	{Code: "SA", Dial: "966", Name: "Saudi Arabia"},
	{Code: "TR", Dial: "90", Name: "Türkiye"},
	{Code: "DE", Dial: "49", Name: "Germany"},
	{Code: "GB", Dial: "44", Name: "United Kingdom"},
	{Code: "US", Dial: "1", Name: "United States"},
}

// ApplyDefaults fills in everything the gateway block does not have to say.
// Exported because Load is not the only way a Config is built — a caller
// assembling one in code gets the same routes, wording and country list as a
// deployment reading the file, rather than a half-configured gateway.
func (s *Sms) ApplyDefaults() {
	if s.Route == "" {
		s.Route = "otp"
	}
	if s.InternationalRoute == "" {
		s.InternationalRoute = "international"
	}
	if s.Template == "" {
		s.Template = "otp"
	}
	if s.CodeParam == "" {
		s.CodeParam = "code"
	}
	if s.Text == "" {
		s.Text = "Your Nabu sign-in code is {code}. It expires in a few minutes."
	}
	if s.DefaultCountry == "" {
		s.DefaultCountry = "98"
	}
	if s.CodeTTL == "" {
		s.CodeTTL = "5m"
	}
	if s.ResendAfter == "" {
		s.ResendAfter = "60s"
	}
	if len(s.Countries) == 0 {
		s.Countries = DefaultCountries
	}
	s.BaseURL = strings.TrimRight(s.BaseURL, "/")
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
		// "phone" is the built-in method's own path segment. A provider claiming
		// it would put two different sign-ins under one URL.
		if p.ID == "phone" {
			return fmt.Errorf("login_method %q: that id belongs to the built-in phone sign-in", p.ID)
		}
		// A provider reached over plaintext hands the code, the secret and the
		// user's identity to whoever is on the wire.
		for _, u := range []string{p.AuthorizeURL, p.TokenURL, p.UserinfoURL} {
			if u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://127.0.0.1") && !strings.HasPrefix(u, "http://localhost") {
				return fmt.Errorf("login_method %q: %q is not https", p.ID, u)
			}
		}
	}

	// The gateway carries a bearer key and a phone number. Plaintext there hands
	// both to whoever is on the wire, and the code with them.
	if c.Sms.BaseURL != "" && !strings.HasPrefix(c.Sms.BaseURL, "https://") &&
		!strings.HasPrefix(c.Sms.BaseURL, "http://127.0.0.1") && !strings.HasPrefix(c.Sms.BaseURL, "http://localhost") {
		return fmt.Errorf("sms.base_url: %q is not https", c.Sms.BaseURL)
	}
	for _, country := range c.Sms.Countries {
		if len(country.Code) != 2 {
			return fmt.Errorf("sms.countries: %q is not an ISO-3166-1 alpha-2 code", country.Code)
		}
		// The dial code is concatenated onto the typed digits. A '+' or a space
		// in it would produce a number no gateway can read.
		if country.Dial == "" || strings.Trim(country.Dial, "0123456789") != "" {
			return fmt.Errorf("sms.countries: %q has dial %q, which is not bare digits", country.Code, country.Dial)
		}
	}

	for _, d := range []struct {
		name  string
		value string
	}{
		{"server.access_token_ttl", c.Server.AccessTokenTTL},
		{"server.refresh_token_ttl", c.Server.RefreshTokenTTL},
		{"server.session_ttl", c.Server.SessionTTL},
		{"server.code_ttl", c.Server.CodeTTL},
		{"sms.code_ttl", c.Sms.CodeTTL},
		{"sms.resend_after", c.Sms.ResendAfter},
	} {
		if d.value == "" {
			continue
		}
		if _, err := time.ParseDuration(d.value); err != nil {
			return fmt.Errorf("%s: %w", d.name, err)
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
