package config

import (
	"strings"
	"testing"
)

// The SMS gateway is configured on the same terms as an app secret and an
// external login method: the file names an environment variable, and the option
// is not offered until the value is actually there.

func TestTheGatewayKeyComesFromTheEnvironmentAndNotTheFile(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "gateway-key")
	cfg, err := Load(write(t, `
sms:
  base_url: https://sms.example.com/
  key_env: TEST_SMS_KEY
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Sms.Key() != "gateway-key" {
		t.Fatalf("key = %q, want the value from the environment", cfg.Sms.Key())
	}
	if !cfg.Sms.Configured() {
		t.Fatal("a gateway with a URL and a key is not being reported as configured")
	}
	// The send endpoint is built by appending to this, so a trailing slash would
	// produce a double one.
	if cfg.Sms.BaseURL != "https://sms.example.com" {
		t.Fatalf("base_url = %q, want it without the trailing slash", cfg.Sms.BaseURL)
	}
}

func TestAGatewayWithNoKeyIsNotConfigured(t *testing.T) {
	// This is what keeps the phone field off the form on a deployment that
	// cannot send. A field with no gateway behind it would say a code is on its
	// way when nothing was sent, and the visitor would wait for it.
	cfg, err := Load(write(t, "sms:\n  base_url: https://sms.example.com\n  key_env: TEST_SMS_KEY_UNSET\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Sms.Configured() {
		t.Fatal("a gateway whose key variable is unset is being reported as ready to send")
	}
	if (Sms{BaseURL: "https://sms.example.com"}).Configured() {
		t.Fatal("a gateway that names no key variable at all is being reported as ready to send")
	}
}

func TestTheGatewayDefaultsToTwoRoutesAndACountryList(t *testing.T) {
	cfg, err := Load(write(t, "sms:\n  base_url: https://sms.example.com\n  key_env: TEST_SMS_KEY\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Two routes rather than one, because the gateway's one-time-code route is
	// declared for Iranian numbers only and refuses anything else outright.
	if cfg.Sms.Route == cfg.Sms.InternationalRoute {
		t.Fatalf("both routes are %q; a foreign number would be sent down a route that refuses it", cfg.Sms.Route)
	}
	if len(cfg.Sms.Countries) < 2 {
		t.Fatalf("the selector has %d countries; the point of it is that the country is a setting, not a number baked into the form", len(cfg.Sms.Countries))
	}
	if cfg.Sms.DialFor("OM") != "968" {
		t.Fatalf("DialFor(OM) = %q", cfg.Sms.DialFor("OM"))
	}
	// An unrecognised selection must not mean "no country": that would leave a
	// national number with no calling code at all.
	if cfg.Sms.DialFor("") != cfg.Sms.DefaultCountry {
		t.Fatalf("an empty selection resolved to %q, want the default calling code", cfg.Sms.DialFor(""))
	}
}

func TestTheGatewayConfigIsRejectedWhenItCannotWork(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			// The request carries a bearer key, a phone number and the code.
			name: "a plaintext gateway URL",
			body: "sms:\n  base_url: http://sms.example.com\n  key_env: K\n",
			want: "not https",
		},
		{
			// The dial code is concatenated onto the typed digits, so a '+' here
			// produces a recipient no gateway can read.
			name: "a dial code that is not bare digits",
			body: "sms:\n  base_url: https://sms.example.com\n  key_env: K\n  countries:\n    - {code: IR, dial: \"+98\", name: Iran}\n",
			want: "not bare digits",
		},
		{
			name: "a country that is not an alpha-2 code",
			body: "sms:\n  base_url: https://sms.example.com\n  key_env: K\n  countries:\n    - {code: IRN, dial: \"98\", name: Iran}\n",
			want: "alpha-2",
		},
		{
			name: "an unparseable code lifetime",
			body: "sms:\n  base_url: https://sms.example.com\n  key_env: K\n  code_ttl: five minutes\n",
			want: "sms.code_ttl",
		},
		{
			// "phone" is the built-in method's own path segment; a provider
			// claiming it would put two different sign-ins under one URL.
			name: "a login method calling itself phone",
			body: "login_methods:\n  - id: phone\n    name: Phone\n",
			want: "built-in phone sign-in",
		},
	} {
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
