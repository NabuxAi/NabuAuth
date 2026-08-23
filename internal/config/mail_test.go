package config

import (
	"strings"
	"testing"
)

// The mail relay is configured on the same terms as the SMS gateway: every
// value arrives through an environment variable, and the option is not offered
// until the deployment can actually send.

func TestTheRelayConfigComesFromTheEnvironmentAndNotTheFile(t *testing.T) {
	t.Setenv("TEST_SMTP_HOST", "mail.example.com")
	t.Setenv("TEST_SMTP_USERNAME", "noreply@example.com")
	t.Setenv("TEST_SMTP_PASSWORD", "relay-password")
	cfg, err := Load(write(t, `
mail:
  host: ${TEST_SMTP_HOST}
  username: ${TEST_SMTP_USERNAME}
  password: ${TEST_SMTP_PASSWORD}
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Mail.Password != "relay-password" {
		t.Fatalf("password = %q, want the value from the environment", cfg.Mail.Password)
	}
	if !cfg.Mail.Configured() {
		t.Fatal("a relay with a host and a sender is not being reported as configured")
	}
	// The submission port and the sender address are defaults, so the file only
	// has to name what the deployment actually chose.
	if cfg.Mail.Port != 587 {
		t.Fatalf("port = %d, want the submission port", cfg.Mail.Port)
	}
	if cfg.Mail.From != "noreply@example.com" {
		t.Fatalf("from = %q, want the account address — the one an authenticated relay is known to let through", cfg.Mail.From)
	}
}

func TestARelayWithNoHostIsNotConfigured(t *testing.T) {
	// This is what keeps the email-code offer off the form on a deployment that
	// cannot send. An offer with no relay behind it would say a code is on its
	// way when nothing was sent, and the visitor would wait for it.
	cfg, err := Load(write(t, ""))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Mail.Configured() {
		t.Fatal("a relay whose host variable is unset is being reported as ready to send")
	}
	if (Mail{Port: 587, From: "noreply@example.com"}).Configured() {
		t.Fatal("a sender address without a host is being reported as ready to send")
	}
}

func TestTheMailConfigIsRejectedWhenItCannotWork(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "an unparseable code lifetime",
			body: "mail:\n  host: mail.example.com\n  from: noreply@example.com\n  code_ttl: five minutes\n",
			want: "mail.code_ttl",
		},
		{
			// "email" is the built-in method's own path segment; a provider
			// claiming it would put two different sign-ins under one URL.
			name: "a login method calling itself email",
			body: "login_methods:\n  - id: email\n    name: Email\n",
			want: "built-in email sign-in",
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
