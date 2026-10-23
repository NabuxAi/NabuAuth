package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"nabuauth/internal/config"
)

func postRegister(t *testing.T, ts *httptest.Server, form url.Values) *http.Response {
	t.Helper()
	client := &http.Client{Jar: &cookieJar{}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.PostForm(ts.URL+"/register?lang=en", form)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return resp
}

func TestCreateAccountWithNameEmailAndConfirmedPassword(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "first@nabuxai.com", "first-password-1") // so the new one is not the admin

	resp := postRegister(t, ts, url.Values{
		"name": {"Sara Ahmadi"}, "email": {"Sara@Example.com"},
		"password": {"sara-password-1"}, "confirm": {"sara-password-1"}, "next": {"/dashboard"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/dashboard" {
		t.Fatalf("got %d to %q, want a redirect to the dashboard", resp.StatusCode, resp.Header.Get("Location"))
	}
	signedIn := false
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			signedIn = true
		}
	}
	if !signedIn {
		t.Error("the new account was not signed in")
	}

	u, err := st.UserByEmail(context.Background(), "sara@example.com")
	if err != nil {
		t.Fatalf("account not created: %v", err)
	}
	if u.Name != "Sara Ahmadi" || u.IsAdmin || !u.PasswordSet {
		t.Errorf("created %+v, want the typed name, not admin, a known password", u)
	}
	if !canSignIn(t, ts, "sara@example.com", "sara-password-1") {
		t.Error("the chosen password does not sign in")
	}
}

func TestCreateAccountRefusals(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "taken@nabuxai.com", "taken-password-1")

	good := func() url.Values {
		return url.Values{"name": {"New Person"}, "email": {"new@nabuxai.com"}, "password": {"new-password-1"}, "confirm": {"new-password-1"}}
	}
	cases := []struct {
		name   string
		edit   func(url.Values)
		status int
		says   string
	}{
		{"no name", func(v url.Values) { v.Set("name", "  ") }, http.StatusBadRequest, "Enter your name."},
		{"bad email", func(v url.Values) { v.Set("email", "not-an-address") }, http.StatusBadRequest, "does not look right"},
		{"short password", func(v url.Values) { v.Set("password", "short"); v.Set("confirm", "short") }, http.StatusBadRequest, "at least 10 characters"},
		{"mismatch", func(v url.Values) { v.Set("confirm", "other-password-2") }, http.StatusBadRequest, "not the same"},
		{"taken email", func(v url.Values) { v.Set("email", "Taken@nabuxai.com") }, http.StatusConflict, "already exists"},
	}
	for _, c := range cases {
		form := good()
		c.edit(form)
		resp := postRegister(t, ts, form)
		body := readBody(t, resp)
		resp.Body.Close()
		if resp.StatusCode != c.status || !strings.Contains(body, c.says) {
			t.Errorf("%s: got %d, want %d saying %q", c.name, resp.StatusCode, c.status, c.says)
		}
		if strings.Contains(body, "new-password-1") {
			t.Errorf("%s: the refused page echoed the password back", c.name)
		}
	}
	if !canSignIn(t, ts, "taken@nabuxai.com", "taken-password-1") {
		t.Error("a refused sign-up changed the existing account's password")
	}
	if _, err := st.UserByEmail(context.Background(), "new@nabuxai.com"); !isNotFound(err) {
		t.Error("a refused sign-up created the account anyway")
	}
}

func TestCreateAccountClosedWhereAdminsMakeAccounts(t *testing.T) {
	ts, st := newTestServer(t, func(c *config.Config) { c.Server.AllowRegistration = false })
	seedUser(t, st, "admin@nabuxai.com", "admin-password-1")

	resp := postRegister(t, ts, url.Values{"name": {"X"}, "email": {"x@nabuxai.com"}, "password": {"x-password-12"}, "confirm": {"x-password-12"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403 while sign-up is closed", resp.StatusCode)
	}
	if _, err := st.UserByEmail(context.Background(), "x@nabuxai.com"); !isNotFound(err) {
		t.Error("an account was created while sign-up is closed")
	}
}

// The sign-in page has to show newcomers the way in, in words they look for.
func TestSignInPageOffersCreateAccount(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/login?lang=en")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	resp.Body.Close()
	if !strings.Contains(body, `href="/register"`) || !strings.Contains(body, "Create an account") {
		t.Errorf("the sign-in page has no create-account link: %s", truncate(body))
	}
}
