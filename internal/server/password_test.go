package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// changePassword posts the dashboard's password form as the signed-in client
// and returns the result code the server redirected back with.
func changePassword(t *testing.T, ts *httptest.Server, client *http.Client, form url.Values) string {
	t.Helper()
	resp, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("dashboard: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	form.Set("csrf", extractInput(string(body), "csrf"))

	resp, err = client.PostForm(ts.URL+"/dashboard/password", form)
	if err != nil {
		t.Fatalf("change password: %v", err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("change password answered %d %q, want a redirect to the dashboard", resp.StatusCode, resp.Header.Get("Location"))
	}
	return loc.Query().Get("password")
}

// signedIn reports whether a client's session still reaches the dashboard.
func signedIn(t *testing.T, ts *httptest.Server, client *http.Client) bool {
	t.Helper()
	resp, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("dashboard: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// canSignIn reports whether the login form accepts this email and password.
func canSignIn(t *testing.T, ts *httptest.Server, email, password string) bool {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"email": {email}, "password": {password}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusFound
}

func TestChangePasswordReplacesItAndSignsOutEverywhereElse(t *testing.T) {
	ts, st := newTestServer(t)
	u := seedUser(t, st, "owner@nabuxai.com", "old-password-123")
	here := signIn(t, ts, "owner@nabuxai.com", "old-password-123")
	elsewhere := signIn(t, ts, "owner@nabuxai.com", "old-password-123")
	if _, err := st.DB().ExecContext(context.Background(),
		`INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, scopes, expires_at)
		 SELECT 'rt-before-change', client_id, $1, 'openid', now() + interval '1 day' FROM oauth_clients LIMIT 1`, u.ID); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	got := changePassword(t, ts, here, url.Values{"current": {"old-password-123"}, "new": {"new-password-456"}, "confirm": {"new-password-456"}})
	if got != "changed" {
		t.Fatalf("result = %q, want changed", got)
	}
	if !canSignIn(t, ts, "owner@nabuxai.com", "new-password-456") {
		t.Error("the new password does not sign in")
	}
	if canSignIn(t, ts, "owner@nabuxai.com", "old-password-123") {
		t.Error("the old password still signs in")
	}
	if !signedIn(t, ts, here) {
		t.Error("the browser that changed the password was signed out")
	}
	if signedIn(t, ts, elsewhere) {
		t.Error("another browser is still signed in after the change; that is the session the change was meant to end")
	}
	var revoked bool
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT revoked_at IS NOT NULL FROM oauth_refresh_tokens WHERE token_hash = 'rt-before-change'`).Scan(&revoked); err != nil {
		t.Fatalf("read refresh token: %v", err)
	}
	if !revoked {
		t.Error("an app's refresh token survived the password change")
	}
}

func TestChangePasswordRefusesWithoutTheCurrentOne(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "owner@nabuxai.com", "old-password-123")
	client := signIn(t, ts, "owner@nabuxai.com", "old-password-123")

	cases := []struct {
		name string
		form url.Values
		want string
	}{
		{"wrong current", url.Values{"current": {"not-it-at-all"}, "new": {"new-password-456"}, "confirm": {"new-password-456"}}, "wrong"},
		{"missing current", url.Values{"new": {"new-password-456"}, "confirm": {"new-password-456"}}, "wrong"},
		{"too short", url.Values{"current": {"old-password-123"}, "new": {"short"}, "confirm": {"short"}}, "short"},
		{"too long", url.Values{"current": {"old-password-123"}, "new": {strings.Repeat("x", 73)}, "confirm": {strings.Repeat("x", 73)}}, "long"},
		{"mismatch", url.Values{"current": {"old-password-123"}, "new": {"new-password-456"}, "confirm": {"new-password-789"}}, "mismatch"},
	}
	for _, c := range cases {
		if got := changePassword(t, ts, client, c.form); got != c.want {
			t.Errorf("%s: result = %q, want %q", c.name, got, c.want)
		}
	}
	if !canSignIn(t, ts, "owner@nabuxai.com", "old-password-123") {
		t.Error("a refused change altered the password anyway")
	}
}

func TestChangePasswordThrottlesWrongGuesses(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "owner@nabuxai.com", "old-password-123")
	client := signIn(t, ts, "owner@nabuxai.com", "old-password-123")

	wrong := url.Values{"current": {"guess"}, "new": {"new-password-456"}, "confirm": {"new-password-456"}}
	for i := 0; i < maxAttempts; i++ {
		changePassword(t, ts, client, wrong)
	}
	right := url.Values{"current": {"old-password-123"}, "new": {"new-password-456"}, "confirm": {"new-password-456"}}
	if got := changePassword(t, ts, client, right); got != "throttled" {
		t.Fatalf("after %d wrong guesses the right password got %q, want throttled", maxAttempts, got)
	}
}

// An account made by a phone, email-code or provider sign-in has a random
// password nobody knows. Asking for it would mean it can never get one.
func TestFirstPasswordNeedsAFreshSignInInstead(t *testing.T) {
	ts, st := newTestServer(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("random-nobody-knows"), bcrypt.MinCost)
	u, err := st.CreateUser(context.Background(), "Phone User", "phone@nabuxai.com", "", string(hash), false, false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if u.PasswordSet {
		t.Fatal("an account made without a known password reads as having one")
	}
	client := signIn(t, ts, "phone@nabuxai.com", "random-nobody-knows")

	// A session older than freshSignIn is not proof of who is at the keyboard.
	if _, err := st.DB().ExecContext(context.Background(),
		`UPDATE sessions SET created_at = now() - interval '1 hour' WHERE user_id = $1`, u.ID); err != nil {
		t.Fatalf("age session: %v", err)
	}
	form := url.Values{"new": {"first-password-1"}, "confirm": {"first-password-1"}}
	if got := changePassword(t, ts, client, form); got != "stale" {
		t.Fatalf("an hour-old session set the first password: result %q, want stale", got)
	}

	fresh := signIn(t, ts, "phone@nabuxai.com", "random-nobody-knows")
	if got := changePassword(t, ts, fresh, form); got != "changed" {
		t.Fatalf("a fresh session could not set the first password: %q", got)
	}
	if !canSignIn(t, ts, "phone@nabuxai.com", "first-password-1") {
		t.Error("the first password does not sign in")
	}

	// From now on the password is known, so changing it asks for it.
	if got := changePassword(t, ts, fresh, url.Values{"new": {"second-password-2"}, "confirm": {"second-password-2"}}); got != "wrong" {
		t.Errorf("once set, the password could be replaced without typing it: %q", got)
	}
}

func TestChangePasswordNeedsTheFormToken(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "owner@nabuxai.com", "old-password-123")
	client := signIn(t, ts, "owner@nabuxai.com", "old-password-123")

	resp, err := client.PostForm(ts.URL+"/dashboard/password", url.Values{
		"current": {"old-password-123"}, "new": {"new-password-456"}, "confirm": {"new-password-456"},
	})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a post without the form token answered %d, want 403", resp.StatusCode)
	}
	if !canSignIn(t, ts, "owner@nabuxai.com", "old-password-123") {
		t.Error("a cross-site post changed the password")
	}
}
