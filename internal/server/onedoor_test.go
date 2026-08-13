package server

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"nabuauth/internal/config"
)

// The sign-in form is one door: the same submission signs an existing account
// in and creates one that does not exist yet. These hold the two halves apart
// where they must stay apart — a wrong password is never a sign-up, and a
// closed deployment never says which emails have accounts.

// postLogin submits the form without following the redirect.
func postLogin(t *testing.T, url_ string, form url.Values) *http.Response {
	t.Helper()
	client := &http.Client{
		Jar:           &cookieJar{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.PostForm(url_, form)
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	return resp
}

func TestAnUnknownEmailCreatesTheAccountFromTheSameForm(t *testing.T) {
	ts, st := newTestServer(t)

	resp := postLogin(t, ts.URL+"/login", url.Values{
		"email":    {"newcomer@nabuxai.com"},
		"password": {"a-long-enough-password"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want a redirect into the account", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/dashboard" {
		t.Fatalf("landed on %q, want /dashboard", loc)
	}
	if _, err := st.UserByEmail(context.Background(), "newcomer@nabuxai.com"); err != nil {
		t.Fatalf("the account was not created: %v", err)
	}

	// And the next screen is told the account is new, so an approval prompt does
	// not appear to a stranger with no explanation.
	welcome := false
	for _, c := range resp.Cookies() {
		if c.Name == welcomeCookie && c.Value == "1" {
			welcome = true
		}
	}
	if !welcome {
		t.Fatal("a brand-new account was not marked as new")
	}
}

func TestAWrongPasswordIsAFailedSignInAndNeverASignUp(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	resp := postLogin(t, ts.URL+"/login", url.Values{
		"email":    {"user@nabuxai.com"},
		"password": {"not-the-password"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("a failed sign-in started a session")
		}
	}
	count, err := st.CountUsers(context.Background())
	if err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 1 {
		t.Fatalf("there are now %d accounts, want the original 1", count)
	}
}

func TestSigningUpNeedsAPasswordWorthHaving(t *testing.T) {
	ts, st := newTestServer(t)

	resp := postLogin(t, ts.URL+"/login", url.Values{
		"email":    {"newcomer@nabuxai.com"},
		"password": {"short"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.StatusCode)
	}
	// And it says so as a sign-up, because "wrong password" on an address that
	// has no account is a sentence nobody can act on.
	if body := readBody(t, resp); !strings.Contains(body, "No Nabu account uses") {
		t.Fatalf("the page does not explain that this would create an account: %s", body)
	}
	if count, err := st.CountUsers(context.Background()); err != nil || count != 0 {
		t.Fatalf("count=%d err=%v, want no account created", count, err)
	}
}

func TestAClosedDeploymentWillNotSayWhichEmailsHaveAccounts(t *testing.T) {
	ts, st := newTestServer(t, func(cfg *config.Config) { cfg.Server.AllowRegistration = false })
	// A user has to exist, or sign-up stays open regardless so a fresh
	// deployment can still be claimed.
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	unknown := postLogin(t, ts.URL+"/login", url.Values{
		"email":    {"stranger@nabuxai.com"},
		"password": {"a-long-enough-password"},
	})
	defer unknown.Body.Close()
	wrong := postLogin(t, ts.URL+"/login", url.Values{
		"email":    {"user@nabuxai.com"},
		"password": {"not-the-password"},
	})
	defer wrong.Body.Close()

	if unknown.StatusCode != wrong.StatusCode {
		t.Fatalf("an unknown email answered %d and a wrong password %d — the difference is the answer to \"does this account exist\"", unknown.StatusCode, wrong.StatusCode)
	}
	// The pages differ only where they echo back the address that was typed;
	// what they say about it has to be the same sentence.
	const refusal = "Wrong email or password."
	for name, body := range map[string]string{"unknown email": readBody(t, unknown), "wrong password": readBody(t, wrong)} {
		if !strings.Contains(body, refusal) {
			t.Fatalf("%s was refused with something other than %q, which tells an outsider which emails have accounts", name, refusal)
		}
	}
	if count, err := st.CountUsers(context.Background()); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v, want no account created while sign-up is closed", count, err)
	}
}

func TestTheSignUpUrlLeadsToTheOneForm(t *testing.T) {
	ts, _ := newTestServer(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	resp, err := client.Get(ts.URL + "/register?next=%2Fdashboard")
	if err != nil {
		t.Fatalf("get register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want a redirect", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login?next=%2Fdashboard" {
		t.Fatalf("sent to %q, want the sign-in form with the destination kept", loc)
	}
}

func TestTheFormNamesTheAppThatSentTheVisitorHere(t *testing.T) {
	ts, _ := newTestServer(t)

	next := "/oauth/authorize?client_id=testapp&response_type=code&redirect_uri=" + url.QueryEscape("http://app.test/callback")
	resp, err := http.Get(ts.URL + "/login?next=" + url.QueryEscape(next))
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	defer resp.Body.Close()

	if body := readBody(t, resp); !strings.Contains(body, "Test App") {
		t.Fatalf("the form does not say which app is asking: %s", body)
	}
}

// readBody reads a response body once, for the assertions that compare what two
// refusals actually say.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}
