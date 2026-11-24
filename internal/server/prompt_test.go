package server

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"nabuauth/internal/config"
)

// The MCP gateways sign a visitor in silently when another one already has:
// they send prompt=none and expect either a code or an error back at their own
// callback — never a page, because they made the request from a place where a
// page cannot be shown.

func authorizeQuery(extra url.Values) url.Values {
	q := url.Values{
		"client_id":             {"testapp"},
		"redirect_uri":          {"http://app.test/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {"st-42"},
		"code_challenge":        {pkceChallenge},
		"code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		q[k] = v
	}
	return q
}

func noFollowClient() *http.Client {
	return &http.Client{
		Jar:           &cookieJar{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// authorizeLocation requests /oauth/authorize and returns where it redirected.
func authorizeLocation(t *testing.T, client *http.Client, base string, q url.Values) *url.URL {
	t.Helper()
	resp, err := client.Get(base + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("authorize answered %d with no redirect: %s", resp.StatusCode, truncate(string(body)))
	}
	return loc
}

func TestPromptNoneWithoutASessionGoesBackWithLoginRequired(t *testing.T) {
	ts, _ := newTestServer(t)

	loc := authorizeLocation(t, noFollowClient(), ts.URL, authorizeQuery(url.Values{"prompt": {"none"}}))

	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != "http://app.test/callback" {
		t.Fatalf("prompt=none without a session went to %s, want the app's callback — never the sign-in page", loc)
	}
	if loc.Query().Get("error") != "login_required" {
		t.Errorf("error = %q, want login_required", loc.Query().Get("error"))
	}
	if loc.Query().Get("state") != "st-42" {
		t.Errorf("state = %q, want it handed back so the app can match the answer", loc.Query().Get("state"))
	}
	if loc.Query().Get("code") != "" {
		t.Error("a code was issued with nobody signed in")
	}
}

func TestPromptNoneWithASessionAndConsentReturnsACodeSilently(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")

	// The first app visit approves the scopes...
	grantCode(t, ts, client, "testapp", "http://app.test/callback", "openid profile", pkceChallenge, "S256")

	// ...after which a silent request is answered with a code, not a page.
	loc := authorizeLocation(t, client, ts.URL, authorizeQuery(url.Values{"prompt": {"none"}}))
	if loc.Host != "app.test" {
		t.Fatalf("silent sign-in went to %s, want the app's callback", loc)
	}
	if loc.Query().Get("code") == "" || loc.Query().Get("error") != "" {
		t.Fatalf("silent sign-in did not return a code: %s", loc)
	}
	if loc.Query().Get("state") != "st-42" {
		t.Errorf("state = %q, want st-42", loc.Query().Get("state"))
	}

	// And the code is a real one.
	tok := postForm(t, ts, "/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"code_verifier": {pkceVerifier}, "redirect_uri": {"http://app.test/callback"},
		"client_id": {"testapp"}, "client_secret": {"test-confidential-secret"},
	})
	if tok["access_token"] == nil {
		t.Fatalf("the silent code could not be exchanged: %v", tok)
	}
}

func TestPromptNoneWithASessionButNoConsentSaysConsentRequired(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")

	loc := authorizeLocation(t, client, ts.URL, authorizeQuery(url.Values{"prompt": {"none"}}))
	if loc.Host != "app.test" || loc.Query().Get("error") != "consent_required" {
		t.Fatalf("got %s, want consent_required at the app's callback", loc)
	}
	if loc.Query().Get("state") != "st-42" {
		t.Errorf("state = %q, want st-42", loc.Query().Get("state"))
	}
}

func TestPromptNoneCannotBeCombinedWithAScreen(t *testing.T) {
	ts, _ := newTestServer(t)

	loc := authorizeLocation(t, noFollowClient(), ts.URL, authorizeQuery(url.Values{"prompt": {"none login"}}))
	if loc.Host != "app.test" || loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("got %s, want invalid_request at the app's callback", loc)
	}
}

// prompt=login shows the sign-in screen over a live session, and once the
// visitor has signed in the request goes on to the app rather than asking for
// a sign-in again — which, before, ended the fresh session and went round the
// loop for ever.
func TestPromptLoginForcesTheSignInScreenAndThenCompletes(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")
	grantCode(t, ts, client, "testapp", "http://app.test/callback", "openid profile", pkceChallenge, "S256")

	loc := authorizeLocation(t, client, ts.URL, authorizeQuery(url.Values{"prompt": {"login"}}))
	if loc.Path != "/login" {
		t.Fatalf("prompt=login over a session went to %s, want the sign-in page", loc)
	}
	next := loc.Query().Get("next")
	if !strings.HasPrefix(next, "/oauth/authorize?") {
		t.Fatalf("the sign-in page was not told where to go back to: next=%q", next)
	}
	back, _ := url.Parse(next)
	if back.Query().Get("prompt") != "" {
		t.Fatalf("next still asks for a sign-in (%q); signing in would loop", next)
	}
	for _, kept := range []string{"client_id", "redirect_uri", "state", "code_challenge", "scope"} {
		if back.Query().Get(kept) == "" {
			t.Errorf("next lost %s: %q", kept, next)
		}
	}

	// The old session is over: the page asks for a sign-in rather than
	// bouncing straight on.
	resp, err := client.Get(ts.URL + loc.RequestURI())
	if err != nil {
		t.Fatalf("login page: %v", err)
	}
	page := readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, `name="identifier"`) {
		t.Fatalf("prompt=login did not show the sign-in form: %d %s", resp.StatusCode, truncate(page))
	}

	// Signing in goes back to the request and on to the app with a code.
	resp, err = client.PostForm(ts.URL+"/login", url.Values{
		"email": {"user@nabuxai.com"}, "password": {"correct-horse-battery"}, "next": {next},
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	after, err := resp.Location()
	if err != nil || after.RequestURI() != next {
		t.Fatalf("signing in went to %v, want %s", after, next)
	}
	final := authorizeLocation(t, client, ts.URL, back.Query())
	if final.Host != "app.test" || final.Query().Get("code") == "" {
		t.Fatalf("after signing in again the app got %s, want a code", final)
	}
}

// "Not you?" on the approval screen is the same request again with
// prompt=login, so the other account lands back at this app.
func TestNotYouKeepsTheWholeRequest(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")

	resp, err := client.Get(ts.URL + "/oauth/authorize?" + authorizeQuery(nil).Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	page := readBody(t, resp)
	start := strings.Index(page, `class="who-change" href="`)
	if start < 0 {
		t.Fatalf("no Not you? link on the approval screen: %s", truncate(page))
	}
	href := page[start+len(`class="who-change" href="`):]
	href = html.UnescapeString(href[:strings.Index(href, `"`)])
	u, err := url.Parse(href)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Path != "/oauth/authorize" || q.Get("prompt") != "login" ||
		q.Get("redirect_uri") != "http://app.test/callback" || q.Get("state") != "st-42" || q.Get("code_challenge") != pkceChallenge {
		t.Fatalf("Not you? points at %s; it must repeat the request with prompt=login", href)
	}
}

// A first-party app (first_party: true in apps.yaml — the MCP gateways) is
// approved by signing in to Nabu at all. That is what lets "sign in once and
// every MCP opens" work: the first silent request to a gateway the person has
// never visited already gets a code.
func withFirstPartyApp(c *config.Config) {
	c.Apps = append(c.Apps, config.App{
		ID:           "fp-mcp",
		Name:         "First Party Gateway",
		Brand:        "telegram",
		FirstParty:   true,
		URL:          "http://fp.test",
		RedirectURIs: []string{"http://fp.test/callback"},
		Scopes:       []string{"openid", "profile", "email"},
		SecretEnv:    "TEST_SECRET_CONFIDENTIAL",
	})
}

func firstPartyQuery(extra url.Values) url.Values {
	q := authorizeQuery(extra)
	q.Set("client_id", "fp-mcp")
	q.Set("redirect_uri", "http://fp.test/callback")
	return q
}

func TestAFirstPartyAppSignsInSilentlyOnTheFirstVisit(t *testing.T) {
	ts, st := newTestServer(t, withFirstPartyApp)
	user := seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")

	// No grant has ever been given to this app, and the request shows nothing.
	loc := authorizeLocation(t, client, ts.URL, firstPartyQuery(url.Values{"prompt": {"none"}}))
	if loc.Host != "fp.test" || loc.Query().Get("code") == "" || loc.Query().Get("error") != "" {
		t.Fatalf("a first-party prompt=none with no prior grant got %s, want a code", loc)
	}
	if loc.Query().Get("state") != "st-42" {
		t.Errorf("state = %q, want st-42", loc.Query().Get("state"))
	}
	tok := postForm(t, ts, "/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"code_verifier": {pkceVerifier}, "redirect_uri": {"http://fp.test/callback"},
		"client_id": {"fp-mcp"}, "client_secret": {"test-confidential-secret"},
	})
	if tok["access_token"] == nil {
		t.Fatalf("the first-party code could not be exchanged: %v", tok)
	}

	// The grant is recorded, so the dashboard lists it and can disconnect it.
	consented, err := st.HasConsent(context.Background(), user.ID, "fp-mcp", []string{"openid", "profile"})
	if err != nil || !consented {
		t.Fatalf("the first-party grant was not recorded: %v %v", consented, err)
	}

	// The same browser, at an ordinary app it never approved, still gets
	// consent_required: first_party belongs to the app, not to the session.
	other := authorizeLocation(t, client, ts.URL, authorizeQuery(url.Values{"prompt": {"none"}}))
	if other.Host != "app.test" || other.Query().Get("error") != "consent_required" {
		t.Fatalf("a non-first-party app got %s, want consent_required", other)
	}
}

func TestAFirstPartyAppSkipsTheScreenButNotTheRules(t *testing.T) {
	ts, st := newTestServer(t, withFirstPartyApp)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")

	// Interactive sign-in goes straight through, no approval screen.
	loc := authorizeLocation(t, client, ts.URL, firstPartyQuery(nil))
	if loc.Host != "fp.test" || loc.Query().Get("code") == "" {
		t.Fatalf("a first-party sign-in got %s, want a code with no approval screen", loc)
	}

	// prompt=consent still asks.
	resp, err := client.Get(ts.URL + "/oauth/authorize?" + firstPartyQuery(url.Values{"prompt": {"consent"}}).Encode())
	if err != nil {
		t.Fatal(err)
	}
	if page := readBody(t, resp); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Connect First Party Gateway") {
		t.Fatalf("prompt=consent on a first-party app did not show the screen: %d", resp.StatusCode)
	}

	// No session: still login_required, never a code.
	anon := authorizeLocation(t, noFollowClient(), ts.URL, firstPartyQuery(url.Values{"prompt": {"none"}}))
	if anon.Query().Get("error") != "login_required" {
		t.Fatalf("first-party prompt=none with no session got %s, want login_required", anon)
	}

	// The redirect must still match exactly...
	bad := firstPartyQuery(nil)
	bad.Set("redirect_uri", "http://evil.test/callback")
	resp, err = client.Get(ts.URL + "/oauth/authorize?" + bad.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Fatalf("an unregistered redirect for a first-party app got %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// ...and PKCE is still required where it was.
	noPKCE := firstPartyQuery(nil)
	noPKCE.Del("code_challenge")
	noPKCE.Del("code_challenge_method")
	if got := authorizeLocation(t, client, ts.URL, noPKCE); got.Query().Get("error") != "invalid_request" || got.Query().Get("code") != "" {
		t.Fatalf("a first-party request without PKCE on a non-https redirect got %s, want invalid_request", got)
	}
}
