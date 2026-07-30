package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"nabuauth/internal/config"
	"nabuauth/internal/store"
	"nabuauth/internal/tokens"
)

// newTestServer boots the full server against a real Postgres database. The
// OAuth flow is mostly about what the database refuses to do twice — replayed
// codes, rotated refresh tokens, idempotent debits — so a fake store would test
// the wrong thing.
func newTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	dsn := os.Getenv("NABUAUTH_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NABUAUTH_TEST_DATABASE_URL to run the integration tests")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	// Start from a clean slate; TRUNCATE cascades through every dependent table.
	if _, err := st.DB().ExecContext(ctx, `TRUNCATE users, oauth_clients, signing_keys RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	t.Setenv("TEST_SECRET_CONFIDENTIAL", "test-confidential-secret")
	cfg := &config.Config{
		Server: config.Server{Port: 0, Issuer: "http://nabuauth.test", AllowRegistration: true},
		Scopes: config.DefaultScopes,
		Apps: []config.App{
			{
				ID:           "testapp",
				Name:         "Test App",
				URL:          "http://app.test",
				RedirectURIs: []string{"http://app.test/callback"},
				Scopes:       []string{"openid", "profile", "email", "wallet"},
				SecretEnv:    "TEST_SECRET_CONFIDENTIAL",
			},
			{
				ID:           "meter",
				Name:         "Metering Service",
				URL:          "http://meter.test",
				RedirectURIs: []string{"http://meter.test/callback"},
				Scopes:       []string{"wallet", "wallet.write"},
				SecretEnv:    "TEST_SECRET_CONFIDENTIAL",
				Hidden:       true,
			},
			{
				ID:           "spa",
				Name:         "Public SPA",
				URL:          "http://spa.test",
				RedirectURIs: []string{"http://spa.test/callback"},
				Scopes:       []string{"openid", "profile"},
				Public:       true,
			},
		},
	}

	kid, pem, err := tokens.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keys, err := tokens.NewKeyring([]struct{ KID, PEM string }{{kid, pem}})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := New(cfg, st, keys, log)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := srv.SyncApps(ctx); err != nil {
		t.Fatalf("sync apps: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

// seedUser creates an account directly, skipping the sign-up form.
func seedUser(t *testing.T, st *store.Store, email, password string) store.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	u, err := st.CreateUser(context.Background(), "Test User", email, "", string(hash), false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

// signIn logs in through the real login form and returns a client carrying the
// session cookie, with redirects disabled so tests can inspect each hop.
func signIn(t *testing.T, ts *httptest.Server, email, password string) *http.Client {
	t.Helper()
	jar := &cookieJar{}
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"email": {email}, "password": {password}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login returned %d, want a redirect", resp.StatusCode)
	}
	return client
}

func TestAuthorizationCodeFlowWithPKCE(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	authQuery := url.Values{
		"client_id":             {"testapp"},
		"redirect_uri":          {"http://app.test/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile email wallet"},
		"state":                 {"state-123"},
		"nonce":                 {"nonce-abc"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	// The first visit must ask for consent rather than silently granting it.
	resp, err := client.Get(ts.URL + "/oauth/authorize?" + authQuery.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "wants to use your Nabu account") {
		t.Fatalf("expected the consent screen, got %d: %s", resp.StatusCode, truncate(string(body)))
	}
	csrf := extractInput(string(body), "csrf")
	if csrf == "" {
		t.Fatal("consent form carries no csrf token")
	}

	form := url.Values{"csrf": {csrf}, "approve": {"yes"}}
	for k, v := range authQuery {
		form[k] = v
	}
	resp, err = client.PostForm(ts.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatalf("consent post: %v", err)
	}
	resp.Body.Close()
	location, err := resp.Location()
	if err != nil {
		t.Fatalf("no redirect after consent: %v", err)
	}
	if location.Query().Get("state") != "state-123" {
		t.Fatalf("state was not echoed back: %s", location)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("no authorization code in %s", location)
	}

	exchange := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://app.test/callback"},
		"code_verifier": {verifier},
		"client_id":     {"testapp"},
		"client_secret": {"test-confidential-secret"},
	}
	tok := postForm(t, ts, "/oauth/token", exchange)
	if tok["access_token"] == nil || tok["refresh_token"] == nil || tok["id_token"] == nil {
		t.Fatalf("token response is missing fields: %v", tok)
	}

	// The same code must not work twice.
	replay := postForm(t, ts, "/oauth/token", exchange)
	if replay["error"] != "invalid_grant" {
		t.Fatalf("replayed code returned %v, want invalid_grant", replay)
	}

	// The profile endpoint must accept the access token and honour its scopes.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/user", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	userResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	defer userResp.Body.Close()
	var profile map[string]any
	if err := json.NewDecoder(userResp.Body).Decode(&profile); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if profile["email"] != "user@nabuxai.com" {
		t.Fatalf("userinfo returned %v", profile)
	}

	// Second time through, consent is remembered and the redirect is immediate.
	resp, err = client.Get(ts.URL + "/oauth/authorize?" + authQuery.Encode())
	if err != nil {
		t.Fatalf("second authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("remembered consent should redirect, got %d", resp.StatusCode)
	}
}

func TestTokenEndpointRejectsWrongCredentials(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")
	code := grantCode(t, ts, client, "testapp", "http://app.test/callback", "openid profile", "", "")

	t.Run("wrong secret", func(t *testing.T) {
		got := postForm(t, ts, "/oauth/token", url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"client_id": {"testapp"}, "client_secret": {"wrong"},
		})
		if got["error"] != "invalid_client" {
			t.Fatalf("got %v, want invalid_client", got)
		}
	})

	t.Run("another client redeeming the code", func(t *testing.T) {
		got := postForm(t, ts, "/oauth/token", url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"client_id": {"meter"}, "client_secret": {"test-confidential-secret"},
		})
		if got["error"] != "invalid_grant" {
			t.Fatalf("got %v, want invalid_grant", got)
		}
	})
}

func TestPublicClientMustUsePKCE(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")

	resp, err := client.Get(ts.URL + "/oauth/authorize?" + url.Values{
		"client_id": {"spa"}, "redirect_uri": {"http://spa.test/callback"},
		"response_type": {"code"}, "scope": {"openid"},
	}.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	location, err := resp.Location()
	if err != nil {
		t.Fatalf("expected an error redirect: %v", err)
	}
	if location.Query().Get("error") != "invalid_request" {
		t.Fatalf("got %s, want invalid_request", location)
	}
}

func TestUnregisteredRedirectIsRefusedWithoutRedirecting(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/oauth/authorize?" + url.Values{
		"client_id": {"testapp"}, "redirect_uri": {"https://evil.example/steal"},
		"response_type": {"code"},
	}.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 — an unverified redirect_uri must never be followed", resp.StatusCode)
	}
}

func TestWalletDebitIsScopedAndIdempotent(t *testing.T) {
	ts, st := newTestServer(t)
	user := seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	service := postForm(t, ts, "/oauth/token", url.Values{
		"grant_type": {"client_credentials"}, "scope": {"wallet wallet.write"},
		"client_id": {"meter"}, "client_secret": {"test-confidential-secret"},
	})
	token, ok := service["access_token"].(string)
	if !ok {
		t.Fatalf("no service token: %v", service)
	}

	topUp := postJSON(t, ts, "/api/v1/wallet/topup", token, map[string]any{
		"user_id": user.ID, "amount_cents": 5000, "description": "top-up",
	})
	if topUp["balance_cents"].(float64) != 5000 {
		t.Fatalf("balance after top-up: %v", topUp)
	}

	// The same idempotency key twice must charge once. This is the difference
	// between a retried metering call and double-billing a customer.
	for i := 0; i < 2; i++ {
		postJSON(t, ts, "/api/v1/wallet/debit", token, map[string]any{
			"user_id": user.ID, "amount_cents": 750,
			"description": "completion", "idempotency_key": "req-1",
		})
	}
	wallet, err := st.WalletFor(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("wallet: %v", err)
	}
	if wallet.BalanceCents != 4250 {
		t.Fatalf("balance is %d, want 4250 — the retry was charged twice", wallet.BalanceCents)
	}

	// Overdrafts must be refused rather than driving the balance negative.
	resp := postJSONRaw(t, ts, "/api/v1/wallet/debit", token, map[string]any{
		"user_id": user.ID, "amount_cents": 999999, "description": "too much",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("overdraft returned %d, want 402", resp.StatusCode)
	}
}

func TestServiceTokenCannotReadAProfile(t *testing.T) {
	ts, _ := newTestServer(t)
	service := postForm(t, ts, "/oauth/token", url.Values{
		"grant_type": {"client_credentials"}, "scope": {"wallet"},
		"client_id": {"meter"}, "client_secret": {"test-confidential-secret"},
	})
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/user", nil)
	req.Header.Set("Authorization", "Bearer "+service["access_token"].(string))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403 — a service token stands for no user", resp.StatusCode)
	}
}

func TestDiscoveryAndJWKS(t *testing.T) {
	ts, _ := newTestServer(t)
	var doc map[string]any
	getJSON(t, ts.URL+"/.well-known/openid-configuration", &doc)
	if doc["issuer"] != "http://nabuauth.test" {
		t.Fatalf("issuer = %v", doc["issuer"])
	}
	for _, key := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"} {
		if doc[key] == nil {
			t.Fatalf("discovery document is missing %s", key)
		}
	}
	var jwks map[string]any
	getJSON(t, ts.URL+"/oauth/jwks.json", &jwks)
	if keys, _ := jwks["keys"].([]any); len(keys) != 1 {
		t.Fatalf("jwks holds %d keys, want 1", len(keys))
	}
}

// ---------------------------------------------------------------- helpers

// grantCode runs authorize + consent and returns the authorization code.
func grantCode(t *testing.T, ts *httptest.Server, client *http.Client, clientID, redirect, scope, challenge, method string) string {
	t.Helper()
	q := url.Values{
		"client_id": {clientID}, "redirect_uri": {redirect},
		"response_type": {"code"}, "scope": {scope},
	}
	if challenge != "" {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", method)
	}
	resp, err := client.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	form := url.Values{"csrf": {extractInput(string(body), "csrf")}, "approve": {"yes"}}
	for k, v := range q {
		form[k] = v
	}
	resp, err = client.PostForm(ts.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	resp.Body.Close()
	location, err := resp.Location()
	if err != nil {
		t.Fatalf("no redirect: %v", err)
	}
	return location.Query().Get("code")
}

func postForm(t *testing.T, ts *httptest.Server, path string, form url.Values) map[string]any {
	t.Helper()
	resp, err := http.PostForm(ts.URL+path, form)
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return out
}

func postJSONRaw(t *testing.T, ts *httptest.Server, path, token string, body map[string]any) *http.Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(string(raw)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	return resp
}

func postJSON(t *testing.T, ts *httptest.Server, path, token string, body map[string]any) map[string]any {
	t.Helper()
	resp := postJSONRaw(t, ts, path, token, body)
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return out
}

func getJSON(t *testing.T, url string, into any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

// extractInput pulls a hidden form field's value out of rendered HTML.
func extractInput(html, name string) string {
	marker := `name="` + name + `" value="`
	i := strings.Index(html, marker)
	if i < 0 {
		return ""
	}
	rest := html[i+len(marker):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func truncate(s string) string {
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// cookieJar is a minimal single-host jar; net/http/cookiejar would need a public
// suffix list to accept cookies from a bare test host.
type cookieJar struct{ cookies []*http.Cookie }

func (j *cookieJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		replaced := false
		for i, existing := range j.cookies {
			if existing.Name == c.Name {
				j.cookies[i] = c
				replaced = true
				break
			}
		}
		if !replaced {
			j.cookies = append(j.cookies, c)
		}
	}
}

func (j *cookieJar) Cookies(*url.URL) []*http.Cookie { return j.cookies }

func TestTokenEndpointThrottlesSecretGuesses(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	// The login form has always been throttled; the token endpoint was not, so a
	// wrong client_secret could be retried without limit.
	var lastError string
	for i := 0; i < maxAttempts+1; i++ {
		got := postForm(t, ts, "/oauth/token", url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {"meter"}, "client_secret": {"wrong"},
		})
		lastError, _ = got["error_description"].(string)
	}
	if !strings.Contains(lastError, "too many failed attempts") {
		t.Fatalf("after %d wrong secrets the endpoint still answered %q", maxAttempts+1, lastError)
	}

	// The lockout must be specific to the failing client, not a way to deny
	// service to every other app on the deployment.
	other := postForm(t, ts, "/oauth/token", url.Values{
		"grant_type": {"client_credentials"}, "scope": {"wallet"},
		"client_id": {"testapp"}, "client_secret": {"test-confidential-secret"},
	})
	if other["access_token"] == nil {
		t.Fatalf("a different client was locked out too: %v", other)
	}
}

func TestEmailVerifiedReflectsRealityNotAnAssumption(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")
	code := grantCode(t, ts, client, "testapp", "http://app.test/callback", "openid email", "", "")

	tok := postForm(t, ts, "/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {"testapp"}, "client_secret": {"test-confidential-secret"},
	})
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/user", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	defer resp.Body.Close()
	var profile map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Nothing verifies an address yet, so claiming it was verified would tell
	// every consuming app something untrue.
	if profile["email_verified"] != false {
		t.Fatalf("email_verified = %v for an unverified address", profile["email_verified"])
	}
}

func TestRevokeUserSessionsSignsEveryBrowserOut(t *testing.T) {
	ts, st := newTestServer(t)
	user := seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")

	resp, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("dashboard: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected a live session, got %d", resp.StatusCode)
	}

	// A password reset revokes sessions; leaving an intruder's alive would
	// defeat the point of resetting.
	if err := st.RevokeUserSessions(context.Background(), user.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp, err = client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("dashboard: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("the old session still works: got %d, want a redirect to login", resp.StatusCode)
	}
}

// seedAdmin creates an administrator account.
func seedAdmin(t *testing.T, st *store.Store, email, password string) store.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	u, err := st.CreateUser(context.Background(), "Admin", email, "", string(hash), true)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	return u
}

func TestOnlyAnAdminCanManageAccounts(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "member@nabuxai.com", "correct-horse-battery")

	// Signed out entirely. The client must not follow the redirect, or the 302
	// to /login is invisible and the assertion tests nothing.
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noFollow.Get(ts.URL + "/admin/users")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("anonymous got %d, want a redirect to login", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login") {
		t.Fatalf("anonymous was sent to %q, want the login page", loc)
	}

	// Signed in, but an ordinary member. The gate is the account flag, not the
	// URL prefix.
	member := signIn(t, ts, "member@nabuxai.com", "correct-horse-battery")
	resp, err = member.Get(ts.URL + "/admin/users")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a member got %d, want 403", resp.StatusCode)
	}
}

func TestAdminCreatesAnAccountThatCanSignIn(t *testing.T) {
	ts, st := newTestServer(t)
	seedAdmin(t, st, "admin@nabuxai.com", "correct-horse-battery")
	admin := signIn(t, ts, "admin@nabuxai.com", "correct-horse-battery")

	page := getBody(t, admin, ts.URL+"/admin/users")
	csrf := extractInput(page, "csrf")
	if csrf == "" {
		t.Fatal("no csrf token on the admin page")
	}

	resp, err := admin.PostForm(ts.URL+"/admin/users", url.Values{
		"csrf": {csrf}, "email": {"teammate@nabuxai.com"}, "name": {"Teammate"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create returned %d", resp.StatusCode)
	}

	// The generated password is shown once; it has to actually work, or the page
	// hands out a credential nobody can use.
	password := passwordFromPage(string(body))
	if password == "" {
		t.Fatalf("no password shown after creating the account: %s", truncate(string(body)))
	}
	signIn(t, ts, "teammate@nabuxai.com", password)
}

func TestAdminCannotDisableTheirOwnAccount(t *testing.T) {
	ts, st := newTestServer(t)
	adminUser := seedAdmin(t, st, "admin@nabuxai.com", "correct-horse-battery")
	admin := signIn(t, ts, "admin@nabuxai.com", "correct-horse-battery")

	csrf := extractInput(getBody(t, admin, ts.URL+"/admin/users"), "csrf")
	resp, err := admin.PostForm(ts.URL+"/admin/users/active", url.Values{
		"csrf": {csrf}, "user_id": {strconv.FormatInt(adminUser.ID, 10)}, "active": {"no"},
	})
	if err != nil {
		t.Fatalf("toggle: %v", err)
	}
	resp.Body.Close()

	// On a one-admin deployment this would end administration entirely.
	fresh, err := st.UserByID(context.Background(), adminUser.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !fresh.IsActive {
		t.Fatal("the admin disabled themselves")
	}
}

func getBody(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// passwordFromPage pulls the one-time password out of the rendered admin page.
func passwordFromPage(html string) string {
	const marker = `class="balance" style="font-size:1.35rem">`
	i := strings.Index(html, marker)
	if i < 0 {
		return ""
	}
	rest := html[i+len(marker):]
	j := strings.Index(rest, "<")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}
