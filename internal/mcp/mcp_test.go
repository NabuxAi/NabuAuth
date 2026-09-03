// The MCP endpoint's contract, pinned.
//
// NabuAuth is the one account every Nabu product signs in against and the
// wallet every product spends from, so the rows behind these tools sit beside
// password hashes, client secrets and refresh tokens. The properties worth a
// test are therefore: no token is 401, a wrong token is 401, a token that is
// the right one plus a suffix is 401, GET is 405, a notification gets 202 and
// no body, the four methods answer in the exact envelope a client expects, and
// no response — success or failure — ever contains a secret.
//
// The fixture is a fake store rather than a Postgres database: the server's own
// tests need a real one because they test what the database refuses to do
// twice, but nothing here is about that, and a suite that skips itself proves
// nothing about a read-only endpoint's blast radius.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nabuauth/internal/config"
	"nabuauth/internal/store"
)

// The needles. Each one is a real secret of this service, seeded into the
// fixture, and no response body in any test may contain it.
const (
	// theAppSecret is what NABUAUTH_SECRET_TESTAPP holds in the fixture.
	theAppSecret = "nabuauth-client-secret-must-never-appear"
	// theProviderSecret is a login method's client secret.
	theProviderSecret = "google-oauth-client-secret-must-never-appear"
	// thePasswordHash is bcrypt-shaped, because that is the shape a careless
	// tool would carry out of a store.User row.
	thePasswordHash = "$2a$10$CwTycUXWue0Thq9StjUM0uJ8e1FhO0GJ0ZBQ0mCk8mCk8mCk8mCk8"
	// theRefreshToken stands for the opaque credentials the store holds beside
	// the accounts these tools read.
	theRefreshToken = "rt-live-0000-must-never-appear"
)

const testToken = "mcp-test-token"

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// fakeAccounts is the four reads Accounts declares, over a slice. It is the
// whole of the store this package can see, which is the point of the interface.
type fakeAccounts struct {
	users   []store.User
	wallets map[int64]store.Wallet
	ledger  map[int64][]store.Transaction
}

func (f *fakeAccounts) ListUsers(_ context.Context, limit int) ([]store.User, error) {
	if limit <= 0 || limit > len(f.users) {
		limit = len(f.users)
	}

	return f.users[:limit], nil
}

func (f *fakeAccounts) UserByID(_ context.Context, id int64) (store.User, error) {
	for _, u := range f.users {
		if u.ID == id {
			return u, nil
		}
	}

	return store.User{}, store.ErrNotFound
}

func (f *fakeAccounts) ReadWalletFor(_ context.Context, userID int64) (store.Wallet, error) {
	w, ok := f.wallets[userID]
	if !ok {
		return store.Wallet{}, store.ErrNotFound
	}

	return w, nil
}

func (f *fakeAccounts) Transactions(_ context.Context, userID int64, limit int) ([]store.Transaction, error) {
	rows := f.ledger[userID]
	if limit > 0 && limit < len(rows) {
		rows = rows[:limit]
	}

	return rows, nil
}

func newTestServer(t *testing.T) http.Handler {
	t.Helper()

	// Both halves of a secret are in reach of a careless tool: the value the
	// process holds, and the name of the variable it arrives in — which is a
	// map of where to look. Every response is checked for both.
	t.Setenv("NABUAUTH_SECRET_TESTAPP", theAppSecret)
	t.Setenv("NABUAUTH_PROVIDER_SECRET_GOOGLE", theProviderSecret)

	cfg := &config.Config{
		Server: config.Server{Port: 8099, Issuer: "https://auth.nabuxai.test"},
		Scopes: config.DefaultScopes,
		Apps: []config.App{
			{
				ID:           "testapp",
				Name:         "Test App",
				URL:          "https://app.test",
				RedirectURIs: []string{"https://app.test/callback"},
				Scopes:       []string{"openid", "profile", "email", "wallet"},
				SecretEnv:    "NABUAUTH_SECRET_TESTAPP",
			},
			{
				ID:           "spa",
				Name:         "Public SPA",
				URL:          "https://spa.test",
				RedirectURIs: []string{"https://spa.test/callback"},
				Scopes:       []string{"openid", "profile"},
				Public:       true,
				Hidden:       true,
			},
		},
		LoginMethods: []config.Provider{{
			ID:           "google",
			Name:         "Google",
			AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			UserinfoURL:  "https://openidconnect.googleapis.com/v1/userinfo",
			ClientID:     "1234.apps.googleusercontent.com",
			SecretEnv:    "NABUAUTH_PROVIDER_SECRET_GOOGLE",
		}},
		MCP: config.MCP{Enabled: true, Path: "/mcp", TokenEnv: "NABUAUTH_MCP_TOKEN"},
	}

	created := time.Date(2026, 1, 1, 9, 30, 0, 0, time.UTC)
	accounts := &fakeAccounts{
		users: []store.User{
			{
				ID: 7, Name: "Hussein", Email: "hussein@nabuxai.test", Username: "hussein",
				// Seeded on purpose: an empty hash would make the secret test
				// pass while proving nothing.
				PasswordHash: thePasswordHash,
				IsActive:     true, IsAdmin: true, CreatedAt: created,
			},
			{
				ID: 8, Name: "Disabled Person", Email: "gone@nabuxai.test", Username: "gone",
				PasswordHash: thePasswordHash, IsActive: false, CreatedAt: created,
			},
		},
		wallets: map[int64]store.Wallet{
			7: {ID: 1, UserID: 7, BalanceCents: 12_500, Currency: "USD"},
		},
		ledger: map[int64][]store.Transaction{
			7: {{
				ID: 41, Type: "debit", AmountCents: -250, BalanceAfterCents: 12_500,
				Description: "NabuGate completion",
				// Meta is free-form and written by whichever app charged the
				// wallet. Here it carries a credential, because that is exactly
				// what a careless app could put there — and the tool must still
				// not carry it out.
				Meta:      map[string]any{"client_id": "testapp", "refresh_token": theRefreshToken},
				CreatedAt: created,
			}},
		},
	}

	srv := New("nabuauth", Version, cfg.MCP.Path, testToken, slog.New(slog.NewTextHandler(discard{}, nil)))
	Register(srv, cfg, accounts)

	return srv.Handler()
}

// newTestServerTracking is newTestServer with the accounts port wrapped so a
// write can be observed. Kept beside it so the two cannot drift.
func newTestServerTracking(t *testing.T, tracker *writeTrackingAccounts) http.Handler {
	t.Helper()

	t.Setenv("NABUAUTH_SECRET_TESTAPP", theAppSecret)
	t.Setenv("NABUAUTH_PROVIDER_SECRET_GOOGLE", theProviderSecret)

	cfg := &config.Config{
		Server: config.Server{Port: 8099, Issuer: "https://auth.nabuxai.test"},
		Scopes: config.DefaultScopes,
	}

	created := time.Date(2026, 1, 1, 9, 30, 0, 0, time.UTC)
	tracker.fakeAccounts = &fakeAccounts{
		users:   []store.User{{ID: 7, Name: "Hussein", Email: "h@nabuxai.test", IsActive: true, CreatedAt: created}},
		wallets: map[int64]store.Wallet{7: {ID: 1, UserID: 7, BalanceCents: 12_500, Currency: "USD"}},
		ledger:  map[int64][]store.Transaction{},
	}

	srv := New("nabuauth", Version, cfg.MCP.Path, testToken, slog.New(slog.NewTextHandler(discard{}, nil)))
	Register(srv, cfg, tracker)

	return srv.Handler()
}

// post sends one JSON-RPC body and returns the recorder.
func post(t *testing.T, h http.Handler, token, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

// rpc is the shape every answer is decoded into.
type rpc struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) rpc {
	t.Helper()

	var out rpc
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}

	return out
}

// toolResult is the tools/call envelope, decoded.
type toolResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

func decodeTool(t *testing.T, got rpc) toolResult {
	t.Helper()

	if got.Error != nil {
		t.Fatalf("want a result, got JSON-RPC error %d: %s", got.Error.Code, got.Error.Message)
	}

	var out toolResult
	if err := json.Unmarshal(got.Result, &out); err != nil {
		t.Fatalf("decode result: %v", err)
	}

	return out
}

// The gate. Without this the endpoint hands an anonymous caller every account
// in the estate and the balance of every wallet.
func TestTheEndpointRefusesAnythingButTheConfiguredToken(t *testing.T) {
	h := newTestServer(t)

	cases := []struct {
		name  string
		token string
		want  int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"wrong token", "not-the-token", http.StatusUnauthorized},
		// The compare is constant-time over the whole value, so a caller who
		// guessed the prefix has guessed nothing.
		{"token with the right prefix", testToken + "-extra", http.StatusUnauthorized},
		{"the configured token", testToken, http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(t, h, tc.token, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// A client that opens the SSE stream or tears a session down must be told this
// endpoint is POST-only rather than that the path does not exist.
func TestNonPostIsRefusedWith405(t *testing.T) {
	h := newTestServer(t)

	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		req := httptest.NewRequest(method, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+testToken)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /mcp = %d, want 405", method, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != http.MethodPost {
			t.Errorf("%s /mcp Allow = %q, want POST", method, got)
		}
	}
}

// notifications/initialized arrives immediately after initialize and carries no
// id. Answering it with a JSON-RPC result and a null id is the classic way a
// hand-rolled server breaks a client, so the 202 is pinned.
func TestNotificationsGetAcceptedWithNoBody(t *testing.T) {
	rec := post(t, newTestServer(t), testToken, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("notification = %d, want 202", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "" {
		t.Errorf("notification answered with a body: %s", body)
	}
}

func TestInitializeAnswersTheExactHandshake(t *testing.T) {
	rec := post(t, newTestServer(t), testToken,
		`{"jsonrpc":"2.0","id":"abc","method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)

	got := decode(t, rec)

	if got.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want 2.0", got.JSONRPC)
	}
	// A string id must come back as the same string, not as a number or null.
	if string(got.ID) != `"abc"` {
		t.Errorf("id = %s, want \"abc\"", got.ID)
	}

	var result struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(got.Result, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}

	if result.ProtocolVersion != ProtocolVersion {
		t.Errorf("protocolVersion = %q, want %q", result.ProtocolVersion, ProtocolVersion)
	}
	if _, ok := result.Capabilities["tools"]; !ok {
		t.Errorf("capabilities = %v, want a tools entry", result.Capabilities)
	}
	if result.ServerInfo.Name != "nabuauth" {
		t.Errorf("serverInfo.name = %q, want nabuauth", result.ServerInfo.Name)
	}
}

// ping is the liveness check every client sends. result must be present and
// empty, not omitted.
func TestPingAnswersWithAnEmptyResult(t *testing.T) {
	got := decode(t, post(t, newTestServer(t), testToken, `{"jsonrpc":"2.0","id":7,"method":"ping"}`))

	if got.Error != nil {
		t.Fatalf("ping errored: %d %s", got.Error.Code, got.Error.Message)
	}
	if string(got.ID) != "7" {
		t.Errorf("id = %s, want the number 7 back unchanged", got.ID)
	}
	if string(got.Result) != "{}" {
		t.Errorf("result = %s, want an empty object that is present rather than omitted", got.Result)
	}
}

// Every tool this service exposes is named here. The test fails when a tool is
// added or renamed, which is the point: the name is the contract four services
// share, and a drifted one is only noticed by the client that breaks.
func TestToolsListIsExactlyTheDeclaredSet(t *testing.T) {
	rec := post(t, newTestServer(t), testToken, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	var result struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(decode(t, rec).Result, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}

	// Sorted the way sort.Strings sorts, which is why user_get precedes
	// users_list: '_' sorts before 's'.
	want := []string{
		"nabuauth_apps_list",
		"nabuauth_login_methods_list",
		"nabuauth_scopes_list",
		"nabuauth_user_get",
		"nabuauth_users_list",
		"nabuauth_wallet_get",
	}

	if len(result.Tools) != len(want) {
		t.Fatalf("tools = %d, want %d", len(result.Tools), len(want))
	}

	for i, name := range want {
		if result.Tools[i].Name != name {
			t.Errorf("tool %d = %q, want %q (the list must be sorted)", i, result.Tools[i].Name, name)
		}
		if result.Tools[i].Description == "" {
			t.Errorf("tool %q has no description", name)
		}
		if result.Tools[i].InputSchema["type"] != "object" {
			t.Errorf("tool %q inputSchema type = %v, want object", name, result.Tools[i].InputSchema["type"])
		}
		if _, ok := result.Tools[i].InputSchema["properties"]; !ok {
			t.Errorf("tool %q inputSchema has no properties map, not even an empty one", name)
		}
	}
}

// No tool may write. The verb set is closed to list/get/search precisely so a
// debit or a top-up cannot appear here without the contract changing first.
func TestNoToolIsAWrite(t *testing.T) {
	rec := post(t, newTestServer(t), testToken, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(decode(t, rec).Result, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}

	for _, tool := range result.Tools {
		if !strings.HasPrefix(tool.Name, "nabuauth_") {
			t.Errorf("tool %q is not prefixed with the service name, so it can collide with another server's", tool.Name)
		}

		switch {
		case strings.HasSuffix(tool.Name, "_list"),
			strings.HasSuffix(tool.Name, "_get"),
			strings.HasSuffix(tool.Name, "_search"):
		default:
			t.Errorf("tool %q ends in a verb outside the closed read-only set; a wallet write must extend the contract first", tool.Name)
		}
	}
}

// The two failure kinds, kept apart. A model can act on "no such account"; only
// whoever wrote the client can act on "no such tool".
func TestFailuresAreSortedIntoTheRightEnvelope(t *testing.T) {
	h := newTestServer(t)

	cases := []struct {
		name     string
		body     string
		wantRPC  int  // JSON-RPC error code, 0 for none
		wantTool bool // result.isError
	}{
		{
			name:    "unknown method",
			body:    `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`,
			wantRPC: CodeMethodNotFound,
		},
		{
			name:    "unknown tool",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_wallet_debit","arguments":{}}}`,
			wantRPC: CodeMethodNotFound,
		},
		{
			name:    "params that are not an object",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"nope"}`,
			wantRPC: CodeInvalidParams,
		},
		{
			name:     "a missing required argument",
			body:     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_user_get","arguments":{}}}`,
			wantTool: true,
		},
		{
			name:     "an id that is not an account id",
			body:     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_user_get","arguments":{"id":"seven"}}}`,
			wantTool: true,
		},
		{
			name:     "an id that is not in the store",
			body:     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_user_get","arguments":{"id":"404"}}}`,
			wantTool: true,
		},
		{
			name:     "a wallet for an account that does not exist",
			body:     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_wallet_get","arguments":{"user_id":"404"}}}`,
			wantTool: true,
		},
		{
			name:     "a query that matched nothing",
			body:     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_users_list","arguments":{"query":"nobody-by-that-name"}}}`,
			wantTool: true,
		},
		{
			name: "a tool called with no arguments key at all",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_apps_list"}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(t, h, testToken, tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: a JSON-RPC failure is still an HTTP 200", rec.Code)
			}

			got := decode(t, rec)

			if tc.wantRPC != 0 {
				if got.Error == nil {
					t.Fatalf("want JSON-RPC error %d, got result %s", tc.wantRPC, got.Result)
				}
				if got.Error.Code != tc.wantRPC {
					t.Errorf("error code = %d, want %d", got.Error.Code, tc.wantRPC)
				}

				return
			}

			result := decodeTool(t, got)

			if result.IsError != tc.wantTool {
				t.Errorf("isError = %v, want %v", result.IsError, tc.wantTool)
			}
			if len(result.Content) != 1 || result.Content[0].Type != "text" {
				t.Fatalf("content = %+v, want exactly one text block", result.Content)
			}
		})
	}
}

// An unparseable body is a parse error with no id, because none could be read.
func TestAnUnparseableBodyIsAParseError(t *testing.T) {
	rec := post(t, newTestServer(t), testToken, `not json at all`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	got := decode(t, rec)
	if got.Error == nil || got.Error.Code != CodeParseError {
		t.Fatalf("want a %d parse error, got %+v", CodeParseError, got)
	}
}

// A successful call carries its payload as JSON inside a text block, not as a
// bare object in content.
func TestASuccessfulCallCarriesJSONInsideATextBlock(t *testing.T) {
	h := newTestServer(t)

	t.Run("one account", func(t *testing.T) {
		result := decodeTool(t, decode(t, post(t, h, testToken,
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_user_get","arguments":{"id":"7"}}}`)))

		if result.IsError {
			t.Fatalf("isError set on an account that exists: %+v", result.Content)
		}

		var user struct {
			ID        int64  `json:"id"`
			Handle    string `json:"handle"`
			Email     string `json:"email"`
			Admin     bool   `json:"admin"`
			Active    bool   `json:"active"`
			CreatedAt string `json:"created_at"`
		}
		if err := json.Unmarshal([]byte(result.Content[0].Text), &user); err != nil {
			t.Fatalf("the text block must be the JSON payload: %v (%q)", err, result.Content[0].Text)
		}

		if user.ID != 7 || user.Handle != "hussein" || !user.Admin || !user.Active {
			t.Errorf("payload = %+v, want the seeded administrator", user)
		}
		if user.CreatedAt != "2026-01-01T09:30:00Z" {
			t.Errorf("created_at = %q, want a UTC timestamp", user.CreatedAt)
		}
	})

	t.Run("a numeric id is accepted too", func(t *testing.T) {
		result := decodeTool(t, decode(t, post(t, h, testToken,
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_user_get","arguments":{"id":7}}}`)))

		if result.IsError {
			t.Fatalf("a JSON number id was refused: %+v", result.Content)
		}
	})

	t.Run("a disabled account is listed rather than hidden", func(t *testing.T) {
		result := decodeTool(t, decode(t, post(t, h, testToken,
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_users_list","arguments":{"query":"gone"}}}`)))

		var payload struct {
			Users []struct {
				ID     int64 `json:"id"`
				Active bool  `json:"active"`
			} `json:"users"`
		}
		if err := json.Unmarshal([]byte(result.Content[0].Text), &payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}

		if len(payload.Users) != 1 || payload.Users[0].ID != 8 || payload.Users[0].Active {
			t.Errorf("users = %+v, want the one disabled account marked inactive", payload.Users)
		}
	})

	t.Run("a wallet and its movements", func(t *testing.T) {
		result := decodeTool(t, decode(t, post(t, h, testToken,
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_wallet_get","arguments":{"user_id":"7"}}}`)))

		if result.IsError {
			t.Fatalf("isError set on a wallet that exists: %+v", result.Content)
		}

		var wallet struct {
			UserID       int64  `json:"user_id"`
			BalanceCents int64  `json:"balance_cents"`
			Currency     string `json:"currency"`
			Movements    []struct {
				Type        string          `json:"type"`
				AmountCents int64           `json:"amount_cents"`
				Meta        json.RawMessage `json:"meta"`
			} `json:"movements"`
		}
		if err := json.Unmarshal([]byte(result.Content[0].Text), &wallet); err != nil {
			t.Fatalf("decode payload: %v", err)
		}

		if wallet.UserID != 7 || wallet.BalanceCents != 12_500 || wallet.Currency != "USD" {
			t.Errorf("wallet = %+v, want the seeded balance", wallet)
		}
		if len(wallet.Movements) != 1 || wallet.Movements[0].AmountCents != -250 {
			t.Fatalf("movements = %+v, want the one seeded debit", wallet.Movements)
		}
		// Meta is written by whichever app charged the wallet, so nothing in
		// this repo controls what is in it. It must not travel.
		if wallet.Movements[0].Meta != nil {
			t.Errorf("a movement carried its free-form meta: %s", wallet.Movements[0].Meta)
		}
	})
}

// The rule the whole endpoint exists under: whatever a caller asks for, and
// however it fails, no secret comes back. Every method, every tool, every
// failure path, checked against the same needles.
//
// These needles are NabuAuth's own. Copying another service's list here would
// leave the tests green while this service leaked its own secrets, which is the
// exact failure this test is written against.
func TestNoResponseEverContainsASecret(t *testing.T) {
	h := newTestServer(t)

	bodies := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_apps_list","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_scopes_list","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_login_methods_list","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_users_list","arguments":{"limit":200}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_users_list","arguments":{"query":"hussein"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_user_get","arguments":{"id":"7"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_user_get","arguments":{"id":"404"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_wallet_get","arguments":{"user_id":"7","limit":100}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_wallet_get","arguments":{"user_id":"404"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"nope"}`,
		`not json at all`,
	}

	needles := []string{
		// The values.
		theAppSecret,
		theProviderSecret,
		thePasswordHash,
		theRefreshToken,
		// The MCP token itself: an echo of it in an error message would put it
		// in the client's transcript.
		testToken,
		// The names of the variables the secrets arrive in. A name is a map of
		// where to look, so it is withheld too.
		"NABUAUTH_SECRET_TESTAPP",
		"NABUAUTH_PROVIDER_SECRET_GOOGLE",
		"NABUAUTH_MCP_TOKEN",
		// The field names a leak would arrive under.
		"secret_env",
		"client_secret",
		"password_hash",
		"refresh_token",
		// A provider's client id is not a password, but it is half a credential
		// and nothing here has a reason to publish it.
		"1234.apps.googleusercontent.com",
	}

	for _, body := range bodies {
		got := post(t, h, testToken, body).Body.String()

		for _, needle := range needles {
			if strings.Contains(got, needle) {
				t.Errorf("response to %s leaked %q: %s", body, needle, got)
			}
		}
	}
}

// The transport's own refusals are house-shaped, not JSON-RPC envelopes: a
// caller that failed the token check has no session for an envelope to belong
// to. They must not leak either.
func TestTransportRefusalsAreHouseShapedAndCarryNoSecret(t *testing.T) {
	h := newTestServer(t)

	rec := post(t, h, "not-the-token", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	var out struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
		JSONRPC string `json:"jsonrpc"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}

	if out.JSONRPC != "" {
		t.Errorf("a 401 came back as a JSON-RPC envelope; the client has no session yet")
	}
	if out.Error.Message != "invalid or missing MCP token" {
		t.Errorf("401 message = %q, want the fixed house message", out.Error.Message)
	}
	if strings.Contains(rec.Body.String(), testToken) || strings.Contains(rec.Body.String(), "not-the-token") {
		t.Errorf("the 401 echoed a token back: %s", rec.Body.String())
	}
}

// An unset token means the route is never mounted. There is no open mode, and
// this is the rule most likely to be got wrong by copying the surrounding code.
func TestAnUnsetTokenLeavesTheServerDisabled(t *testing.T) {
	srv := New("nabuauth", Version, "/mcp", "", slog.New(slog.NewTextHandler(discard{}, nil)))

	if srv.Enabled() {
		t.Fatal("a server with no token reports itself enabled; Handler() would then be mounted with no auth at all")
	}

	// And if it were mounted anyway, it still refuses everything.
	rec := post(t, srv.Handler(), "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 even when the server was mounted by mistake", rec.Code)
	}
}

// A tool error that is not a *ToolFailure is replaced wholesale, because a
// driver error's text is where a connection string — and its password — ends up.
func TestAnUnexpectedToolErrorIsReplacedRatherThanForwarded(t *testing.T) {
	srv := New("nabuauth", Version, "/mcp", testToken, slog.New(slog.NewTextHandler(discard{}, nil)))
	srv.Register(Tool{
		Name:        "nabuauth_broken_get",
		Description: "A tool that fails the way a database does.",
		InputSchema: ObjectSchema(nil, nil),
		Handler: func(context.Context, map[string]any) (any, error) {
			return nil, errors.New("dial postgres://nabuauth:hunter2@db:5432: connection refused")
		},
	})

	result := decodeTool(t, decode(t, post(t, srv.Handler(), testToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nabuauth_broken_get"}}`)))

	if !result.IsError {
		t.Fatal("an unexpected error came back as a success")
	}
	if strings.Contains(result.Content[0].Text, "hunter2") {
		t.Fatalf("the driver's error text reached the model: %q", result.Content[0].Text)
	}
	if result.Content[0].Text != "this tool failed; the reason is in the service log" {
		t.Errorf("message = %q, want the fixed replacement", result.Content[0].Text)
	}
}

// TestNoToolWritesThroughTheAccountsPort is the property TestNoToolIsAWrite was
// named after but did not check: that one only asserted on tool *names*.
//
// The concrete bug it would have caught: nabuauth_wallet_get called
// store.WalletFor, which is `INSERT INTO wallets ... ON CONFLICT DO UPDATE`. A
// tool advertised as read-only created a wallet row for any id it was handed and
// touched updated_at on every existing one — on the service that holds the
// shared wallet.
//
// So this drives every tool through a port that fails the test the moment a
// write method is called, rather than trusting the naming.
func TestNoToolWritesThroughTheAccountsPort(t *testing.T) {
	// The shared harness already seeds a user with a wallet and a ledger; this
	// wraps its account port so any write shows up.
	writes := &writeTrackingAccounts{}
	h := newTestServerTracking(t, writes)

	var listed struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	body := post(t, h, testToken, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`).Body.Bytes()
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatalf("tools/list did not decode: %v", err)
	}
	if len(listed.Result.Tools) == 0 {
		t.Fatal("tools/list returned nothing, so this test would pass vacuously")
	}

	// Prove the detector fires before trusting that it stayed silent. Without
	// this, a rename of the tracked method would turn the whole test green and
	// mean nothing.
	if _, _ = writes.WalletFor(context.Background(), 7); writes.wrote == "" {
		t.Fatal("the write tracker did not fire on a direct call, so its silence below proves nothing")
	}
	writes.wrote = ""

	for _, tool := range listed.Result.Tools {
		// Arguments every tool tolerates: unknown keys are ignored, and the
		// ones that need a user_id get a real one.
		call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` +
			tool.Name + `","arguments":{"user_id":"1","id":"1","limit":5}}}`
		post(t, h, testToken, call)

		if writes.wrote != "" {
			t.Fatalf("%s called %s, which writes — a read-only tool must not", tool.Name, writes.wrote)
		}
	}
}

// writeTrackingAccounts records any call to a method that mutates.
type writeTrackingAccounts struct {
	*fakeAccounts
	wrote string
}

// WalletFor is the upsert. Reaching it from a tool is the failure.
func (w *writeTrackingAccounts) WalletFor(ctx context.Context, userID int64) (store.Wallet, error) {
	w.wrote = "WalletFor (INSERT ... ON CONFLICT DO UPDATE)"
	return store.Wallet{}, nil
}

// TestOnlyTheBearerSchemeAuthenticates pins what the comment on authorised
// claims. TrimPrefix is a no-op when the prefix is absent, so the earlier
// implementation accepted a bare token as a second valid shape — a second place
// for it to leak from, which is the thing the comment rules out.
func TestOnlyTheBearerSchemeAuthenticates(t *testing.T) {
	h := newTestServer(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`

	for _, header := range []string{
		testToken,             // no scheme at all
		"bearer " + testToken, // lowercase scheme
		"Basic " + testToken,  // a different scheme
		"Token " + testToken,
	} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		req.Header.Set("Authorization", header)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Authorization: %q returned %d, want 401", header, rec.Code)
		}
	}

	// And the correct shape still works, so this is not passing by rejecting all.
	if got := post(t, h, testToken, body).Code; got != http.StatusOK {
		t.Fatalf("a correct Bearer header returned %d, want 200", got)
	}
}
