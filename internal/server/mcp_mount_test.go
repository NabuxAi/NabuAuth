package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nabuauth/internal/config"
	"nabuauth/internal/mcp"
	"nabuauth/web"
)

// Where /mcp is mounted is not a detail. This mux already carries a "GET /"
// pattern for the account page, and net/http panics at registration on a bare
// "/mcp" beside it — "/mcp matches more methods than GET /, but has a more
// specific path pattern". That panic happens while Handler() is building the
// routes, which is to say at boot, which is to say sign-in for the whole estate
// would be down because an MCP endpoint was added.
//
// So the mount is spelled out method by method, and this file is what keeps it
// that way. It builds the routes only: no database is touched, because none of
// these assertions is about one.
func mountTestServer(t *testing.T, m *mcp.Server) http.Handler {
	t.Helper()

	tmpl, err := web.Templates()
	if err != nil {
		t.Fatalf("templates: %v", err)
	}

	srv := &Server{
		cfg:  &config.Config{Server: config.Server{Issuer: "https://auth.nabuxai.test"}},
		log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		tmpl: tmpl,
	}

	// Handler() is the thing under test: it panics here or it does not.
	return srv.WithMCP(m).Handler()
}

func testMCP(t *testing.T, token string) *mcp.Server {
	t.Helper()

	m := mcp.New("nabuauth", mcp.Version, "/mcp", token, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// A nil Accounts is safe only because nothing here calls a tool: these
	// tests are about which handler a method and path reach, and they stop at
	// the token check. A tools/call assertion added to this file needs a real
	// fixture, or it panics inside the handler instead of failing an assertion.
	mcp.Register(m, &config.Config{Scopes: config.DefaultScopes}, nil)

	return m
}

func TestMountingMCPDoesNotBreakTheExistingRoutes(t *testing.T) {
	h := mountTestServer(t, testMCP(t, "mount-test-token"))

	// The account page still answers on "/", which is the pattern a bare
	// "/mcp" mount would have collided with.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code == http.StatusNotFound {
		t.Errorf("GET / = 404; mounting /mcp displaced the account page")
	}
}

func TestTheMountedEndpointAnswersEveryMethodItself(t *testing.T) {
	h := mountTestServer(t, testMCP(t, "mount-test-token"))

	// Not OPTIONS: cors answers that before the mux is reached, which is
	// correct — a preflight for an endpoint no browser client calls is refused
	// there rather than being given an opinion here.
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPut, http.MethodHead} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/mcp", nil))

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /mcp = %d, want 405 from the MCP handler rather than the account page or a 404", method, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != http.MethodPost {
			t.Errorf("%s /mcp Allow = %q, want POST", method, got)
		}
	}

	// And POST reaches the endpoint, where the token check refuses it.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /mcp with no token = %d, want 401", rec.Code)
	}
}

// The rule that differs from the surrounding code: no token means no route at
// all, rather than an open one. NabuGate's policy layer serves its API with no
// auth when no keys are configured; carrying that idiom here would publish
// every account in the estate.
func TestAnUnconfiguredMCPIsNotMountedAtAll(t *testing.T) {
	h := mountTestServer(t, testMCP(t, ""))

	// GET /mcp falls through to the account page's "GET /" pattern, which is
	// what "the path is not registered" looks like on this mux. The MCP
	// handler's own refusal — 405 with Allow: POST — must not appear.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mcp", nil))

	if rec.Code == http.StatusMethodNotAllowed && rec.Header().Get("Allow") == http.MethodPost {
		t.Errorf("GET /mcp was answered by the MCP handler despite no token being configured")
	}

	// POST reaches no handler of ours at all: the mux answers for the path it
	// does know, and the answer names the methods that path takes — not POST.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)))

	if rec.Code == http.StatusUnauthorized {
		t.Errorf("POST /mcp = 401; the endpoint is mounted and answering, and only its token check is refusing")
	}
	if strings.Contains(rec.Body.String(), "stateless streamable HTTP") {
		t.Errorf("POST /mcp reached the MCP handler: %s", rec.Body.String())
	}
	if got := rec.Header().Get("Allow"); strings.Contains(got, http.MethodPost) {
		t.Errorf("Allow = %q; POST /mcp is a route somewhere, and it should not be", got)
	}
}
