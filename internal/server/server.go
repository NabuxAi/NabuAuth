// Package server exposes the NabuAuth HTTP surface: the OAuth2/OIDC endpoints,
// the account UI and the wallet API.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"nabuauth/internal/config"
	"nabuauth/internal/store"
	"nabuauth/internal/tokens"
	"nabuauth/web"
)

const (
	sessionCookie = "nabuauth_session"

	// maxRequestBytes caps request bodies. Every endpoint here takes a small
	// form or a small JSON object; nothing legitimate comes close.
	maxRequestBytes = 1 << 20
)

// Server wires config, storage and the keyring into an http.Handler.
type Server struct {
	cfg   *config.Config
	store *store.Store
	keys  *tokens.Keyring
	log   *slog.Logger
	tmpl  *template.Template

	accessTTL  time.Duration
	refreshTTL time.Duration
	sessionTTL time.Duration
	codeTTL    time.Duration

	throttle *throttle
}

// New builds the server.
func New(cfg *config.Config, st *store.Store, keys *tokens.Keyring, log *slog.Logger) (*Server, error) {
	tmpl, err := web.Templates()
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:        cfg,
		store:      st,
		keys:       keys,
		log:        log,
		tmpl:       tmpl,
		accessTTL:  config.Duration(cfg.Server.AccessTokenTTL, time.Hour),
		refreshTTL: config.Duration(cfg.Server.RefreshTokenTTL, 30*24*time.Hour),
		sessionTTL: config.Duration(cfg.Server.SessionTTL, 30*24*time.Hour),
		codeTTL:    config.Duration(cfg.Server.CodeTTL, 10*time.Minute),
		throttle:   newThrottle(),
	}, nil
}

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Discovery and keys.
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleDiscovery)
	mux.HandleFunc("GET /oauth/jwks.json", s.handleJWKS)

	// OAuth2.
	mux.HandleFunc("GET /oauth/authorize", s.handleAuthorize)
	mux.HandleFunc("POST /oauth/authorize", s.handleAuthorizeDecision)
	mux.HandleFunc("POST /oauth/token", s.handleToken)
	mux.HandleFunc("POST /oauth/introspect", s.handleIntrospect)
	mux.HandleFunc("POST /oauth/revoke", s.handleRevoke)
	mux.HandleFunc("GET /oauth/userinfo", s.handleUserInfo)
	mux.HandleFunc("POST /oauth/userinfo", s.handleUserInfo)
	mux.HandleFunc("GET /oauth/logout", s.handleLogout)

	// Resource API. /api/v1/user is the shape the published SDKs already call;
	// /oauth/userinfo is the OIDC-standard name for the same thing.
	mux.HandleFunc("GET /api/v1/user", s.handleUserInfo)
	mux.HandleFunc("GET /api/v1/apps", s.handleApps)
	mux.HandleFunc("GET /api/v1/wallet/balance", s.handleWalletBalance)
	mux.HandleFunc("GET /api/v1/wallet/transactions", s.handleWalletTransactions)
	mux.HandleFunc("POST /api/v1/wallet/topup", s.handleWalletTopup)
	mux.HandleFunc("POST /api/v1/wallet/debit", s.handleWalletDebit)

	// Account UI.
	mux.HandleFunc("GET /", s.handleHome)
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	mux.HandleFunc("GET /register", s.handleRegisterForm)
	mux.HandleFunc("POST /register", s.handleRegisterSubmit)
	mux.HandleFunc("POST /logout", s.handleLogoutSubmit)
	mux.HandleFunc("GET /dashboard", s.handleDashboard)
	mux.HandleFunc("POST /dashboard/revoke", s.handleRevokeApp)

	// Administrator pages. Sign-up is closed and every app treats a Nabu account
	// as the way in, so this is the path to a second person.
	mux.HandleFunc("GET /admin/users", s.handleAdminUsers)
	mux.HandleFunc("POST /admin/users", s.handleAdminCreateUser)
	mux.HandleFunc("POST /admin/users/active", s.handleAdminToggleUser)

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(web.Static()))))

	return s.recover(s.limitBody(mux))
}

// recover turns a handler panic into a 500 instead of killing the process and
// dropping every other in-flight request with it.
func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("panic serving request", "path", r.URL.Path, "value", v)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "issuer": s.cfg.Server.Issuer, "kid": s.keys.SigningKID()})
}

// ---------------------------------------------------------------- sessions

// currentUser resolves the browser session cookie, or reports no user.
func (s *Server) currentUser(r *http.Request) (store.User, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return store.User{}, false
	}
	u, err := s.store.SessionUser(r.Context(), tokens.HashOpaque(c.Value))
	if err != nil {
		return store.User{}, false
	}
	return u, true
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID int64) error {
	token, hash, err := tokens.NewOpaque()
	if err != nil {
		return err
	}
	expires := time.Now().Add(s.sessionTTL)
	if err := s.store.CreateSession(r.Context(), hash, userID, expires); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.cfg.Server.UseSecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Server) endSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		_ = s.store.DeleteSession(r.Context(), tokens.HashOpaque(c.Value))
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.Server.UseSecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

// ---------------------------------------------------------------- bearer auth

// bearer extracts and verifies an access token from the Authorization header.
func (s *Server) bearer(r *http.Request) (tokens.Claims, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return tokens.Claims{}, tokens.ErrInvalidToken
	}
	claims, err := s.keys.Verify(strings.TrimSpace(h[len("bearer "):]))
	if err != nil {
		return tokens.Claims{}, err
	}
	// An id_token is handed to the browser and is not a credential for this API.
	if claims.TokenType != "access" {
		return tokens.Claims{}, tokens.ErrInvalidToken
	}
	if claims.Issuer != s.cfg.Server.Issuer {
		return tokens.Claims{}, tokens.ErrInvalidToken
	}
	return claims, nil
}

// requireScope authenticates the request and checks one scope, writing the
// error response itself when either fails.
func (s *Server) requireScope(w http.ResponseWriter, r *http.Request, scope string) (tokens.Claims, bool) {
	claims, err := s.bearer(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="nabuauth", error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return tokens.Claims{}, false
	}
	if scope != "" && !claims.HasScope(scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":             "insufficient_scope",
			"error_description": "this token is missing the " + scope + " scope",
		})
		return tokens.Claims{}, false
	}
	return claims, true
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Tokens and profile data must never be cached by a proxy or the browser.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// encodeJSON writes a value without touching the caching headers, for responses
// like the JWKS that are meant to be cached.
func encodeJSON(w http.ResponseWriter, v any) error {
	return json.NewEncoder(w).Encode(v)
}

// csrfToken derives a per-session form token. It is a hash of the session
// cookie, so it needs no storage and an attacker who cannot read the cookie
// cannot produce it.
func (s *Server) csrfToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return ""
	}
	return tokens.HashOpaque("csrf:" + c.Value)
}

// checkCSRF verifies the token a form posted back.
func (s *Server) checkCSRF(r *http.Request) bool {
	want := s.csrfToken(r)
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(r.PostFormValue("csrf"))) == 1
}

// oauthError renders an RFC 6749 error body.
func oauthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Issuer"] = s.cfg.Server.Issuer
	data["AllowRegistration"] = s.cfg.Server.AllowRegistration
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("render template", "template", name, "error", err)
	}
}

// isNotFound reports whether an error came back as "no such row".
func isNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }

// scopeLabels turns scope names into the descriptions shown on the consent
// screen, so a user sees "Your email address" instead of "email".
func (s *Server) scopeLabels(scopes []string) []map[string]string {
	out := make([]map[string]string, 0, len(scopes))
	for _, sc := range scopes {
		label := s.cfg.Scopes[sc]
		if label == "" {
			label = sc
		}
		out = append(out, map[string]string{"Scope": sc, "Label": label})
	}
	return out
}

// SyncApps upserts every configured app into the client table. Called at boot so
// the config file is the source of truth for who may sign users in.
func (s *Server) SyncApps(ctx context.Context) error {
	return SyncApps(ctx, s.cfg, s.store, s.log)
}
