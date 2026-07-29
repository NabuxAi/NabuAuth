package server

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// urlQueryEscape is a short alias, since the SSO link builder uses it a lot.
func urlQueryEscape(s string) string { return url.QueryEscape(s) }

// handleUserInfo serves both /oauth/userinfo and /api/v1/user. The response
// shape is the one the published SDKs already consume, with the OIDC-standard
// claim names alongside it.
func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireScope(w, r, "")
	if !ok {
		return
	}
	// A service token has no user behind it, so there is no profile to return.
	if strings.HasPrefix(claims.Subject, "client:") {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":             "invalid_token",
			"error_description": "this is a service token; it represents no user",
		})
		return
	}
	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	user, err := s.store.UserByID(r.Context(), userID)
	if err != nil || !user.IsActive {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	body := map[string]any{
		"sub":        claims.Subject,
		"id":         user.ID,
		"name":       user.Name,
		"avatar_url": user.AvatarURL,
		"picture":    user.AvatarURL,
		"is_admin":   user.IsAdmin,
		"created_at": user.CreatedAt,
		"scopes":     claims.Scopes(),
		"scope":      claims.Scope,
		"client_id":  claims.ClientID,
	}
	// Email and phone are only in the response when the token was granted the
	// scope for them; a "profile"-only token must not leak contact details.
	if claims.HasScope("email") {
		body["email"] = user.Email
		body["email_verified"] = true
	}
	if claims.HasScope("profile") {
		body["phone"] = user.Phone
	}
	if claims.HasScope("wallet") {
		if wallet, err := s.store.WalletFor(r.Context(), user.ID); err == nil {
			body["wallet"] = map[string]any{
				"balance_cents": wallet.BalanceCents,
				"currency":      wallet.Currency,
			}
		}
	}
	writeJSON(w, http.StatusOK, body)
}

// handleApps lists the ecosystem apps. This is the JSON form of the launcher the
// dashboard renders, so an app can show the same grid without duplicating it.
func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
	clients, err := s.store.ListedClients(r.Context())
	if err != nil {
		s.log.Error("list apps", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	apps := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		redirect := ""
		if len(c.RedirectURIs) > 0 {
			redirect = c.RedirectURIs[0]
		}
		apps = append(apps, map[string]any{
			"id":          c.ClientID,
			"name":        c.Name,
			"description": c.Description,
			"icon":        c.Icon,
			"url":         c.AppURL,
			"badge":       c.Badge,
			"sso_url":     s.ssoURL(c.ClientID, redirect, c.Scopes),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": apps})
}

// ssoURL builds the "sign in to this app" link shown in the launcher.
func (s *Server) ssoURL(clientID, redirectURI string, scopes []string) string {
	q := make([]string, 0, 4)
	q = append(q, "client_id="+urlQueryEscape(clientID), "response_type=code")
	if redirectURI != "" {
		q = append(q, "redirect_uri="+urlQueryEscape(redirectURI))
	}
	if len(scopes) > 0 {
		q = append(q, "scope="+urlQueryEscape(strings.Join(scopes, " ")))
	}
	return s.cfg.Server.Issuer + "/oauth/authorize?" + strings.Join(q, "&")
}
