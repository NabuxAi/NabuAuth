package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"nabuauth/internal/config"
	"nabuauth/internal/store"
	"nabuauth/internal/tokens"
)

// External sign-in methods. Every provider here is an ordinary OIDC
// authorization-code client, so one implementation covers Google, Microsoft, an
// enterprise IdP or another Nabu deployment — a deployment adds one by naming
// its three endpoints and a client secret, not by shipping new code.
//
// The account is matched on the email the provider asserts, and only when the
// provider says it verified that email. Without that check, any provider that
// lets a user type an address becomes a way into somebody else's Nabu account.

const (
	// providerStateCookie carries the CSRF state and the post-sign-in
	// destination across the round trip to the provider.
	providerStateCookie = "nabuauth_provider"

	providerStateTTL = 15 * time.Minute
)

// handleProviderStart sends the browser to the external provider.
func (s *Server) handleProviderStart(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.cfg.LoginMethod(r.PathValue("provider"))
	if !ok {
		s.render(w, http.StatusNotFound, "error.html", map[string]any{
			"Title":   "Unknown sign-in method",
			"Message": "That sign-in method is not available here.",
		})
		return
	}

	state, _, err := tokens.NewOpaque()
	if err != nil {
		s.log.Error("provider state", "error", err)
		s.renderLogin(w, r, http.StatusInternalServerError, "", "", "Could not start that sign-in. Try again.")
		return
	}

	next := safeNext(r.URL.Query().Get("next"))
	// The cookie holds both halves: what came back has to match a flow this
	// browser started, and the destination must not travel through the provider
	// where a crafted link could rewrite it.
	http.SetCookie(w, &http.Cookie{
		Name:     providerStateCookie,
		Value:    provider.ID + ":" + state + ":" + next,
		Path:     "/",
		MaxAge:   int(providerStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.Server.UseSecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, provider.AuthorizeURL+"?"+url.Values{
		"client_id":     {provider.ClientID},
		"redirect_uri":  {s.providerRedirectURI(provider)},
		"response_type": {"code"},
		"scope":         {strings.Join(provider.Scopes, " ")},
		"state":         {state},
	}.Encode(), http.StatusFound)
}

// handleProviderCallback finishes the round trip: exchange the code, read the
// profile, and sign the matching Nabu account in.
func (s *Server) handleProviderCallback(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.cfg.LoginMethod(r.PathValue("provider"))
	if !ok {
		s.render(w, http.StatusNotFound, "error.html", map[string]any{
			"Title":   "Unknown sign-in method",
			"Message": "That sign-in method is not available here.",
		})
		return
	}

	wantID, wantState, next := s.takeProviderState(w, r)
	fail := func(status int, msg string) {
		s.renderLogin(w, r, status, next, "", msg)
	}

	if err := r.URL.Query().Get("error"); err != "" {
		fail(http.StatusUnauthorized, provider.Name+" did not complete the sign-in ("+err+").")
		return
	}
	// A callback whose state does not match was not started here, so the code in
	// it is not ours to redeem.
	if wantState == "" || wantID != provider.ID || r.URL.Query().Get("state") != wantState {
		fail(http.StatusBadRequest, "That sign-in has expired. Please try again.")
		return
	}

	profile, err := s.exchangeWithProvider(r.Context(), provider, r.URL.Query().Get("code"))
	if err != nil {
		s.log.Error("provider exchange", "provider", provider.ID, "error", err)
		fail(http.StatusBadGateway, "Could not complete the "+provider.Name+" sign-in. Try again.")
		return
	}
	if profile.Email == "" || !profile.EmailVerified {
		// An unverified address proves nothing about who is signing in, and this
		// is the step where an account is handed over.
		fail(http.StatusForbidden, provider.Name+" did not confirm a verified email address for this account.")
		return
	}

	user, err := s.userForProvider(r, profile)
	if errors.Is(err, errSignUpClosed) {
		fail(http.StatusForbidden, "No Nabu account uses that address, and accounts here are created by an administrator.")
		return
	}
	if err != nil {
		s.log.Error("provider account", "provider", provider.ID, "error", err)
		fail(http.StatusInternalServerError, "Could not sign you in. Try again.")
		return
	}
	if !user.IsActive {
		fail(http.StatusForbidden, "This account is disabled.")
		return
	}
	if err := s.startSession(w, r, user.ID); err != nil {
		s.log.Error("start session", "error", err)
		fail(http.StatusInternalServerError, "Could not start a session. Try again.")
		return
	}
	if next == "" {
		next = "/dashboard"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// errSignUpClosed is returned when a provider asserts an address no account uses
// on a deployment where accounts are made by an administrator.
var errSignUpClosed = errors.New("sign-up is closed")

// providerProfile is the part of an OIDC userinfo response this server acts on.
type providerProfile struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// exchangeWithProvider redeems the authorization code and reads the profile.
func (s *Server) exchangeWithProvider(ctx context.Context, provider config.Provider, code string) (providerProfile, error) {
	if code == "" {
		return providerProfile{}, errors.New("no code in the callback")
	}
	client := &http.Client{Timeout: 10 * time.Second}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {s.providerRedirectURI(provider)},
		"client_id":     {provider.ClientID},
		"client_secret": {provider.Secret()},
	}
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return providerProfile{}, err
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Accept", "application/json")

	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return providerProfile{}, err
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		return providerProfile{}, errors.New("token endpoint returned " + tokenResp.Status)
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&token); err != nil {
		return providerProfile{}, err
	}
	if token.AccessToken == "" {
		return providerProfile{}, errors.New("token endpoint returned no access token")
	}

	infoReq, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.UserinfoURL, nil)
	if err != nil {
		return providerProfile{}, err
	}
	infoReq.Header.Set("Authorization", "Bearer "+token.AccessToken)
	infoReq.Header.Set("Accept", "application/json")

	infoResp, err := client.Do(infoReq)
	if err != nil {
		return providerProfile{}, err
	}
	defer infoResp.Body.Close()
	if infoResp.StatusCode != http.StatusOK {
		return providerProfile{}, errors.New("userinfo endpoint returned " + infoResp.Status)
	}
	var profile providerProfile
	if err := json.NewDecoder(infoResp.Body).Decode(&profile); err != nil {
		return providerProfile{}, err
	}
	profile.Email = strings.ToLower(strings.TrimSpace(profile.Email))
	return profile, nil
}

// userForProvider finds the Nabu account for a verified external identity,
// creating one where the deployment allows it.
func (s *Server) userForProvider(r *http.Request, profile providerProfile) (store.User, error) {
	user, err := s.store.UserByEmail(r.Context(), profile.Email)
	if err == nil {
		return user, nil
	}
	if !isNotFound(err) {
		return store.User{}, err
	}
	if !s.registrationOpen(r) {
		return store.User{}, errSignUpClosed
	}

	// The account has no local password and is never meant to be signed into
	// with one, so it gets a random value rather than an empty column somebody
	// could later match against.
	random, _, err := tokens.NewOpaque()
	if err != nil {
		return store.User{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(random), bcrypt.DefaultCost)
	if err != nil {
		return store.User{}, err
	}
	name := profile.Name
	if name == "" {
		name = nameFromEmail(profile.Email)
	}
	count, err := s.store.CountUsers(r.Context())
	if err != nil {
		return store.User{}, err
	}
	return s.store.CreateUser(r.Context(), name, profile.Email, "", string(hash), count == 0)
}

// providerRedirectURI is where the provider sends the browser back. It is
// derived from the issuer, so it is the same string at every step and matches
// what was registered with the provider.
func (s *Server) providerRedirectURI(provider config.Provider) string {
	return s.cfg.Server.Issuer + "/login/" + provider.ID + "/callback"
}

// takeProviderState reads and clears the round-trip cookie.
func (s *Server) takeProviderState(w http.ResponseWriter, r *http.Request) (providerID, state, next string) {
	c, err := r.Cookie(providerStateCookie)
	if err != nil || c.Value == "" {
		return "", "", ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     providerStateCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.Server.UseSecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
	parts := strings.SplitN(c.Value, ":", 3)
	if len(parts) != 3 {
		return "", "", ""
	}
	return parts[0], parts[1], safeNext(parts[2])
}
