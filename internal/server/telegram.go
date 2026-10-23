package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"nabuauth/internal/store"
	"nabuauth/internal/tokens"
)

// Signing in with Telegram.
//
// Telegram is not an OpenID provider, so it is not one of the login_methods.
// Its login page (oauth.telegram.org) shows the person their own Telegram
// account, and on approval sends the browser back with the profile in the URL
// fragment, signed by HMAC-SHA256 under SHA-256 of the bot's token. Checking
// that signature is the whole proof: anyone holding the token could mint a
// profile, which is why the token never leaves the environment.
//
// The fragment is never sent to a server, so the return page is a small form a
// script fills from it and posts back. The post carries a one-time nonce from a
// cookie set when this browser started the flow: without it, somebody could
// make a victim's browser post the attacker's own signed profile and sign the
// victim in to the attacker's account.

const (
	telegramFlowCookie = "nabuauth_tg"
	telegramFlowTTL    = 10 * time.Minute
	// telegramMaxAge bounds how old a signed profile may be. Telegram's own
	// guidance is a day; a login that is not used within minutes is not a login
	// somebody is waiting on.
	telegramMaxAge = 10 * time.Minute
)

// telegramFlow is what the cookie remembers between leaving for Telegram and
// coming back.
type telegramFlow struct {
	Nonce string `json:"n"`
	Mode  string `json:"m"` // "signin" or "link"
	Next  string `json:"x,omitempty"`
}

// telegramProfile is the part of Telegram's answer this server keeps.
type telegramProfile struct {
	ID        int64
	FirstName string
	LastName  string
	Username  string
	PhotoURL  string
}

func (p telegramProfile) displayName() string {
	name := strings.TrimSpace(p.FirstName + " " + p.LastName)
	if name == "" && p.Username != "" {
		name = "@" + p.Username
	}
	if name == "" {
		name = "Telegram " + strconv.FormatInt(p.ID, 10)
	}
	return name
}

var (
	errTelegramSignature = errors.New("telegram signature does not match")
	errTelegramStale     = errors.New("telegram login is too old")
)

// verifyTelegram checks a tgAuthResult — base64 of the JSON profile Telegram
// signed — against the bot token, and returns the profile it vouches for.
func verifyTelegram(botToken, result string, now time.Time) (telegramProfile, error) {
	raw, err := decodeBase64Any(result)
	if err != nil {
		return telegramProfile{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Numbers stay the digits Telegram signed; a float64 round trip could print
	// a large id differently and break the signature.
	dec.UseNumber()
	var fields map[string]any
	if err := dec.Decode(&fields); err != nil {
		return telegramProfile{}, err
	}
	hash, _ := fields["hash"].(string)
	if hash == "" {
		return telegramProfile{}, errTelegramSignature
	}

	// The data-check-string: every field but the hash, as key=value lines in
	// key order.
	keys := make([]string, 0, len(fields))
	for k := range fields {
		if k != "hash" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		switch v := fields[k].(type) {
		case string:
			lines = append(lines, k+"="+v)
		case json.Number:
			lines = append(lines, k+"="+v.String())
		default:
			return telegramProfile{}, errTelegramSignature
		}
	}
	secret := sha256.Sum256([]byte(botToken))
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte(strings.Join(lines, "\n")))
	want := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(want), []byte(strings.ToLower(hash))) != 1 {
		return telegramProfile{}, errTelegramSignature
	}

	authDate, _ := fields["auth_date"].(json.Number)
	signedAt, err := authDate.Int64()
	if err != nil {
		return telegramProfile{}, errTelegramSignature
	}
	age := now.Sub(time.Unix(signedAt, 0))
	if age > telegramMaxAge || age < -time.Minute {
		return telegramProfile{}, errTelegramStale
	}

	idNum, _ := fields["id"].(json.Number)
	id, err := idNum.Int64()
	if err != nil || id <= 0 {
		return telegramProfile{}, errTelegramSignature
	}
	p := telegramProfile{ID: id}
	p.FirstName, _ = fields["first_name"].(string)
	p.LastName, _ = fields["last_name"].(string)
	p.Username, _ = fields["username"].(string)
	if photo, _ := fields["photo_url"].(string); strings.HasPrefix(photo, "https://") {
		p.PhotoURL = photo
	}
	return p, nil
}

func decodeBase64Any(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	var lastErr error
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		out, err := enc.DecodeString(s)
		if err == nil {
			return out, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// handleTelegramStart sends the browser to Telegram to sign in.
func (s *Server) handleTelegramStart(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Telegram.Configured() {
		s.telegramUnavailable(w, r)
		return
	}
	s.leaveForTelegram(w, r, telegramFlow{Mode: "signin", Next: safeNext(r.URL.Query().Get("next"))})
}

// handleTelegramLink starts the same trip from the account page, to connect a
// Telegram account to the signed-in one instead of signing in with it.
func (s *Server) handleTelegramLink(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if _, ok := s.currentUser(r); !ok {
		http.Redirect(w, r, "/login?next=%2Fdashboard", http.StatusFound)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "invalid form token", http.StatusForbidden)
		return
	}
	if !s.cfg.Telegram.Configured() {
		s.telegramUnavailable(w, r)
		return
	}
	s.leaveForTelegram(w, r, telegramFlow{Mode: "link"})
}

func (s *Server) leaveForTelegram(w http.ResponseWriter, r *http.Request, flow telegramFlow) {
	nonce, _, err := tokens.NewOpaque()
	if err != nil {
		s.log.Error("telegram nonce", "error", err)
		s.renderLogin(w, r, http.StatusInternalServerError, "", "", "Could not start that sign-in. Try again.")
		return
	}
	flow.Nonce = nonce
	raw, _ := json.Marshal(flow)
	http.SetCookie(w, &http.Cookie{
		Name:     telegramFlowCookie,
		Value:    base64.RawURLEncoding.EncodeToString(raw),
		Path:     "/login/telegram",
		MaxAge:   int(telegramFlowTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.Server.UseSecureCookies(),
		// Lax: the browser comes back from oauth.telegram.org by a top-level
		// navigation, which Strict would strip the cookie from.
		SameSite: http.SameSiteLaxMode,
	})
	issuer := strings.TrimRight(s.cfg.Server.Issuer, "/")
	q := url.Values{
		"bot_id":         {s.cfg.Telegram.BotID()},
		"origin":         {issuer},
		"request_access": {"write"},
		"return_to":      {issuer + "/login/telegram/callback"},
	}
	http.Redirect(w, r, "https://oauth.telegram.org/auth?"+q.Encode(), http.StatusFound)
}

// readTelegramFlow returns the flow this browser started, if it is intact.
func readTelegramFlow(r *http.Request) (telegramFlow, bool) {
	c, err := r.Cookie(telegramFlowCookie)
	if err != nil || c.Value == "" {
		return telegramFlow{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return telegramFlow{}, false
	}
	var flow telegramFlow
	if json.Unmarshal(raw, &flow) != nil || flow.Nonce == "" {
		return telegramFlow{}, false
	}
	return flow, true
}

func (s *Server) clearTelegramFlow(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: telegramFlowCookie, Value: "", Path: "/login/telegram", MaxAge: -1, HttpOnly: true, Secure: s.cfg.Server.UseSecureCookies(), SameSite: http.SameSiteLaxMode})
}

// handleTelegramReturn is where Telegram sends the browser back. The profile is
// in the fragment, out of the server's reach, so this page hands it back by
// form post with the flow's nonce.
func (s *Server) handleTelegramReturn(w http.ResponseWriter, r *http.Request) {
	flow, ok := readTelegramFlow(r)
	if !ok {
		s.renderLogin(w, r, http.StatusBadRequest, "", "", "That sign-in has expired. Please try again.")
		return
	}
	s.render(w, r, http.StatusOK, "telegram_return.html", map[string]any{
		"Title": "Signing in with Telegram",
		"Nonce": flow.Nonce,
		"Next":  flow.Next,
	})
}

// handleTelegramCallback checks the signed profile and signs in with it, or
// connects it to the signed-in account.
func (s *Server) handleTelegramCallback(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	flow, ok := readTelegramFlow(r)
	s.clearTelegramFlow(w)
	if !ok || subtle.ConstantTimeCompare([]byte(flow.Nonce), []byte(r.PostFormValue("nonce"))) != 1 {
		s.renderLogin(w, r, http.StatusBadRequest, "", "", "That sign-in has expired. Please try again.")
		return
	}
	if !s.cfg.Telegram.Configured() {
		s.telegramUnavailable(w, r)
		return
	}
	profile, err := verifyTelegram(s.cfg.Telegram.BotToken(), r.PostFormValue("result"), time.Now())
	if err != nil {
		s.log.Warn("telegram login refused", "error", err)
		s.renderLogin(w, r, http.StatusUnauthorized, flow.Next, "", "Telegram could not confirm that sign-in. Try again.")
		return
	}

	if flow.Mode == "link" {
		s.linkTelegram(w, r, profile)
		return
	}

	user, err := s.store.UserByTelegramID(r.Context(), profile.ID)
	created := false
	switch {
	case err == nil:
		if !user.IsActive {
			s.renderLogin(w, r, http.StatusForbidden, flow.Next, "", "This account is disabled.")
			return
		}
	case !isNotFound(err):
		s.log.Error("telegram lookup", "error", err)
		s.renderLogin(w, r, http.StatusInternalServerError, flow.Next, "", "Could not sign you in. Try again.")
		return
	case !s.registrationOpen(r):
		s.renderLogin(w, r, http.StatusForbidden, flow.Next, "", "No Nabu account is connected to that Telegram account. Sign in another way, then connect Telegram from your account page.")
		return
	default:
		user, err = s.createTelegramAccount(r, profile)
		if errors.Is(err, store.ErrDuplicate) {
			// Two returns raced; the other one made the account.
			user, err = s.store.UserByTelegramID(r.Context(), profile.ID)
		}
		if err != nil {
			s.log.Error("create telegram user", "error", err)
			s.renderLogin(w, r, http.StatusInternalServerError, flow.Next, "", "Could not create the account. Try again.")
			return
		}
		created = true
	}

	if err := s.startSession(w, r, user.ID); err != nil {
		s.log.Error("start session", "error", err)
		s.renderLogin(w, r, http.StatusInternalServerError, flow.Next, "", "Could not start a session. Try again.")
		return
	}
	if created {
		s.markWelcome(w)
	}
	next := flow.Next
	if next == "" {
		next = "/dashboard"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// createTelegramAccount makes an account from a Telegram profile. Like the
// phone door it has no email and a random password nobody knows, until its
// owner sets one on the account page.
func (s *Server) createTelegramAccount(r *http.Request, p telegramProfile) (store.User, error) {
	random, _, err := tokens.NewOpaque()
	if err != nil {
		return store.User{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(random), bcrypt.DefaultCost)
	if err != nil {
		return store.User{}, err
	}
	count, err := s.store.CountUsers(r.Context())
	if err != nil {
		return store.User{}, err
	}
	return s.store.CreateTelegramUser(r.Context(), store.NewUser{
		Name:             p.displayName(),
		PasswordHash:     string(hash),
		AvatarURL:        p.PhotoURL,
		IsAdmin:          count == 0,
		TelegramID:       p.ID,
		TelegramUsername: p.Username,
	})
}

func (s *Server) linkTelegram(w http.ResponseWriter, r *http.Request, p telegramProfile) {
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login?next=%2Fdashboard", http.StatusFound)
		return
	}
	result := "linked"
	if err := s.store.LinkTelegram(r.Context(), user.ID, p.ID, p.Username); err != nil {
		result = "failed"
		if errors.Is(err, store.ErrDuplicate) {
			result = "taken"
		} else {
			s.log.Error("link telegram", "error", err)
		}
	}
	http.Redirect(w, r, "/dashboard?telegram="+result+"#telegram", http.StatusSeeOther)
}

// handleTelegramUnlink disconnects Telegram, unless it is the only way left
// into the account: an account made by a Telegram sign-in has no email, no
// phone and no password anybody knows, and disconnecting would lock its owner
// out for good.
func (s *Server) handleTelegramUnlink(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login?next=%2Fdashboard", http.StatusFound)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "invalid form token", http.StatusForbidden)
		return
	}
	result := "unlinked"
	if !user.PasswordSet && user.Email == "" && user.Phone == "" {
		result = "last"
	} else if err := s.store.UnlinkTelegram(r.Context(), user.ID); err != nil {
		s.log.Error("unlink telegram", "error", err)
		result = "failed"
	}
	http.Redirect(w, r, "/dashboard?telegram="+result+"#telegram", http.StatusSeeOther)
}

func (s *Server) telegramUnavailable(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusNotFound, "error.html", map[string]any{
		"Title":   "Not available",
		"Message": "Signing in with Telegram is not available here.",
	})
}
