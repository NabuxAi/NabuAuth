package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"nabuauth/internal/store"
)

// throttle limits password attempts per key (email + client IP). Without it the
// login form is an offline-speed guessing oracle against every account.
type throttle struct {
	mu       sync.Mutex
	attempts map[string]*attempt
}

type attempt struct {
	count int
	until time.Time
}

const (
	maxAttempts = 8
	lockFor     = 10 * time.Minute

	// minPasswordLen is checked only when an account is being created. Signing
	// in compares against the stored hash, so an account made before this rule
	// still works with the password it has.
	minPasswordLen = 10

	// welcomeCookie marks a session that began by creating the account, so the
	// next screen can say the account is new instead of asking somebody who has
	// never seen NabuAuth to approve something with no explanation.
	welcomeCookie = "nabuauth_welcome"
)

func newThrottle() *throttle { return &throttle{attempts: map[string]*attempt{}} }

// blocked reports whether the key is currently locked out.
func (t *throttle) blocked(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.attempts[key]
	if a == nil {
		return false
	}
	if time.Now().After(a.until) {
		delete(t.attempts, key)
		return false
	}
	return a.count >= maxAttempts
}

func (t *throttle) fail(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.attempts[key]
	if a == nil || time.Now().After(a.until) {
		a = &attempt{}
		t.attempts[key] = a
	}
	a.count++
	a.until = time.Now().Add(lockFor)
}

func (t *throttle) reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.attempts, key)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	// ServeMux's "GET /" matches everything unmatched, so unknown paths land
	// here and must 404 rather than silently render the dashboard.
	if r.URL.Path != "/" {
		s.render(w, http.StatusNotFound, "error.html", map[string]any{
			"Title":   "Not found",
			"Message": "There is nothing at " + r.URL.Path + ".",
		})
		return
	}
	if _, ok := s.currentUser(r); ok {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// handleLoginForm renders the one door into the ecosystem: a single step, email
// and password together. There is no separate sign-up form to send people to,
// because a visitor arriving from an app does not know yet whether they have a
// Nabu account — the ecosystem may have made one for them through another app.
// Asking them to choose the right form first is asking a question they cannot
// answer.
func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if _, ok := s.currentUser(r); ok && next != "" {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	s.renderLogin(w, r, http.StatusOK, next, "", "")
}

// handleLoginSubmit signs the visitor in, or creates the account and signs them
// in, from the same submission. Which of the two happened is never a question
// the form asked: the email either has an account behind it or it does not.
func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	password := r.PostFormValue("password")
	next := safeNext(r.PostFormValue("next"))
	key := email + "|" + clientIP(r)

	fail := func(status int, msg string) {
		s.renderLogin(w, r, status, next, email, msg)
	}

	if s.throttle.blocked(key) {
		fail(http.StatusTooManyRequests, "Too many failed attempts. Try again in a few minutes.")
		return
	}
	if !validEmail(email) {
		fail(http.StatusBadRequest, "That email address does not look right.")
		return
	}

	user, err := s.store.UserByEmail(r.Context(), email)
	created := false
	switch {
	case err == nil:
		if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
			s.throttle.fail(key)
			fail(http.StatusUnauthorized, "Wrong email or password.")
			return
		}
		if !user.IsActive {
			fail(http.StatusForbidden, "This account is disabled.")
			return
		}
	case !isNotFound(err):
		s.log.Error("login lookup", "error", err)
		fail(http.StatusInternalServerError, "Could not sign you in. Try again.")
		return

	// No account with that email. Where sign-up is closed the answer has to be
	// the same sentence a wrong password gets, or this form becomes a way to ask
	// which addresses hold accounts.
	case !s.registrationOpen(r):
		// Spend the same time a real comparison would, so the two answers cannot
		// be told apart by how long they take either.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidin"), []byte(password))
		s.throttle.fail(key)
		fail(http.StatusUnauthorized, "Wrong email or password.")
		return

	default:
		if len(password) < minPasswordLen {
			// The account does not exist, so this is a sign-up, and saying so is
			// what stops a mistyped address from reading as a broken password.
			fail(http.StatusBadRequest, fmt.Sprintf("No Nabu account uses %s yet. To create one now, choose a password of at least %d characters.", email, minPasswordLen))
			return
		}
		user, err = s.createAccount(r, email, password)
		if errors.Is(err, store.ErrDuplicate) {
			// Two submissions raced. The account exists now, so the second one is
			// an ordinary sign-in that has to prove the password.
			fail(http.StatusUnauthorized, "Wrong email or password.")
			return
		}
		if err != nil {
			s.log.Error("create user", "error", err)
			fail(http.StatusInternalServerError, "Could not create the account. Try again.")
			return
		}
		created = true
	}

	s.throttle.reset(key)
	if err := s.startSession(w, r, user.ID); err != nil {
		s.log.Error("start session", "error", err)
		fail(http.StatusInternalServerError, "Could not start a session. Try again.")
		return
	}
	if created {
		// Read and cleared by whichever screen comes next, so a brand-new account
		// is told it is new exactly once.
		http.SetCookie(w, &http.Cookie{
			Name:     welcomeCookie,
			Value:    "1",
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
			Secure:   s.cfg.Server.UseSecureCookies(),
			SameSite: http.SameSiteLaxMode,
		})
	}
	if next == "" {
		next = "/dashboard"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// createAccount makes the account behind an email nobody has claimed yet.
func (s *Server) createAccount(r *http.Request, email, password string) (store.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return store.User{}, err
	}
	// The very first account is the administrator, so a fresh deployment has an
	// owner without a seeding step.
	count, err := s.store.CountUsers(r.Context())
	if err != nil {
		return store.User{}, err
	}
	return s.store.CreateUser(r.Context(), nameFromEmail(email), email, "", string(hash), count == 0)
}

// handleRegisterRedirect keeps every /register link in the ecosystem working.
// Signing in and signing up are the same door now, so this one leads to it.
func (s *Server) handleRegisterRedirect(w http.ResponseWriter, r *http.Request) {
	target := "/login"
	if next := safeNext(r.URL.Query().Get("next")); next != "" {
		target += "?next=" + url.QueryEscape(next)
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// renderLogin draws the sign-in page, naming the application that sent the
// visitor here so the page does not look like an unrelated site asking for a
// password.
func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, next, email, errMsg string) {
	s.render(w, status, "login.html", map[string]any{
		"Title": "Sign in to Nabu",
		"Next":  next,
		"Email": email,
		"Error": errMsg,
		"App":   s.connectingApp(r, next),
		// What the page tells the visitor about an unknown email has to match
		// what the submission will actually do — which includes the case where
		// sign-up is closed but the database has no accounts yet.
		"AllowRegistration": s.registrationOpen(r),
		"Providers":         s.cfg.EnabledLoginMethods(),
	})
}

// connectingApp is the application whose authorize request sent the visitor to
// this form, or nil when they came here on their own.
func (s *Server) connectingApp(r *http.Request, next string) map[string]any {
	if next == "" {
		return nil
	}
	u, err := url.Parse(next)
	if err != nil || !strings.HasPrefix(u.Path, "/oauth/authorize") {
		return nil
	}
	clientID := u.Query().Get("client_id")
	if clientID == "" {
		return nil
	}
	client, err := s.store.ClientByID(r.Context(), clientID)
	if err != nil {
		return nil
	}
	return map[string]any{
		"Name":        client.Name,
		"Description": client.Description,
		"URL":         client.AppURL,
	}
}

// nameFromEmail is the display name for an account created from nothing but an
// email address. The form asks for two fields and no more, so this stands in
// until the person changes it.
func nameFromEmail(email string) string {
	local := email
	if i := strings.IndexByte(local, '@'); i > 0 {
		local = local[:i]
	}
	local = strings.NewReplacer(".", " ", "_", " ", "-", " ").Replace(local)
	words := strings.Fields(local)
	for i, word := range words {
		words[i] = strings.ToUpper(word[:1]) + word[1:]
	}
	if len(words) == 0 {
		return email
	}
	return strings.Join(words, " ")
}

// takeWelcome reports whether this session was created by signing up a moment
// ago, clearing the marker so the message is shown once.
func (s *Server) takeWelcome(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie(welcomeCookie)
	if err != nil || c.Value == "" {
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     welcomeCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.Server.UseSecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
	return true
}

// registrationOpen reports whether the sign-up form is available. It is always
// open while no account exists, so a fresh deployment can be claimed.
func (s *Server) registrationOpen(r *http.Request) bool {
	if s.cfg.Server.AllowRegistration {
		return true
	}
	count, err := s.store.CountUsers(r.Context())
	return err == nil && count == 0
}

func (s *Server) handleLogoutSubmit(w http.ResponseWriter, r *http.Request) {
	s.endSession(w, r)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login?next=%2Fdashboard", http.StatusFound)
		return
	}
	clients, err := s.store.ListedClients(r.Context())
	if err != nil {
		s.log.Error("list apps", "error", err)
	}
	consents, err := s.store.ConsentedClients(r.Context(), user.ID)
	if err != nil {
		s.log.Error("list consents", "error", err)
	}
	wallet, err := s.store.WalletFor(r.Context(), user.ID)
	if err != nil {
		s.log.Error("wallet lookup", "error", err)
	}
	entries, err := s.store.Transactions(r.Context(), user.ID, 10)
	if err != nil {
		s.log.Error("wallet transactions", "error", err)
	}

	apps := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		redirect := ""
		if len(c.RedirectURIs) > 0 {
			redirect = c.RedirectURIs[0]
		}
		_, connected := consents[c.ClientID]
		apps = append(apps, map[string]any{
			"ID":          c.ClientID,
			"Name":        c.Name,
			"Description": c.Description,
			"URL":         c.AppURL,
			"Badge":       c.Badge,
			"Icon":        c.Icon,
			"SSOURL":      s.ssoURL(c.ClientID, redirect, c.Scopes),
			"Connected":   connected,
		})
	}
	s.render(w, http.StatusOK, "dashboard.html", map[string]any{
		"Title":        "Your Nabu account",
		"NewAccount":   s.takeWelcome(w, r),
		"User":         user,
		"Apps":         apps,
		"Wallet":       wallet,
		"BalanceMajor": formatMoney(wallet.BalanceCents, wallet.Currency),
		"Transactions": entries,
		"CSRF":         s.csrfToken(r),
	})
}

func (s *Server) handleRevokeApp(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "invalid form token", http.StatusForbidden)
		return
	}
	if clientID := r.PostFormValue("client_id"); clientID != "" {
		if err := s.store.RevokeConsent(r.Context(), user.ID, clientID); err != nil {
			s.log.Error("revoke consent", "error", err)
		}
	}
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// safeNext keeps post-login redirects inside this server. An absolute URL here
// would turn the login page into an open redirect.
func safeNext(next string) string {
	if next == "" {
		return ""
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return ""
	}
	return next
}

func validEmail(addr string) bool {
	_, err := mail.ParseAddress(addr)
	return err == nil
}

// clientIP prefers the proxy-supplied address, since NabuAuth always runs behind
// one in production and RemoteAddr would otherwise be the proxy for everyone.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// minorUnitDigits is how many decimal places a currency's minor unit has. The
// ecosystem prices in Omani rial, whose baisa is 1/1000 — formatting it with two
// decimals would misstate every balance by a factor of ten.
func minorUnitDigits(currency string) int {
	switch strings.ToUpper(currency) {
	case "OMR", "BHD", "KWD", "JOD", "TND":
		return 3
	case "JPY", "KRW", "IRR", "VND":
		return 0
	default:
		return 2
	}
}

// formatMoney renders a minor-unit amount as a major-unit string.
func formatMoney(minor int64, currency string) string {
	digits := minorUnitDigits(currency)
	sign := ""
	if minor < 0 {
		sign, minor = "-", -minor
	}
	if digits == 0 {
		return sign + strconv.FormatInt(minor, 10)
	}
	scale := int64(1)
	for i := 0; i < digits; i++ {
		scale *= 10
	}
	return fmt.Sprintf("%s%d.%0*d", sign, minor/scale, digits, minor%scale)
}
