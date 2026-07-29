package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
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

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if _, ok := s.currentUser(r); ok && next != "" {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	s.render(w, http.StatusOK, "login.html", map[string]any{
		"Title": "Sign in to Nabu",
		"Next":  next,
	})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	password := r.PostFormValue("password")
	next := safeNext(r.PostFormValue("next"))
	key := email + "|" + clientIP(r)

	fail := func(msg string) {
		s.render(w, http.StatusUnauthorized, "login.html", map[string]any{
			"Title": "Sign in to Nabu",
			"Next":  next,
			"Email": email,
			"Error": msg,
		})
	}

	if s.throttle.blocked(key) {
		fail("Too many failed attempts. Try again in a few minutes.")
		return
	}
	user, err := s.store.UserByEmail(r.Context(), email)
	if err != nil {
		if !isNotFound(err) {
			s.log.Error("login lookup", "error", err)
		}
		// Compare against a dummy hash anyway, so a missing account and a wrong
		// password take the same time and cannot be told apart.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidin"), []byte(password))
		s.throttle.fail(key)
		fail("Wrong email or password.")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		s.throttle.fail(key)
		fail("Wrong email or password.")
		return
	}
	if !user.IsActive {
		fail("This account is disabled.")
		return
	}
	s.throttle.reset(key)
	if err := s.startSession(w, r, user.ID); err != nil {
		s.log.Error("start session", "error", err)
		fail("Could not start a session. Try again.")
		return
	}
	if next == "" {
		next = "/dashboard"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func (s *Server) handleRegisterForm(w http.ResponseWriter, r *http.Request) {
	if !s.registrationOpen(r) {
		s.render(w, http.StatusForbidden, "error.html", map[string]any{
			"Title":   "Sign-up is closed",
			"Message": "Nabu accounts are created by an administrator. Ask your team to invite you.",
		})
		return
	}
	s.render(w, http.StatusOK, "register.html", map[string]any{
		"Title": "Create a Nabu account",
		"Next":  safeNext(r.URL.Query().Get("next")),
	})
}

func (s *Server) handleRegisterSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.registrationOpen(r) {
		s.render(w, http.StatusForbidden, "error.html", map[string]any{
			"Title":   "Sign-up is closed",
			"Message": "Nabu accounts are created by an administrator.",
		})
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	phone := strings.TrimSpace(r.PostFormValue("phone"))
	password := r.PostFormValue("password")
	next := safeNext(r.PostFormValue("next"))

	fail := func(msg string) {
		s.render(w, http.StatusBadRequest, "register.html", map[string]any{
			"Title": "Create a Nabu account",
			"Name":  name,
			"Email": email,
			"Phone": phone,
			"Next":  next,
			"Error": msg,
		})
	}
	switch {
	case name == "":
		fail("Your name is required.")
		return
	case !validEmail(email):
		fail("That email address does not look right.")
		return
	case len(password) < 10:
		fail("Use a password of at least 10 characters.")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		s.log.Error("hash password", "error", err)
		fail("Could not create the account. Try again.")
		return
	}
	// The very first account is the administrator, so a fresh deployment has an
	// owner without a seeding step.
	count, err := s.store.CountUsers(r.Context())
	if err != nil {
		s.log.Error("count users", "error", err)
		fail("Could not create the account. Try again.")
		return
	}
	user, err := s.store.CreateUser(r.Context(), name, email, phone, string(hash), count == 0)
	if errors.Is(err, store.ErrDuplicate) {
		fail("That email or phone number is already registered.")
		return
	}
	if err != nil {
		s.log.Error("create user", "error", err)
		fail("Could not create the account. Try again.")
		return
	}
	if err := s.startSession(w, r, user.ID); err != nil {
		s.log.Error("start session", "error", err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if next == "" {
		next = "/dashboard"
	}
	http.Redirect(w, r, next, http.StatusFound)
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
