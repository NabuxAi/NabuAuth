package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	"nabuauth/internal/sms"
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

// spent reports whether a budget of limit uses has already been used up.
//
// Separate from blocked because a spend ceiling is not a lockout: it has its own
// size and its own window, and the thing it protects is a bill rather than an
// account.
func (t *throttle) spent(key string, limit int) bool {
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
	return a.count >= limit
}

// spend records one use against a budget lasting window. The window is set when
// the budget opens and not extended by later uses, so the budget actually
// refills instead of a steady trickle holding it open forever.
func (t *throttle) spend(key string, window time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.attempts[key]
	if a == nil || time.Now().After(a.until) {
		a = &attempt{until: time.Now().Add(window)}
		t.attempts[key] = a
	}
	a.count++
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

// The door asks one question at a time.
//
// It used to ask several at once: an email and a password side by side, a phone
// field under them, and a row of providers under that — four ways in, all on
// screen together, and the visitor had to decide which of them they were before
// typing anything. So the first step is one box that takes whatever they know
// about themselves — the address, the number, or the handle — and the second
// asks for the one proof that fits what they typed.
type identifierKind string

const (
	kindUnknown  identifierKind = ""
	kindEmail    identifierKind = "email"
	kindPhone    identifierKind = "phone"
	kindUsername identifierKind = "username"
)

// A handle is deliberately narrow: lowercase letters, digits and the three
// separators, starting and ending on an alphanumeric. Anything looser and a
// typo'd email address with the '@' missing would be taken for a username and
// answered with the wrong question.
var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,30}[a-z0-9]$`)

// classifyIdentifier decides which of the three the visitor typed, and returns
// it in the form the lookups use: a lowercase address, an E.164 number, or a
// lowercase handle.
func classifyIdentifier(raw, dial string) (identifierKind, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return kindUnknown, ""
	}

	if strings.Contains(raw, "@") {
		email := strings.ToLower(raw)
		if !validEmail(email) {
			return kindUnknown, raw
		}
		return kindEmail, email
	}

	// Digits, spacing and the punctuation people write numbers with, and nothing
	// else. Eastern Arabic digits count: a Persian keyboard produces them, and
	// sms.Normalise already folds them to ASCII.
	if looksLikeNumber(raw) {
		if e164, ok := sms.Normalise(raw, dial); ok {
			return kindPhone, e164
		}
		return kindUnknown, raw
	}

	handle := strings.ToLower(raw)
	if usernamePattern.MatchString(handle) {
		return kindUsername, handle
	}
	return kindUnknown, raw
}

func looksLikeNumber(s string) bool {
	digits := false
	for _, r := range s {
		switch {
		case unicode.IsDigit(r):
			digits = true
		case r == '+' || r == '-' || r == ' ' || r == '(' || r == ')' || r == '.':
		default:
			return false
		}
	}
	return digits
}

// handleLoginForm renders the first step: one box, and nothing else to decide.
// There is no separate sign-up form to send people to, because a visitor
// arriving from an app does not know yet whether they have a Nabu account — the
// ecosystem may have made one for them through another app. Asking them to
// choose the right form first is asking a question they cannot answer.
func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if _, ok := s.currentUser(r); ok && next != "" {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	s.renderLogin(w, r, http.StatusOK, next, "", "")
}

// handleLoginSubmit takes the identifier and decides what the second step is: a
// code for a number, a password for an address or a handle.
//
// A submission that carries a password as well is answered in one step. That is
// how every form in the ecosystem posted here before this page had two, and a
// visitor whose browser filled both fields should not be sent back a step.
func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostFormValue("next"))
	typed := r.PostFormValue("identifier")
	if strings.TrimSpace(typed) == "" {
		typed = r.PostFormValue("email")
	}
	password := r.PostFormValue("password")

	kind, value := classifyIdentifier(typed, s.cfg.Sms.DialFor(""))

	switch kind {
	case kindUnknown:
		s.renderLogin(w, r, http.StatusBadRequest, next, typed,
			"That is not an email address, a phone number or a username.")

	case kindPhone:
		if s.sms == nil {
			// Nothing here can send a code, and saying "check your messages"
			// when no message is coming is the one failure this door exists to
			// not repeat.
			s.renderLogin(w, r, http.StatusBadRequest, next, typed,
				"Signing in with a phone number is not available here. Use your email address instead.")
			return
		}
		s.startPhoneCode(w, r, loginView{Next: next, Identifier: value, Kind: string(kindPhone)}, value)

	default:
		if password != "" {
			s.finishPassword(w, r, next, kind, value, password)
			return
		}
		s.renderCredential(w, r, http.StatusOK, next, kind, value, "")
	}
}

// handleLoginPassword is the second step for an address or a handle.
func (s *Server) handleLoginPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostFormValue("next"))
	kind, value := classifyIdentifier(r.PostFormValue("identifier"), s.cfg.Sms.DialFor(""))
	password := r.PostFormValue("password")

	switch {
	case kind == kindUnknown || kind == kindPhone:
		// The identifier came back changed, or was never one this step can
		// answer. Start again rather than guess which of the two happened.
		s.renderLogin(w, r, http.StatusBadRequest, next, r.PostFormValue("identifier"),
			"Start again — that is not an email address or a username.")
	case password == "":
		s.renderCredential(w, r, http.StatusBadRequest, next, kind, value, "Enter your password.")
	default:
		s.finishPassword(w, r, next, kind, value, password)
	}
}

// finishPassword signs the visitor in against a password, and — for an address
// nobody holds, where the deployment allows it — creates the account first.
// Which of the two happened is never a question the form asked.
func (s *Server) finishPassword(w http.ResponseWriter, r *http.Request, next string, kind identifierKind, value, password string) {
	key := string(kind) + ":" + value + "|" + clientIP(r)

	// One sentence for every refusal this step can produce, so it never becomes
	// a way to ask which addresses or handles hold accounts.
	refusal := "Wrong email or password."
	if kind == kindUsername {
		refusal = "Wrong username or password."
	}

	fail := func(status int, msg string) {
		s.renderCredential(w, r, status, next, kind, value, msg)
	}

	if s.throttle.blocked(key) {
		fail(http.StatusTooManyRequests, "Too many failed attempts. Try again in a few minutes.")
		return
	}

	var (
		user    store.User
		err     error
		created bool
	)

	if kind == kindUsername {
		user, err = s.store.UserByUsername(r.Context(), value)
	} else {
		user, err = s.store.UserByEmail(r.Context(), value)
	}

	switch {
	case err == nil:
		if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
			s.throttle.fail(key)
			fail(http.StatusUnauthorized, refusal)
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

	// A handle nobody holds is never a sign-up: a username on its own is not an
	// address or a number, so there would be no way to reach the account later.
	// Same sentence as a wrong password, for the same reason.
	case kind == kindUsername:
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
		s.throttle.fail(key)
		fail(http.StatusUnauthorized, refusal)
		return

	// No account with that email. Where sign-up is closed the answer has to be
	// the same sentence a wrong password gets, or this form becomes a way to ask
	// which addresses hold accounts.
	case !s.registrationOpen(r):
		// Spend the same time a real comparison would, so the two answers cannot
		// be told apart by how long they take either.
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
		s.throttle.fail(key)
		fail(http.StatusUnauthorized, refusal)
		return

	default:
		if len(password) < minPasswordLen {
			// The account does not exist, so this is a sign-up, and saying so is
			// what stops a mistyped address from reading as a broken password.
			fail(http.StatusBadRequest, fmt.Sprintf("No Nabu account uses %s yet. To create one now, choose a password of at least %d characters.", value, minPasswordLen))
			return
		}
		user, err = s.createAccount(r, value, password)
		if errors.Is(err, store.ErrDuplicate) {
			// Two submissions raced. The account exists now, so the second one is
			// an ordinary sign-in that has to prove the password.
			fail(http.StatusUnauthorized, refusal)
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

// dummyHash is compared against when there is no account, so a refusal costs
// the same time a real comparison does.
const dummyHash = "$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidin"

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

// loginView is the state of the door: which step it is on, what was typed into
// the one box, and what went wrong.
type loginView struct {
	Next  string
	Email string
	Error string

	// Identifier is what the visitor typed, normalised — the address, the
	// number or the handle — and Kind which of the three it was. Empty Kind is
	// the first step, where nothing has been decided yet.
	Identifier string
	Kind       string

	// The phone half. Phone is the E.164 number a code was just sent to, and
	// Country the ISO code the visitor picked, kept so a refused submission
	// comes back with the selector where they left it.
	Phone       string
	Country     string
	PhoneError  string
	PhoneNotice string
	CodeSent    bool
}

// renderLogin draws the sign-in page, naming the application that sent the
// visitor here so the page does not look like an unrelated site asking for a
// password.
func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, next, identifier, errMsg string) {
	s.renderLoginView(w, r, status, loginView{Next: next, Identifier: identifier, Email: identifier, Error: errMsg})
}

// renderCredential draws the second step for an address or a handle: the one
// box replaced by what was typed, and a field for the password.
func (s *Server) renderCredential(w http.ResponseWriter, r *http.Request, status int, next string, kind identifierKind, value, errMsg string) {
	s.renderLoginView(w, r, status, loginView{
		Next:       next,
		Identifier: value,
		Email:      value,
		Kind:       string(kind),
		Error:      errMsg,
	})
}

func (s *Server) renderLoginView(w http.ResponseWriter, r *http.Request, status int, v loginView) {
	s.render(w, status, "login.html", map[string]any{
		"Title":      "Sign in to Nabu",
		"Next":       v.Next,
		"Email":      v.Email,
		"Identifier": v.Identifier,
		"Kind":       v.Kind,
		"Error":      v.Error,
		"App":        s.connectingApp(r, v.Next),
		// What the page tells the visitor about an unknown email has to match
		// what the submission will actually do — which includes the case where
		// sign-up is closed but the database has no accounts yet.
		"AllowRegistration": s.registrationOpen(r),
		"Providers":         s.cfg.EnabledLoginMethods(),
		// The phone half exists only where a gateway is configured. A field that
		// cannot send a code would report one as sent, which is the whole defect
		// this door is here to not repeat.
		"Sms":         s.sms != nil,
		"Countries":   s.cfg.Sms.Countries,
		"Country":     v.Country,
		"Phone":       v.Phone,
		"PhoneError":  v.PhoneError,
		"PhoneNotice": v.PhoneNotice,
		"CodeSent":    v.CodeSent,
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

// clientIP is the address every rate limiter in this server is keyed on, so it
// has to be an address the caller cannot choose.
//
// X-Forwarded-For is a list each hop appends to, and the leftmost entry is
// whatever the *client* wrote — Traefik appends the real peer to it rather than
// replacing it. Reading the front of that list therefore let one visitor mint a
// fresh limiter bucket per request by incrementing a header, which uncaps every
// budget here, including the per-IP ceiling that is the only thing standing
// between a script and an unlimited SMS bill.
//
// So the list is walked from the right, skipping the hops that are ours, and
// the first address that is not ours is the one that actually reached us. A
// client-written prefix is always to the left of that, and is never reached.
func clientIP(r *http.Request) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		peer = host
	}

	// Only believe the header at all when the machine talking to us is a proxy
	// of ours. A direct connection from the internet has no forwarded chain
	// worth reading, whatever it claims.
	if !trustedProxy(peer) {
		return peer
	}

	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(parts[i])
		if hop == "" {
			continue
		}
		if trustedProxy(hop) {
			continue
		}
		return hop
	}

	return peer
}

// trustedProxies are the networks a reverse proxy of ours runs on. Anything
// inside them may speak for a client through X-Forwarded-For; nothing outside
// them may. A deployment fronted by Cloudflare adds its published ranges here
// (or in front of it), or every visitor is counted as the edge that forwarded
// them — which is conservative rather than exploitable, and so the safe default.
var trustedProxies = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8", "::1/128",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"fc00::/7",
	}
	if extra := os.Getenv("NABUAUTH_TRUSTED_PROXIES"); extra != "" {
		for _, c := range strings.Split(extra, ",") {
			if c = strings.TrimSpace(c); c != "" {
				cidrs = append(cidrs, c)
			}
		}
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

func trustedProxy(addr string) bool {
	ip := net.ParseIP(strings.Trim(addr, "[]"))
	if ip == nil {
		return false
	}
	for _, n := range trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
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
