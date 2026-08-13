package server

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"nabuauth/internal/sms"
	"nabuauth/internal/store"
	"nabuauth/internal/tokens"
)

// Phone sign-in is the fourth door into the ecosystem, beside the password and
// the external providers, and it works on the same terms as they do: it appears
// on the form only where the deployment can actually complete it, it never says
// whether a number has an account behind it, and the account is handed over only
// once the number has proved itself.
//
// The proof is the whole point. A code sent to a number and typed back is what
// separates "somebody typed this number" from "somebody holds this number", and
// nothing here matches an account before that has happened.

const (
	// phoneCodeDigits is the length of the code. It is short because it is typed
	// off a lock screen; what keeps it from being guessable is that a code dies
	// after a handful of wrong tries, not that it is long.
	phoneCodeDigits = 6

	// refusal is the one sentence every failed verification gets. "No account
	// uses that number" and "that code is wrong" have to be the same answer, or
	// the form becomes a way to ask which numbers hold accounts.
	phoneRefusal = "That code is wrong or has expired."

	// sentNotice never varies either — not by whether an account exists, and not
	// by whether a message was actually paid for.
	phoneSentNotice = "If that number can receive messages, a sign-in code is on its way."

	// Two ceilings on what this door may spend, neither of which depends on who
	// is asking. Every key derived from the caller — an address, a session, a
	// header — is a key the caller can change, and a budget that can be reset by
	// changing a header is not a budget. These two cannot be: one counts a
	// number, which is the thing being messaged, and one counts the deployment.
	//
	// They are ceilings and not ordinary limits. Ordinary use never reaches
	// them; what reaches them is a script walking through numbers, and what they
	// bound is the invoice and the number of strangers who receive an
	// unsolicited Nabu code.
	maxSendsPerNumberPerDay = 5
	maxSendsPerHour         = 300

	sendsPerNumberWindow = 24 * time.Hour
	sendsGlobalWindow    = time.Hour

	// globalSendKey is deliberately one fixed string: the whole point is that
	// nothing about the request goes into it.
	globalSendKey = "phone-sends"
)

// handlePhoneStart takes a number and sends a code to it.
func (s *Server) handlePhoneStart(w http.ResponseWriter, r *http.Request) {
	if s.sms == nil {
		s.phoneUnavailable(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostFormValue("next"))
	country := strings.ToUpper(strings.TrimSpace(r.PostFormValue("country")))
	typed := r.PostFormValue("phone")

	view := loginView{Next: next, Country: country}
	fail := func(status int, msg string) {
		view.PhoneError = msg
		s.renderLoginView(w, r, status, view)
	}

	e164, ok := sms.Normalise(typed, s.cfg.Sms.DialFor(country))
	if !ok {
		fail(http.StatusBadRequest, "That phone number does not look right.")
		return
	}
	view.Phone = e164

	// Three keys, because the three abuses are different. The first stops one
	// number being hammered; the second stops one visitor walking through many
	// numbers; the third bounds what the deployment can be made to spend in an
	// hour no matter how the requests are spread. All are prefixed so a phone
	// lockout can never lock the password form for the same address or
	// address-holder.
	//
	// The per-number key carries only the number. It used to carry the client
	// address too, which meant the one cap on messaging a single handset could
	// be stepped around by changing an address — and it was never incremented
	// anyway, so the only thing pacing a number was the 60-second cooldown, and
	// a code a minute forever is harassment with the organisation's name on it.
	perNumber := "phone-send:" + e164
	perIP := "phone-ip:" + clientIP(r)
	if s.throttle.blocked(perIP) ||
		s.throttle.spent(perNumber, maxSendsPerNumberPerDay) ||
		s.throttle.spent(globalSendKey, maxSendsPerHour) {
		fail(http.StatusTooManyRequests, "Too many code requests. Try again in a few minutes.")
		return
	}

	// A resend inside the cooldown is answered as though it had been sent. Doing
	// otherwise would make the wait itself a signal, and resending on demand
	// would reset the attempt counter — an unlimited supply of guesses.
	if existing, err := s.store.PhoneCode(r.Context(), e164); err == nil {
		if time.Since(existing.SentAt) < s.phoneResend && time.Now().Before(existing.ExpiresAt) {
			view.CodeSent = true
			view.PhoneNotice = phoneSentNotice
			s.renderLoginView(w, r, http.StatusOK, view)
			return
		}
	} else if !isNotFound(err) {
		s.log.Error("phone code lookup", "error", err)
		fail(http.StatusInternalServerError, "Could not send a code. Try again.")
		return
	}

	// Where accounts are made by an administrator, a number nobody holds gets no
	// code — there is nothing it could sign into, and sending would spend a
	// message to tell a stranger that the number is unknown. The page says the
	// same sentence either way, so the silence is not itself an answer.
	send := true
	if !s.registrationOpen(r) {
		_, err := s.store.UserByPhone(r.Context(), e164)
		switch {
		case err == nil:
		case isNotFound(err):
			send = false
		default:
			s.log.Error("phone lookup", "error", err)
			fail(http.StatusInternalServerError, "Could not send a code. Try again.")
			return
		}
	}

	if send {
		code, err := newPhoneCode()
		if err != nil {
			s.log.Error("generate phone code", "error", err)
			fail(http.StatusInternalServerError, "Could not send a code. Try again.")
			return
		}
		// Hashed with the same function the passwords use: the code is a
		// credential for the few minutes it lives, and a database dump inside
		// that window must not be enough to sign in with it.
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			s.log.Error("hash phone code", "error", err)
			fail(http.StatusInternalServerError, "Could not send a code. Try again.")
			return
		}
		// Stored before it is sent. The other order loses the code of any message
		// that goes out while the write fails, and the visitor then types a valid
		// code at a server that has never heard of it.
		if err := s.store.SavePhoneCode(r.Context(), e164, string(hash), time.Now().Add(s.phoneTTL)); err != nil {
			s.log.Error("save phone code", "error", err)
			fail(http.StatusInternalServerError, "Could not send a code. Try again.")
			return
		}
		if err := s.sms.SendCode(r.Context(), e164, code); err != nil {
			// The gateway answers 200 even when the message failed, so this is a
			// real failure and the page must not claim otherwise. The stored code
			// goes with it, or a retry would be refused by the cooldown.
			s.log.Error("send phone code", "error", err)
			_ = s.store.DeletePhoneCode(r.Context(), e164)
			s.throttle.fail(perIP)
			fail(http.StatusBadGateway, "Could not send a code to that number. Try again, or sign in with your email.")
			return
		}

		// Counted where the money is actually spent. Counting a refused or
		// suppressed request instead would let a stranger exhaust a number's
		// daily budget without a single message going out, which turns a spend
		// ceiling into a way of locking somebody out of their own sign-in.
		s.throttle.spend(perNumber, sendsPerNumberWindow)
		s.throttle.spend(globalSendKey, sendsGlobalWindow)
	}

	// Every send counts against the per-IP budget whether or not a message was
	// paid for, so the budget cannot be probed by watching which requests count.
	s.throttle.fail(perIP)

	view.CodeSent = true
	view.PhoneNotice = phoneSentNotice
	s.renderLoginView(w, r, http.StatusOK, view)
}

// handlePhoneVerify takes the code back and signs the number's holder in,
// creating the account where the deployment allows it.
func (s *Server) handlePhoneVerify(w http.ResponseWriter, r *http.Request) {
	if s.sms == nil {
		s.phoneUnavailable(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostFormValue("next"))
	country := strings.ToUpper(strings.TrimSpace(r.PostFormValue("country")))
	typedCode := strings.TrimSpace(r.PostFormValue("code"))

	// The number is re-normalised rather than trusted as posted, so the row this
	// looks up is the row the code was stored under whatever the field carried.
	e164, ok := sms.Normalise(r.PostFormValue("phone"), s.cfg.Sms.DialFor(country))
	view := loginView{Next: next, Country: country, Phone: e164, CodeSent: true}
	fail := func(status int, msg string) {
		view.PhoneError = msg
		s.renderLoginView(w, r, status, view)
	}
	if !ok {
		view.CodeSent = false
		fail(http.StatusBadRequest, "That phone number does not look right.")
		return
	}

	key := "phone:" + e164 + "|" + clientIP(r)
	if s.throttle.blocked(key) {
		fail(http.StatusTooManyRequests, "Too many attempts. Try again in a few minutes.")
		return
	}

	pending, err := s.store.PhoneCode(r.Context(), e164)
	switch {
	case isNotFound(err):
		// No code was ever sent to this number, or one was spent already. Both
		// are the same sentence as a wrong code.
		s.throttle.fail(key)
		fail(http.StatusUnauthorized, phoneRefusal)
		return
	case err != nil:
		s.log.Error("phone code lookup", "error", err)
		fail(http.StatusInternalServerError, "Could not sign you in. Try again.")
		return
	}

	if time.Now().After(pending.ExpiresAt) {
		_ = s.store.DeletePhoneCode(r.Context(), e164)
		s.throttle.fail(key)
		fail(http.StatusUnauthorized, phoneRefusal)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(pending.CodeHash), []byte(typedCode)) != nil {
		attempts, err := s.store.BumpPhoneCodeAttempts(r.Context(), e164)
		if err != nil {
			s.log.Error("count phone code attempt", "error", err)
		}
		// A code with a spent budget is thrown away rather than left to be
		// guessed at for the rest of its window.
		if attempts >= store.MaxPhoneCodeAttempts {
			_ = s.store.DeletePhoneCode(r.Context(), e164)
		}
		s.throttle.fail(key)
		fail(http.StatusUnauthorized, phoneRefusal)
		return
	}

	// Correct. Spend it here, before anything else can go wrong, so the same
	// code cannot be replayed by whoever else read the message.
	if err := s.store.DeletePhoneCode(r.Context(), e164); err != nil {
		s.log.Error("consume phone code", "error", err)
		fail(http.StatusInternalServerError, "Could not sign you in. Try again.")
		return
	}

	user, err := s.userForPhone(r, e164)
	switch {
	case errors.Is(err, errSignUpClosed), errors.Is(err, store.ErrDuplicate):
		// Closed deployment with no account on that number — answered with the
		// same sentence a wrong code gets, because the difference between them
		// is the answer to "does this number have an account". ErrDuplicate is
		// the race where an account claimed the number between the lookup and
		// the insert; the next attempt is an ordinary sign-in.
		fail(http.StatusUnauthorized, phoneRefusal)
		return
	case err != nil:
		s.log.Error("phone account", "error", err)
		fail(http.StatusInternalServerError, "Could not sign you in. Try again.")
		return
	}
	if !user.IsActive {
		fail(http.StatusForbidden, "This account is disabled.")
		return
	}

	// The number has now proved itself, which is the claim /api/v1/user reports.
	if err := s.store.MarkPhoneVerified(r.Context(), user.ID); err != nil {
		s.log.Error("mark phone verified", "error", err)
	}

	s.throttle.reset(key)
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

// userForPhone finds the account holding a number that has just proved itself,
// creating one where the deployment allows it.
func (s *Server) userForPhone(r *http.Request, e164 string) (store.User, error) {
	user, err := s.store.UserByPhone(r.Context(), e164)
	if err == nil {
		return user, nil
	}
	if !isNotFound(err) {
		return store.User{}, err
	}
	if !s.registrationOpen(r) {
		return store.User{}, errSignUpClosed
	}

	// The account has no password and no email: the number is the identifier,
	// and a made-up address here would be a claim about a mailbox nobody owns.
	// The password column still gets a random value rather than an empty string
	// somebody could later match against.
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
	return s.store.CreateUser(r.Context(), e164, "", e164, string(hash), count == 0)
}

// phoneUnavailable is what a deployment with no gateway answers on either phone
// route: the same 404 an unconfigured external provider gets, because a route
// that cannot send a code should not be reachable at all.
func (s *Server) phoneUnavailable(w http.ResponseWriter, _ *http.Request) {
	s.render(w, http.StatusNotFound, "error.html", map[string]any{
		"Title":   "Unknown sign-in method",
		"Message": "Signing in with a phone number is not available here.",
	})
}

// newPhoneCode draws a code from crypto/rand. math/rand would make every code
// predictable from any other, which is the same as having no code.
func newPhoneCode() (string, error) {
	max := big.NewInt(1)
	for i := 0; i < phoneCodeDigits; i++ {
		max.Mul(max, big.NewInt(10))
	}
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	// Zero-padded, so a small draw is still a six-digit code rather than a
	// shorter one an attacker could recognise as a smaller search space.
	digits := n.String()
	return strings.Repeat("0", phoneCodeDigits-len(digits)) + digits, nil
}
