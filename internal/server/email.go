package server

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"nabuauth/internal/store"
	"nabuauth/internal/tokens"
)

// A sign-in code by email is the address half of the door, on the same terms
// the number half gets: the offer appears only where the deployment can
// actually deliver, it never says whether an address has an account behind it,
// and the account is handed over only once the mailbox has proved itself.
//
// The proof is the whole point. A code sent to an address and typed back is
// what separates "somebody typed this address" from "somebody reads this
// mailbox", and nothing here matches an account before that has happened —
// which is also what makes it a way back in for somebody who has forgotten the
// password, without a reset flow of its own.

const (
	// emailCodeDigits is the length of the code. It is short because it is typed
	// off a mail notification; what keeps it from being guessable is that a code
	// dies after a handful of wrong tries, not that it is long.
	emailCodeDigits = 6

	// emailRefusal is the one sentence every failed verification gets. "No
	// account uses that address" and "that code is wrong" have to be the same
	// answer, or the form becomes a way to ask which addresses hold accounts.
	emailRefusal = "That code is wrong or has expired."

	// emailSentNotice never varies either — not by whether an account exists,
	// and not by whether a message was actually sent.
	emailSentNotice = "If that address can receive mail, a sign-in code is on its way."

	// The same two ceilings the phone door gets, and for the same reason: what
	// reaches them is a script walking through addresses, and what they bound is
	// the number of strangers who receive an unsolicited Nabu code — which for
	// email costs the sending domain's reputation rather than a per-message fee.
	// The keys are prefixed so an email lockout can never lock the password form
	// or the phone door for the same address or address-holder.
	maxSendsPerAddressPerDay = 5
	maxEmailSendsPerHour     = 300

	emailSendsPerAddressWindow = 24 * time.Hour
	emailSendsGlobalWindow     = time.Hour

	// globalEmailSendKey is deliberately one fixed string: the whole point is
	// that nothing about the request goes into it.
	globalEmailSendKey = "email-sends"
)

// kindEmailCode is the second step for an address signing in by code: the same
// page shape as the phone code step. It is never something classifyIdentifier
// returns — the one box routes addresses to the password step, and the code
// step is reached only by asking for one.
const kindEmailCode identifierKind = "email-code"

// handleEmailCodeStart takes an address and sends a code to it.
func (s *Server) handleEmailCodeStart(w http.ResponseWriter, r *http.Request) {
	if s.mail == nil {
		s.emailCodeUnavailable(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostFormValue("next"))
	address := normaliseEmail(r.PostFormValue("email"))

	view := loginView{Next: next, Identifier: address, Kind: string(kindEmailCode)}
	fail := func(status int, msg string) {
		view.EmailError = msg
		s.renderLoginView(w, r, status, view)
	}

	if !validEmail(address) {
		fail(http.StatusBadRequest, "That email address does not look right.")
		return
	}

	s.startEmailCode(w, r, view, address)
}

// startEmailCode sends a code to an address that has already been validated,
// and draws the step that asks for it back.
//
// Split out of handleEmailCodeStart for the same reason the phone half is: the
// resend form reaches this with an address that was already checked, and
// re-checking a form the visitor never filled in would mean inventing one.
func (s *Server) startEmailCode(w http.ResponseWriter, r *http.Request, view loginView, address string) {
	view.Identifier = address
	view.Kind = string(kindEmailCode)

	fail := func(status int, msg string) {
		view.EmailError = msg
		s.renderLoginView(w, r, status, view)
	}

	// Three keys, because the three abuses are different: one stops one mailbox
	// being hammered, one stops one visitor walking through many addresses, and
	// one bounds what the deployment can be made to send in an hour no matter
	// how the requests are spread.
	perAddress := "email-send:" + address
	perIP := "email-ip:" + clientIP(r)
	if s.throttle.blocked(perIP) ||
		s.throttle.spent(perAddress, maxSendsPerAddressPerDay) ||
		s.throttle.spent(globalEmailSendKey, maxEmailSendsPerHour) {
		fail(http.StatusTooManyRequests, "Too many code requests. Try again in a few minutes.")
		return
	}

	// A resend inside the cooldown is answered as though it had been sent. Doing
	// otherwise would make the wait itself a signal, and resending on demand
	// would reset the attempt counter — an unlimited supply of guesses.
	if existing, err := s.store.EmailCode(r.Context(), address); err == nil {
		if time.Since(existing.SentAt) < s.mailResend && time.Now().Before(existing.ExpiresAt) {
			view.CodeSent = true
			view.EmailNotice = emailSentNotice
			s.renderLoginView(w, r, http.StatusOK, view)
			return
		}
	} else if !isNotFound(err) {
		s.log.Error("email code lookup", "error", err)
		fail(http.StatusInternalServerError, "Could not send a code. Try again.")
		return
	}

	// Where accounts are made by an administrator, an address nobody holds gets
	// no code — there is nothing it could sign into, and sending would tell a
	// stranger that the address is unknown. The page says the same sentence
	// either way, so the silence is not itself an answer.
	send := true
	if !s.registrationOpen(r) {
		_, err := s.store.UserByEmail(r.Context(), address)
		switch {
		case err == nil:
		case isNotFound(err):
			send = false
		default:
			s.log.Error("email lookup", "error", err)
			fail(http.StatusInternalServerError, "Could not send a code. Try again.")
			return
		}
	}

	if send {
		code, err := newEmailCode()
		if err != nil {
			s.log.Error("generate email code", "error", err)
			fail(http.StatusInternalServerError, "Could not send a code. Try again.")
			return
		}
		// Hashed with the same function the passwords use: the code is a
		// credential for the few minutes it lives, and a database dump inside
		// that window must not be enough to sign in with it.
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			s.log.Error("hash email code", "error", err)
			fail(http.StatusInternalServerError, "Could not send a code. Try again.")
			return
		}
		// Stored before it is sent. The other order loses the code of any message
		// that goes out while the write fails, and the visitor then types a valid
		// code at a server that has never heard of it.
		if err := s.store.SaveEmailCode(r.Context(), address, string(hash), time.Now().Add(s.mailTTL)); err != nil {
			s.log.Error("save email code", "error", err)
			fail(http.StatusInternalServerError, "Could not send a code. Try again.")
			return
		}
		if err := s.mail.SendCode(r.Context(), address, code); err != nil {
			// The relay refused, so the page must not claim otherwise. The stored
			// code goes with it, or a retry would be refused by the cooldown.
			s.log.Error("send email code", "error", err)
			_ = s.store.DeleteEmailCode(r.Context(), address)
			s.throttle.fail(perIP)
			fail(http.StatusBadGateway, "Could not send a code to that address. Try again, or sign in with your password.")
			return
		}

		// Counted where the message actually went out. Counting a refused or
		// suppressed request instead would let a stranger exhaust an address's
		// daily budget without a single message leaving, which turns a send
		// ceiling into a way of locking somebody out of their own sign-in.
		s.throttle.spend(perAddress, emailSendsPerAddressWindow)
		s.throttle.spend(globalEmailSendKey, emailSendsGlobalWindow)
	}

	// Every send counts against the per-IP budget whether or not a message went
	// out, so the budget cannot be probed by watching which requests count.
	s.throttle.fail(perIP)

	view.CodeSent = true
	view.EmailNotice = emailSentNotice
	s.renderLoginView(w, r, http.StatusOK, view)
}

// handleEmailCodeVerify takes the code back and signs the mailbox's holder in,
// creating the account where the deployment allows it.
func (s *Server) handleEmailCodeVerify(w http.ResponseWriter, r *http.Request) {
	if s.mail == nil {
		s.emailCodeUnavailable(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostFormValue("next"))
	typedCode := strings.TrimSpace(r.PostFormValue("code"))

	// The address is re-normalised rather than trusted as posted, so the row
	// this looks up is the row the code was stored under whatever the field
	// carried.
	address := normaliseEmail(r.PostFormValue("email"))
	view := loginView{Next: next, Identifier: address, Kind: string(kindEmailCode), CodeSent: true}
	fail := func(status int, msg string) {
		view.EmailError = msg
		s.renderLoginView(w, r, status, view)
	}
	if !validEmail(address) {
		view.CodeSent = false
		fail(http.StatusBadRequest, "That email address does not look right.")
		return
	}

	key := "email:" + address + "|" + clientIP(r)
	if s.throttle.blocked(key) {
		fail(http.StatusTooManyRequests, "Too many attempts. Try again in a few minutes.")
		return
	}

	pending, err := s.store.EmailCode(r.Context(), address)
	switch {
	case isNotFound(err):
		// No code was ever sent to this address, or one was spent already. Both
		// are the same sentence as a wrong code.
		s.throttle.fail(key)
		fail(http.StatusUnauthorized, emailRefusal)
		return
	case err != nil:
		s.log.Error("email code lookup", "error", err)
		fail(http.StatusInternalServerError, "Could not sign you in. Try again.")
		return
	}

	if time.Now().After(pending.ExpiresAt) {
		_ = s.store.DeleteEmailCode(r.Context(), address)
		s.throttle.fail(key)
		fail(http.StatusUnauthorized, emailRefusal)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(pending.CodeHash), []byte(typedCode)) != nil {
		attempts, err := s.store.BumpEmailCodeAttempts(r.Context(), address)
		if err != nil {
			s.log.Error("count email code attempt", "error", err)
		}
		// A code with a spent budget is thrown away rather than left to be
		// guessed at for the rest of its window.
		if attempts >= store.MaxEmailCodeAttempts {
			_ = s.store.DeleteEmailCode(r.Context(), address)
		}
		s.throttle.fail(key)
		fail(http.StatusUnauthorized, emailRefusal)
		return
	}

	// Correct. Spend it here, before anything else can go wrong, so the same
	// code cannot be replayed by whoever else read the message.
	if err := s.store.DeleteEmailCode(r.Context(), address); err != nil {
		s.log.Error("consume email code", "error", err)
		fail(http.StatusInternalServerError, "Could not sign you in. Try again.")
		return
	}

	user, err := s.userForEmail(r, address)
	switch {
	case errors.Is(err, errSignUpClosed), errors.Is(err, store.ErrDuplicate):
		// Closed deployment with no account on that address — answered with the
		// same sentence a wrong code gets, because the difference between them
		// is the answer to "does this address have an account". ErrDuplicate is
		// the race where an account claimed the address between the lookup and
		// the insert; the next attempt is an ordinary sign-in.
		fail(http.StatusUnauthorized, emailRefusal)
		return
	case err != nil:
		s.log.Error("email account", "error", err)
		fail(http.StatusInternalServerError, "Could not sign you in. Try again.")
		return
	}
	if !user.IsActive {
		fail(http.StatusForbidden, "This account is disabled.")
		return
	}

	// The mailbox has now proved itself, which is the claim /api/v1/user
	// reports — the first thing that may set email_verified truthfully.
	if err := s.store.MarkEmailVerified(r.Context(), user.ID); err != nil {
		s.log.Error("mark email verified", "error", err)
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

// userForEmail finds the account holding an address that has just proved
// itself, creating one where the deployment allows it.
func (s *Server) userForEmail(r *http.Request, address string) (store.User, error) {
	user, err := s.store.UserByEmail(r.Context(), address)
	if err == nil {
		return user, nil
	}
	if !isNotFound(err) {
		return store.User{}, err
	}
	if !s.registrationOpen(r) {
		return store.User{}, errSignUpClosed
	}

	// The account has no password: the mailbox is the identifier and the proof.
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
	return s.store.CreateUser(r.Context(), nameFromEmail(address), address, "", string(hash), count == 0)
}

// emailCodeUnavailable is what a deployment with no relay answers on either
// email-code route: the same 404 an unconfigured external provider gets,
// because a route that cannot send a code should not be reachable at all.
func (s *Server) emailCodeUnavailable(w http.ResponseWriter, _ *http.Request) {
	s.render(w, http.StatusNotFound, "error.html", map[string]any{
		"Title":   "Unknown sign-in method",
		"Message": "Signing in with an email code is not available here.",
	})
}

// normaliseEmail is the one canonical form written to users.email and keyed in
// email_codes, matching what CreateUser and UserByEmail do on their side: the
// row a code is stored under must be the row the lookup finds.
func normaliseEmail(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// newEmailCode draws a code from crypto/rand. math/rand would make every code
// predictable from any other, which is the same as having no code.
func newEmailCode() (string, error) {
	max := big.NewInt(1)
	for i := 0; i < emailCodeDigits; i++ {
		max.Mul(max, big.NewInt(10))
	}
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	// Zero-padded, so a small draw is still a six-digit code rather than a
	// shorter one an attacker could recognise as a smaller search space.
	digits := n.String()
	return strings.Repeat("0", emailCodeDigits-len(digits)) + digits, nil
}
