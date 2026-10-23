package server

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"nabuauth/internal/store"
)

// Signing up by address is its own page. The one-door form still creates an
// account from an email nobody uses, but a newcomer looks for the words
// "create an account", and that door asked for one password, unconfirmed, under
// a heading that said "Sign in" — a typo there made an account with a password
// nobody knew.
//
// Unlike the sign-in door this page says so when the address already has an
// account; a sign-up form that pretended otherwise would leave the person
// unable to tell why nothing happened. That answer is the reason for the
// per-address budget below: it caps how fast the page can be used to ask
// which addresses are registered.
const (
	registerBudget = 10
	registerWindow = 15 * time.Minute
	maxNameLen     = 80
)

func (s *Server) handleRegisterForm(w http.ResponseWriter, r *http.Request) {
	s.renderRegister(w, r, http.StatusOK, registerView{Next: safeNext(r.URL.Query().Get("next"))})
}

// registerView is what the page shows: what was typed, kept across a refusal
// (never the passwords), and what went wrong.
type registerView struct {
	Next, Name, Email, Error string
	// Exists marks the one refusal whose fix is to sign in instead.
	Exists bool
}

func (s *Server) renderRegister(w http.ResponseWriter, r *http.Request, status int, v registerView) {
	s.render(w, r, status, "register.html", map[string]any{
		"Title":  "Create an account",
		"Next":   v.Next,
		"Name":   v.Name,
		"Email":  v.Email,
		"Error":  v.Error,
		"Exists": v.Exists,
		"App":    s.connectingApp(r, v.Next),
		"Open":   s.registrationOpen(r),
		"Sms":    s.sms != nil,
	})
}

// handleRegisterSubmit creates an account from a name, an address and a
// confirmed password. A post carrying only "identifier" is the one-door form
// posted to /register, which has always meant signing in, and still does.
func (s *Server) handleRegisterSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if r.PostForm.Has("identifier") && !r.PostForm.Has("email") {
		s.handleLoginSubmit(w, r)
		return
	}

	v := registerView{
		Next:  safeNext(r.PostFormValue("next")),
		Name:  strings.TrimSpace(r.PostFormValue("name")),
		Email: strings.ToLower(strings.TrimSpace(r.PostFormValue("email"))),
	}
	fail := func(status int, msg string) {
		v.Error = msg
		s.renderRegister(w, r, status, v)
	}

	if !s.registrationOpen(r) {
		fail(http.StatusForbidden, "Nabu accounts are created by an administrator. Ask your team to invite you.")
		return
	}
	key := "register:" + clientIP(r)
	if s.throttle.spent(key, registerBudget) {
		fail(http.StatusTooManyRequests, "Too many attempts. Try again in a few minutes.")
		return
	}

	password := r.PostFormValue("password")
	switch {
	case v.Name == "" || utf8.RuneCountInString(v.Name) > maxNameLen:
		fail(http.StatusBadRequest, "Enter your name.")
		return
	case !validEmail(v.Email) || strings.ContainsAny(v.Email, " <>"):
		fail(http.StatusBadRequest, "That email address does not look right.")
		return
	case len(password) < minPasswordLen:
		fail(http.StatusBadRequest, "The password needs at least 10 characters.")
		return
	case len(password) > maxPasswordLen:
		fail(http.StatusBadRequest, "The password can be at most 72 characters.")
		return
	case password != r.PostFormValue("confirm"):
		fail(http.StatusBadRequest, "The two passwords are not the same.")
		return
	}

	s.throttle.spend(key, registerWindow)
	user, err := s.createAccount(r, v.Name, v.Email, password)
	if errors.Is(err, store.ErrDuplicate) {
		v.Exists = true
		fail(http.StatusConflict, "An account with this email already exists.")
		return
	}
	if err != nil {
		s.log.Error("create user", "error", err)
		fail(http.StatusInternalServerError, "Could not create the account. Try again.")
		return
	}
	if err := s.startSession(w, r, user.ID); err != nil {
		s.log.Error("start session", "error", err)
		fail(http.StatusInternalServerError, "Could not start a session. Try again.")
		return
	}
	s.markWelcome(w)
	next := v.Next
	if next == "" {
		next = "/dashboard"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// hashForNewAccount is split out so the cost is chosen in one place.
func hashForNewAccount(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}
