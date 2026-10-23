package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	"nabuauth/internal/tokens"
)

// freshSignIn is how recent a sign-in must be for an account with no known
// password to set one without typing a current password. Such an account came
// in through a phone code, an email code or a provider, and the only proof of
// who is at the keyboard is that door; a session that old enough to have been
// left open on a shared machine is not that proof any more.
const freshSignIn = 10 * time.Minute

// maxPasswordLen is bcrypt's limit. A longer password would be refused by the
// hash function itself, so it is refused here with a sentence instead.
const maxPasswordLen = 72

// handlePasswordChange lets the signed-in owner change their password, or set
// one for the first time.
//
// An account whose owner knows its password must type it: a session cookie on
// its own is not enough to take the account away from the person who made it.
// An account that has never had a known password (User.PasswordSet false) has
// nothing to type, so it may set one only within freshSignIn of signing in.
//
// A change signs out every other browser and revokes every app's refresh token
// (store.ChangePassword). The usual reason to change a password is that
// somebody else may have it; leaving their sessions alive would defeat that.
func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
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
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		http.Redirect(w, r, "/login?next=%2Fdashboard", http.StatusFound)
		return
	}
	session := tokens.HashOpaque(cookie.Value)

	back := func(result string) {
		http.Redirect(w, r, "/dashboard?password="+result+"#password", http.StatusSeeOther)
	}

	// Per account, not per address: the guess being limited is this account's
	// password, from whichever network the session happens to be on.
	key := "password-change:" + strconv.FormatInt(user.ID, 10)
	if s.throttle.blocked(key) {
		back("throttled")
		return
	}

	if user.PasswordSet {
		if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(r.PostFormValue("current"))) != nil {
			s.throttle.fail(key)
			back("wrong")
			return
		}
	} else {
		started, err := s.store.SessionStartedAt(r.Context(), session)
		if err != nil || time.Since(started) > freshSignIn {
			back("stale")
			return
		}
	}

	next := r.PostFormValue("new")
	switch {
	case len(next) < minPasswordLen:
		back("short")
		return
	case len(next) > maxPasswordLen:
		back("long")
		return
	case next != r.PostFormValue("confirm"):
		back("mismatch")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		s.log.Error("hash new password", "error", err)
		back("failed")
		return
	}
	if err := s.store.ChangePassword(r.Context(), user.ID, string(hash), session); err != nil {
		if !errors.Is(err, context.Canceled) {
			s.log.Error("change password", "user", user.ID, "error", err)
		}
		back("failed")
		return
	}
	s.throttle.reset(key)
	s.log.Info("password changed", "user", user.ID, "first", !user.PasswordSet)
	back("changed")
}
