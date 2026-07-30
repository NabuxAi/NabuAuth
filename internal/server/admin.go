package server

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"nabuauth/internal/store"
)

// Administrator pages for managing who has a Nabu account.
//
// Sign-up is closed in production and every app now presents a Nabu account as
// the way in, so without a path here there is no way to add a second person
// short of writing to the database by hand.

// newGeneratedPassword returns a random password strong enough that showing it
// once and never storing it is safe.
func newGeneratedPassword() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// requireAdmin resolves the session and refuses anyone who is not an
// administrator. The check is on the account, not on a URL that happens to
// start with /admin.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	user, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusFound)
		return store.User{}, false
	}
	if !user.IsAdmin {
		s.render(w, http.StatusForbidden, "error.html", map[string]any{
			"Title":   "Not allowed",
			"Message": "Only an administrator can manage Nabu accounts.",
		})
		return store.User{}, false
	}
	return user, true
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	s.renderAdminUsers(w, r, admin, nil, "", "")
}

// renderAdminUsers draws the page. created carries a one-time password so it can
// be shown immediately after a account is added — it is never stored in clear
// and cannot be shown again.
func (s *Server) renderAdminUsers(w http.ResponseWriter, r *http.Request, admin store.User, created *store.User, password, errMsg string) {
	users, err := s.store.ListUsers(r.Context(), 200)
	if err != nil {
		s.log.Error("list users", "error", err)
	}
	status := http.StatusOK
	if errMsg != "" {
		status = http.StatusBadRequest
	}
	s.render(w, status, "admin_users.html", map[string]any{
		"Title":       "Nabu accounts",
		"User":        admin,
		"Users":       users,
		"Created":     created,
		"Password":    password,
		"Error":       errMsg,
		"CSRF":        s.csrfToken(r),
		"SelfID":      admin.ID,
		"AccountsURL": s.cfg.Server.Issuer,
	})
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "invalid form token", http.StatusForbidden)
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	name := strings.TrimSpace(r.PostFormValue("name"))
	makeAdmin := r.PostFormValue("is_admin") == "yes"

	if !validEmail(email) {
		s.renderAdminUsers(w, r, admin, nil, "", "That email address does not look right.")
		return
	}
	if name == "" {
		if at := strings.IndexByte(email, '@'); at > 0 {
			name = email[:at]
		} else {
			name = email
		}
	}

	// The password is generated rather than chosen by the administrator: one
	// person picking passwords for everyone is how a whole team ends up sharing
	// a pattern. It is shown once and never stored in clear.
	password, err := newGeneratedPassword()
	if err != nil {
		s.log.Error("generate password", "error", err)
		s.renderAdminUsers(w, r, admin, nil, "", "Could not create the account. Try again.")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		s.log.Error("hash password", "error", err)
		s.renderAdminUsers(w, r, admin, nil, "", "Could not create the account. Try again.")
		return
	}

	user, err := s.store.CreateUser(r.Context(), name, email, "", string(hash), makeAdmin)
	if errors.Is(err, store.ErrDuplicate) {
		s.renderAdminUsers(w, r, admin, nil, "", "That email is already registered.")
		return
	}
	if err != nil {
		s.log.Error("create user", "error", err)
		s.renderAdminUsers(w, r, admin, nil, "", "Could not create the account. Try again.")
		return
	}
	s.renderAdminUsers(w, r, admin, &user, password, "")
}

func (s *Server) handleAdminToggleUser(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "invalid form token", http.StatusForbidden)
		return
	}

	id, err := strconv.ParseInt(r.PostFormValue("user_id"), 10, 64)
	if err != nil {
		http.Error(w, "bad user id", http.StatusBadRequest)
		return
	}
	// Disabling your own account would lock you out of the page that could undo
	// it, and on a one-admin deployment that is the end of administration.
	if id == admin.ID {
		s.renderAdminUsers(w, r, admin, nil, "", "You cannot disable your own account.")
		return
	}

	active := r.PostFormValue("active") == "yes"
	if err := s.store.SetActive(r.Context(), id, active); err != nil {
		s.log.Error("set active", "error", err)
	}
	if !active {
		// A disabled account must not keep a live browser session or a refresh
		// token that outlives the decision.
		if err := s.store.RevokeUserSessions(r.Context(), id); err != nil {
			s.log.Error("revoke sessions", "error", err)
		}
		if err := s.store.RevokeUserTokens(r.Context(), id); err != nil {
			s.log.Error("revoke tokens", "error", err)
		}
	}
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}
