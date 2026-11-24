package server

import (
	"net/http"
	"strings"
	"unicode"

	"nabuauth/internal/config"
)

// appView is what the sign-in pages need to draw an app: its name, its mark
// (a platform glyph for an app with a brand, initials otherwise) and whether it
// is the app the visitor is signing in to.
type appView struct {
	ID          string
	Name        string
	Description string
	URL         string
	Brand       string
	Initials    string
	Current     bool
}

// ecosystemView is the ecosystem half of the sign-in screen: the apps one
// account opens, and the MCP gateways — the apps that carry a platform brand —
// drawn as a row of marks.
type ecosystemView struct {
	Apps     []appView
	More     int
	Gateways []appView
}

// ecosystemApps is how many app names the panel lists before it says "+N
// more". The panel is there to say one account opens all of them, not to be
// the launcher; the dashboard is the launcher.
const ecosystemApps = 9

// viewOf builds the view of a configured app.
func viewOf(a config.App) appView {
	return appView{
		ID:          a.ID,
		Name:        a.Name,
		Description: a.Description,
		URL:         a.URL,
		Brand:       a.Brand,
		Initials:    appInitials(a.Name),
	}
}

// appByID is the view of a registered app, falling back to the name stored
// with the client when the config does not list it (a client registered by an
// older config, say) so the page still names it.
func (s *Server) appByID(id, storedName string) appView {
	if a, ok := s.cfg.App(id); ok {
		return viewOf(a)
	}
	return appView{ID: id, Name: storedName, Initials: appInitials(storedName)}
}

// ecosystem lists the apps a visitor can see from apps.yaml — hidden service
// clients stay out — with the one they are signing in to first and marked.
func (s *Server) ecosystem(currentID string) ecosystemView {
	var v ecosystemView
	var current *appView
	for _, a := range s.cfg.Apps {
		if a.Hidden {
			continue
		}
		view := viewOf(a)
		if a.ID == currentID {
			view.Current = true
		}
		switch {
		case view.Brand != "":
			v.Gateways = append(v.Gateways, view)
		case view.Current:
			c := view
			current = &c
		default:
			v.Apps = append(v.Apps, view)
		}
	}
	if current != nil {
		v.Apps = append([]appView{*current}, v.Apps...)
	}
	if len(v.Apps) > ecosystemApps {
		v.More = len(v.Apps) - ecosystemApps
		v.Apps = v.Apps[:ecosystemApps]
	}
	return v
}

// appInitials is the fallback mark. Most of the ecosystem is called Nabu-
// something, and "N" on every tile tells them apart by nothing, so the prefix
// is dropped first ("NabuDesk" → "De", "NabuCRM" → "CR"). Otherwise the first
// letters of the first two words, or of the two capitals in a single word that
// has them ("ReelMind" → "RM").
func appInitials(name string) string {
	words := strings.Fields(name)
	if len(words) == 0 {
		return "?"
	}
	first := words[0]
	if rest := strings.TrimPrefix(first, "Nabu"); rest != first && rest != "" {
		r := []rune(rest)
		if len(r) == 1 {
			return string(r)
		}
		if unicode.IsUpper(r[1]) {
			return string(r[:2])
		}
		return string([]rune{unicode.ToUpper(r[0]), unicode.ToLower(r[1])})
	}
	if len(words) > 1 {
		return string([]rune{unicode.ToUpper([]rune(first)[0]), unicode.ToUpper([]rune(words[1])[0])})
	}
	runes := []rune(first)
	out := []rune{unicode.ToUpper(runes[0])}
	for _, r := range runes[1:] {
		if unicode.IsUpper(r) {
			out = append(out, r)
			break
		}
	}
	return string(out)
}

// signedOutCookie marks a browser that has just signed out, so the sign-in
// page it lands on can say so — once — instead of looking as if nothing
// happened. A cookie rather than a query parameter so no URL changes.
const signedOutCookie = "nabuauth_signed_out"

func (s *Server) markSignedOut(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     signedOutCookie,
		Value:    "1",
		Path:     "/",
		MaxAge:   60,
		HttpOnly: true,
		Secure:   s.cfg.Server.UseSecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) takeSignedOut(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie(signedOutCookie)
	if err != nil || c.Value == "" {
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     signedOutCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.Server.UseSecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
	return true
}
