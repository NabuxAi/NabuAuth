package store

import "testing"

// The rule that decides which redirects must carry PKCE. Getting a case wrong
// in one direction blocks a real app's sign-in; in the other it lets a code
// travel to a scheme any app on the device can claim.
func TestRedirectIsInterceptable(t *testing.T) {
	cases := map[string]bool{
		"https://desk.nabuxai.com/auth/nabu/callback":  false,
		"HTTPS://desk.nabuxai.com/auth/nabu/callback":  false,
		"http://localhost:3000/api/auth/nabu/callback": true,
		"http://127.0.0.1:8080/api/nabu/callback":      true,
		"rasad://oauth": true,
		"http://desk.nabuxai.com/auth/nabu/callback": true,
		"":             true,
		"://not a url": true,
	}
	for uri, want := range cases {
		if got := RedirectIsInterceptable(uri); got != want {
			t.Errorf("RedirectIsInterceptable(%q) = %v, want %v", uri, got, want)
		}
	}
}
