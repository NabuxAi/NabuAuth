package i18n

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every catalog translates the same strings: one that is missing a key shows
// that sentence in English in the middle of a Persian page.
func TestCatalogsCoverTheSameStrings(t *testing.T) {
	for code, cat := range catalogs {
		for key := range catalogs["fa"] {
			if cat[key] == "" {
				t.Errorf("%s has no translation for %q", code, key)
			}
		}
		for key := range cat {
			if _, ok := catalogs["fa"][key]; !ok {
				t.Errorf("%s translates %q, which fa does not", code, key)
			}
		}
	}
}

// A translation with a different number of %s or %d would print "%!s(MISSING)"
// or drop a value.
func TestTranslationsKeepTheirFormatVerbs(t *testing.T) {
	for code, cat := range catalogs {
		for key, val := range cat {
			for _, verb := range []string{"%s", "%d"} {
				if strings.Count(key, verb) != strings.Count(val, verb) {
					t.Errorf("%s: %q has %d %s, its translation %q has %d", code, key, strings.Count(key, verb), verb, val, strings.Count(val, verb))
				}
			}
		}
	}
}

func TestTranslateFallsBackToTheEnglishSource(t *testing.T) {
	if got := T("fa", "Sign in"); got != "ورود" {
		t.Errorf("T(fa, Sign in) = %q", got)
	}
	if got := T("en", "Sign in"); got != "Sign in" {
		t.Errorf("English is the source and must come back as written: %q", got)
	}
	if got := T("fa", "A sentence nobody translated"); got != "A sentence nobody translated" {
		t.Errorf("a missing key must read in English, not vanish: %q", got)
	}
	if got := T("tr", "Continue to %s", "NabuGate"); got != "NabuGate uygulamasına devam" {
		t.Errorf("format args were not applied: %q", got)
	}
}

func TestPickOrder(t *testing.T) {
	req := func(query, cookie, accept string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/login"+query, nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: Cookie, Value: cookie})
		}
		if accept != "" {
			r.Header.Set("Accept-Language", accept)
		}
		return r
	}
	cases := []struct {
		name string
		r    *http.Request
		want string
	}{
		{"nothing says", req("", "", ""), "fa"},
		{"browser", req("", "", "ar-OM,ar;q=0.9,en;q=0.8"), "ar"},
		{"browser, second choice", req("", "", "de-DE,tr;q=0.9"), "tr"},
		{"browser, nothing supported", req("", "", "de-DE,de;q=0.9"), "fa"},
		{"remembered beats browser", req("", "en", "ar"), "en"},
		{"link beats remembered", req("?lang=tr", "en", "ar"), "tr"},
		{"unknown link value is ignored", req("?lang=xx", "en", ""), "en"},
	}
	for _, c := range cases {
		if got := Pick(c.r).Code; got != c.want {
			t.Errorf("%s: picked %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRightToLeftLanguages(t *testing.T) {
	for code, dir := range map[string]string{"fa": "rtl", "ar": "rtl", "en": "ltr", "tr": "ltr"} {
		if got := Get(code).Dir; got != dir {
			t.Errorf("%s dir = %q, want %q", code, got, dir)
		}
	}
}
