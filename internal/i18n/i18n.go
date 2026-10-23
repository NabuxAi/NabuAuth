// Package i18n puts the account pages in the visitor's language.
//
// English is the source text: every message is written in English where it is
// used, and each other language is a catalog from that exact English string to
// its translation. A string missing from a catalog shows in English rather than
// as an empty space or a key name, and TestEveryStringIsTranslated keeps the
// catalogs complete.
package i18n

import (
	"fmt"
	"net/http"
	"strings"
)

// Lang is one language the pages can be shown in.
type Lang struct {
	Code string // BCP 47, also the value of ?lang= and of <html lang>
	Name string // in its own language, for the switcher
	Dir  string // "rtl" or "ltr", for <html dir>
}

// Default is the language a visitor sees when nothing says otherwise: the one
// the Nabu ecosystem speaks first, as every other Nabu product does.
const Default = "fa"

// Langs is every supported language, in switcher order.
var Langs = []Lang{
	{Code: "fa", Name: "فارسی", Dir: "rtl"},
	{Code: "en", Name: "English", Dir: "ltr"},
	{Code: "ar", Name: "العربية", Dir: "rtl"},
	{Code: "tr", Name: "Türkçe", Dir: "ltr"},
}

// Cookie remembers a visitor's choice across pages and visits.
const Cookie = "nabuauth_lang"

// catalogs maps a language code to its English-to-translation table. English
// has none: it is the source.
var catalogs = map[string]map[string]string{
	"fa": fa,
	"ar": ar,
	"tr": tr,
}

// Get returns the language for a code, or the default for an unknown one.
func Get(code string) Lang {
	for _, l := range Langs {
		if l.Code == code {
			return l
		}
	}
	return Get(Default)
}

// Supported reports whether a code is one of Langs.
func Supported(code string) bool {
	for _, l := range Langs {
		if l.Code == code {
			return true
		}
	}
	return false
}

// Pick decides a request's language: ?lang= first (a link that says which
// language is a choice), then the remembered choice, then the browser's own
// preference, then Default.
func Pick(r *http.Request) Lang {
	if code := r.URL.Query().Get("lang"); Supported(code) {
		return Get(code)
	}
	if c, err := r.Cookie(Cookie); err == nil && Supported(c.Value) {
		return Get(c.Value)
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag, _, _ := strings.Cut(strings.TrimSpace(part), ";")
		base, _, _ := strings.Cut(strings.ToLower(tag), "-")
		if Supported(base) {
			return Get(base)
		}
	}
	return Get(Default)
}

// T translates an English source string into lang and fills any fmt verbs
// with args. A string the catalog lacks comes back in English.
func T(lang, msg string, args ...any) string {
	if out, ok := catalogs[lang][msg]; ok && out != "" {
		msg = out
	}
	if len(args) > 0 {
		return fmt.Sprintf(msg, args...)
	}
	return msg
}
