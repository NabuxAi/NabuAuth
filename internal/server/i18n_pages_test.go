package server

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"nabuauth/internal/config"
	"nabuauth/internal/i18n"
)

// TestEveryStringIsTranslated finds every sentence the pages can show — in the
// templates, in the handlers, and in apps.yaml — and fails on any that a
// catalog lacks. Without it a new sentence ships in English to everybody.
func TestEveryStringIsTranslated(t *testing.T) {
	want := map[string]string{} // string -> where it was found

	templateCall := regexp.MustCompile(`\{\{t \$\.Lang "((?:[^"\\]|\\.)*)"`)
	files, _ := filepath.Glob("../../web/templates/*.html")
	if len(files) == 0 {
		t.Fatal("no templates found")
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range templateCall.FindAllStringSubmatch(string(raw), -1) {
			s, err := strconv.Unquote(`"` + m[1] + `"`)
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			want[s] = filepath.Base(f)
		}
	}

	// Handler sentences: the string literals on the lines that hand a message
	// to a page. They are English source text, translated by render.
	messageLine := regexp.MustCompile(`(fail\(|renderLogin\(|renderAdminUsers\(|renderCredential\(|"Title":|"Message":|Refusal\s*=|Notice\s*=|refusal\s*:?=|i18n\.T\()`)
	literal := regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	sources, _ := filepath.Glob("*.go")
	for _, f := range sources {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			hit := messageLine.MatchString(line) ||
				(i > 0 && messageLine.MatchString(lines[i-1]) && strings.HasPrefix(strings.TrimSpace(line), `"`))
			if !hit || strings.Contains(line, "log.") {
				continue
			}
			for _, m := range literal.FindAllStringSubmatch(line, -1) {
				s, err := strconv.Unquote(`"` + m[1] + `"`)
				if err != nil || len(s) < 3 || !strings.Contains(s, " ") {
					continue
				}
				if first := s[0]; (first >= 'A' && first <= 'Z') || first == '"' {
					want[s] = f
				}
			}
		}
	}

	cfg, err := config.Load("../../apps.yaml")
	if err != nil {
		t.Fatalf("load apps.yaml: %v", err)
	}
	for _, label := range cfg.Scopes {
		want[label] = "apps.yaml scopes"
	}
	for _, label := range config.DefaultScopes {
		want[label] = "config.DefaultScopes"
	}
	for _, app := range cfg.Apps {
		if app.Description != "" {
			want[app.Description] = "apps.yaml " + app.ID
		}
	}

	for _, l := range i18n.Langs {
		if l.Code == "en" {
			continue
		}
		for s, where := range want {
			if i18n.T(l.Code, s) == s && !strings.EqualFold(s, "Telegram") {
				t.Errorf("%s: no %s translation for %q", where, l.Code, s)
			}
		}
	}
}

// The page itself has to say which language and direction it is in, and a
// choice made by link has to hold on the next page without the link.
func TestPagesFollowTheChosenLanguage(t *testing.T) {
	ts, _ := newTestServer(t)
	client := &http.Client{Jar: &cookieJar{}}

	get := func(path, accept string) string {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if accept != "" {
			req.Header.Set("Accept-Language", accept)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		defer resp.Body.Close()
		return readBody(t, resp)
	}

	if body := get("/login", "ar"); !strings.Contains(body, `<html lang="ar" dir="rtl">`) || !strings.Contains(body, "تسجيل الدخول") {
		t.Errorf("an Arabic browser did not get the Arabic page: %s", truncate(body))
	}
	if body := get("/login?lang=en", "ar"); !strings.Contains(body, `<html lang="en" dir="ltr">`) || !strings.Contains(body, ">Sign in<") {
		t.Errorf("?lang=en did not win over the browser: %s", truncate(body))
	}
	if body := get("/register", "ar"); !strings.Contains(body, `<html lang="en" dir="ltr">`) {
		t.Errorf("the choice made by link was not remembered on the next page: %s", truncate(body))
	}
	if body := get("/login?lang=fa", ""); !strings.Contains(body, `dir="rtl"`) || !strings.Contains(body, "ساخت حساب کاربری") {
		t.Errorf("the Persian page is not right-to-left Persian: %s", truncate(body))
	}
}
