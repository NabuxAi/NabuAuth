package web

import (
	"bytes"
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestTelegramLoginOffersPopupAndLinkedPhoneCode(t *testing.T) {
	templates, err := Templates()
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"Lang": "en", "Dir": "ltr", "Title": "Sign in", "Kind": "",
		"Issuer": "https://auth.nabuxai.com", "Telegram": true,
		"TelegramCode": true, "Sms": true, "Next": "/oauth/authorize?client_id=testapp&redirect_uri=https%3A%2F%2Fexample.test%2Fcb&state=a-b",
	}
	var out bytes.Buffer
	if err := templates.ExecuteTemplate(&out, "login.html", data); err != nil {
		t.Fatal(err)
	}
	page := out.String()
	for _, wanted := range []string{"data-telegram-popup", "/static/telegram-popup.js", "data-telegram-code", "name=\"via\" value=\"telegram\""} {
		if !strings.Contains(page, wanted) {
			t.Errorf("login page missing %q", wanted)
		}
	}
	popupHref := regexp.MustCompile(`data-telegram-popup href="([^"]+)"`).FindStringSubmatch(page)
	if len(popupHref) < 2 {
		t.Fatal("Telegram popup link not rendered")
	}
	parsed, err := url.Parse(html.UnescapeString(popupHref[1]))
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("next"); got != data["Next"].(string) {
		t.Errorf("OAuth next state changed: got %q, want %q", got, data["Next"])
	}

	var complete bytes.Buffer
	if err := templates.ExecuteTemplate(&complete, "telegram_complete.html", map[string]any{
		"Lang": "en", "Dir": "ltr", "Title": "Completed", "Next": "/dashboard",
	}); err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"telegram-complete.js", "id=\"telegram-complete-continue\""} {
		if !strings.Contains(complete.String(), wanted) {
			t.Errorf("completion page missing %q", wanted)
		}
	}
}

func TestTelegramCodeIsOnlyOfferedWhenGatewayEnabled(t *testing.T) {
	templates, err := Templates()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := templates.ExecuteTemplate(&out, "login.html", map[string]any{
		"Lang": "en", "Dir": "ltr", "Telegram": true, "TelegramCode": false, "Sms": false,
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "data-telegram-code") {
		t.Fatal("Telegram code option shown without messaging gateway")
	}
}
