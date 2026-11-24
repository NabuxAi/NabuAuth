package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"nabuauth/internal/config"
	"nabuauth/internal/store"
	"nabuauth/internal/tokens"
)

// withTelegramRoute turns on the code-to-Telegram road: the gateway has a route
// that hands the code to Telegram's own gateway for the number itself.
func withTelegramRoute(gw *fakeGateway) func(*config.Config) {
	return func(cfg *config.Config) {
		withGateway(gw)(cfg)
		cfg.Sms.TelegramRoute = "otp-telegram-gateway"
	}
}

func getPage(t *testing.T, target string) (int, string) {
	t.Helper()
	resp, err := http.Get(target)
	if err != nil {
		t.Fatalf("get %s: %v", target, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, readBody(t, resp)
}

func TestTheTelegramButtonAsksForANumberWhenTheGatewayCanCarryTheCode(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	ts, _ := newTestServer(t, withTelegramRoute(gw))

	// The button no longer opens oauth.telegram.org, which Iran filters: it
	// leads to the same page asking for a mobile number.
	_, page := getPage(t, ts.URL+"/login?next=/oauth/authorize%3Fclient_id%3Dtestapp")
	if !strings.Contains(page, `href="/login?via=telegram&next=`) {
		t.Fatalf("the Telegram button does not lead to the number form:\n%s", truncate(page))
	}
	if strings.Contains(page, "data-telegram-popup") {
		t.Fatal("the Telegram button still opens Telegram's own login page")
	}

	status, form := getPage(t, ts.URL+"/login?via=telegram")
	if status != http.StatusOK {
		t.Fatalf("the number form answered %d", status)
	}
	for _, want := range []string{`type="tel"`, `name="via" value="telegram"`, "Send the code to Telegram"} {
		if !strings.Contains(form, want) {
			t.Errorf("the Telegram form lacks %q", want)
		}
	}
}

func TestOfficialTelegramLoginPreferredWhenBothRoutesConfigured(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	ts, _, _ := telegramServer(t, withTelegramRoute(gw))
	_, page := getPage(t, ts.URL+"/login?next=/dashboard")
	if !strings.Contains(page, `data-telegram-popup href="/login/telegram?next=`) {
		t.Fatal("official Telegram login must be the primary button")
	}
	if !strings.Contains(page, `href="/login?via=telegram&next=`) {
		t.Fatal("number-code fallback must remain available")
	}
}

func TestWithoutTheRouteTheTelegramButtonIsUnchanged(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	ts, _ := newTestServer(t, withGateway(gw))

	// A deployment that has not set the route must not grow a form that sends
	// a code nobody can deliver; ?via=telegram then is just the usual page.
	_, page := getPage(t, ts.URL+"/login?via=telegram")
	if strings.Contains(page, "Send the code to Telegram") {
		t.Fatal("the Telegram number form appeared on a gateway with no Telegram route")
	}
}

func TestANumberSentThroughTheTelegramButtonGetsItsCodeInTelegram(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	ts, st := newTestServer(t, withTelegramRoute(gw))
	user := seedUserWithPhone(t, st, "user@nabuxai.com", "+989121234567")

	client, sent := requestCodeVia(t, ts, url.Values{"identifier": {"09121234567"}, "via": {"telegram"}})
	defer sent.Body.Close()
	if sent.StatusCode != http.StatusOK {
		t.Fatalf("asking for the code answered %d", sent.StatusCode)
	}
	body := readBody(t, sent)

	if gw.count() != 1 {
		t.Fatalf("the gateway was handed %d messages, want exactly one", gw.count())
	}
	got := gw.at(t, 0)
	if got.Route != "otp-telegram-gateway" || got.To != "+989121234567" {
		t.Fatalf("the code went %+v, want the Telegram route to the number in E.164", got)
	}
	// The gateway's provider takes the code as a parameter, under the same
	// names the domestic pattern reads.
	if got.Params["token"] == "" || got.Params["token"] != got.Params["code"] {
		t.Fatalf("the code travelled as %v", got.Params)
	}
	// Resending keeps the road the first code took, and SMS is offered as the
	// other one.
	if !strings.Contains(body, `name="via" value="telegram"`) || !strings.Contains(body, "Send the code by SMS instead") {
		t.Errorf("the code step forgot it was sent to Telegram:\n%s", truncate(body))
	}

	resp := verifyCode(t, client, ts, "+989121234567", "IR", gw.lastCode(t))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want a redirect into the account", resp.StatusCode)
	}
	signed := sessionUser(t, st, resp)
	if signed.ID != user.ID {
		t.Fatalf("signed in user %d, want the account holding the number (%d)", signed.ID, user.ID)
	}
}

func TestANumberTelegramCannotReachGetsItsCodeBySms(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	gw.refuseRoute = "otp-telegram-gateway"
	ts, st := newTestServer(t, withTelegramRoute(gw))
	seedUserWithPhone(t, st, "user@nabuxai.com", "+989121234567")

	client, sent := requestCodeVia(t, ts, url.Values{"identifier": {"09121234567"}, "via": {"telegram"}})
	defer sent.Body.Close()
	if sent.StatusCode != http.StatusOK {
		t.Fatalf("a number without Telegram answered %d: the page must not tell it apart", sent.StatusCode)
	}

	if gw.count() != 2 {
		t.Fatalf("the gateway was handed %d messages, want the Telegram try then SMS", gw.count())
	}
	if fallback := gw.at(t, 1); fallback.Route != "otp" {
		t.Fatalf("the fallback went on %q, want the SMS route", fallback.Route)
	}

	resp := verifyCode(t, client, ts, "+989121234567", "IR", gw.lastCode(t))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("the SMS code did not sign in: %d", resp.StatusCode)
	}
}

// requestCodeVia posts the one-box form and keeps the cookies for the code step.
func requestCodeVia(t *testing.T, ts *httptest.Server, form url.Values) (*http.Client, *http.Response) {
	t.Helper()
	client := &http.Client{
		Jar:           &cookieJar{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("request code: %v", err)
	}
	return client, resp
}

// sessionUser is the account a response signed in.
func sessionUser(t *testing.T, st *store.Store, resp *http.Response) store.User {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			u, err := st.SessionUser(context.Background(), tokens.HashOpaque(c.Value))
			if err != nil {
				t.Fatalf("resolve session: %v", err)
			}
			return u
		}
	}
	t.Fatal("no session was started")
	return store.User{}
}
