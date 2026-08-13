package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"nabuauth/internal/config"
	"nabuauth/internal/store"
	"nabuauth/internal/tokens"
)

// Phone sign-in against a stand-in for NabuSms. The gateway is faked rather than
// called, but it is faked accurately in the one way that matters: it answers
// HTTP 200 whether or not a message went out, and says which in the body. A
// client that reads only the status code is how a sign-in form comes to promise
// a code it never sent, and one of these tests exists solely to hold that shut.

// fakeGateway stands in for NabuSms. It records every send so a test can read
// the code that was "delivered", and can be told to fail a message the way the
// real gateway does — with a 200 and a failure inside the body.
type fakeGateway struct {
	*httptest.Server

	mu     sync.Mutex
	sends  []gatewaySend
	refuse bool
}

type gatewaySend struct {
	To       string
	Route    string
	Template string
	Text     string
	Params   map[string]string
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	gw := &fakeGateway{}
	gw.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-sms-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body struct {
			To       []string          `json:"to"`
			Text     string            `json:"text"`
			Route    string            `json:"route"`
			Template string            `json:"template"`
			Params   map[string]string `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		gw.mu.Lock()
		for _, to := range body.To {
			gw.sends = append(gw.sends, gatewaySend{To: to, Route: body.Route, Template: body.Template, Text: body.Text, Params: body.Params})
		}
		refuse := gw.refuse
		gw.mu.Unlock()

		if refuse {
			// Exactly what NabuSms does when every provider refused: the request
			// was fine, the message was not sent, and the status code says
			// nothing about it.
			writeJSON(w, http.StatusOK, map[string]any{
				"sent": 0, "failed": 1,
				"messages": []map[string]any{{"status": "failed", "error": "route otp does not cover OM"}},
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"sent": 1, "failed": 0,
			"messages": []map[string]any{{"status": "sent", "provider": "smsir"}},
		})
	}))
	t.Cleanup(gw.Close)
	return gw
}

// lastCode returns the code the gateway was last asked to deliver, however the
// route carried it.
func (g *fakeGateway) lastCode(t *testing.T) string {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.sends) == 0 {
		t.Fatal("no message was handed to the gateway")
	}
	last := g.sends[len(g.sends)-1]
	if code := last.Params["code"]; code != "" {
		return code
	}
	// The international route carries plain text, so the code is inside it.
	for _, word := range strings.FieldsFunc(last.Text, func(r rune) bool { return r < '0' || r > '9' }) {
		if len(word) == 6 {
			return word
		}
	}
	t.Fatalf("the message carried no code: %+v", last)
	return ""
}

func (g *fakeGateway) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sends)
}

// at returns one recorded send.
func (g *fakeGateway) at(t *testing.T, i int) gatewaySend {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if i >= len(g.sends) {
		t.Fatalf("the gateway was handed %d messages, wanted at least %d", len(g.sends), i+1)
	}
	return g.sends[i]
}

// otherThan is a six-digit code that is definitely not the right one, so a test
// about wrong guesses cannot pass or fail on a one-in-a-million coincidence.
func otherThan(t *testing.T, code string, nth int) string {
	t.Helper()
	n, err := strconv.Atoi(code)
	if err != nil {
		t.Fatalf("the gateway carried %q, which is not a code", code)
	}
	return fmt.Sprintf("%06d", (n+nth+1)%1000000)
}

// withGateway configures the SMS gateway on the server under test. The key still
// arrives through an env var, because that is what decides whether the option is
// offered at all.
func withGateway(gw *fakeGateway) func(*config.Config) {
	return func(cfg *config.Config) {
		cfg.Sms = config.Sms{BaseURL: gw.URL, KeyEnv: "TEST_SMS_KEY"}
		cfg.Sms.ApplyDefaults()
	}
}

// seedUserWithPhone creates an account that already holds a number.
func seedUserWithPhone(t *testing.T, st *store.Store, email, phone string) store.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-horse-battery"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	u, err := st.CreateUser(context.Background(), "Test User", email, phone, string(hash), false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

// requestCode submits the phone half of the form and returns the client holding
// whatever cookies came back.
func requestCode(t *testing.T, ts *httptest.Server, country, phone string) (*http.Client, *http.Response) {
	t.Helper()
	client := &http.Client{
		Jar:           &cookieJar{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.PostForm(ts.URL+"/login/phone", url.Values{"country": {country}, "phone": {phone}})
	if err != nil {
		t.Fatalf("request code: %v", err)
	}
	return client, resp
}

func verifyCode(t *testing.T, client *http.Client, ts *httptest.Server, phone, country, code string) *http.Response {
	t.Helper()
	resp, err := client.PostForm(ts.URL+"/login/phone/verify", url.Values{
		"phone": {phone}, "country": {country}, "code": {code},
	})
	if err != nil {
		t.Fatalf("verify code: %v", err)
	}
	return resp
}

func TestACodeThatArrivesSignsInTheAccountHoldingThatNumber(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	ts, st := newTestServer(t, withGateway(gw))
	user := seedUserWithPhone(t, st, "user@nabuxai.com", "+989121234567")

	client, sent := requestCode(t, ts, "IR", "09121234567")
	defer sent.Body.Close()
	if sent.StatusCode != http.StatusOK {
		t.Fatalf("requesting a code answered %d, want 200", sent.StatusCode)
	}
	// The national number and the selected country became one canonical E.164
	// number, which is what the gateway and the database both key on.
	if to := gw.at(t, 0).To; to != "+989121234567" {
		t.Fatalf("the gateway was given %q, want the E.164 form of what was typed", to)
	}

	resp := verifyCode(t, client, ts, "+989121234567", "IR", gw.lastCode(t))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want a redirect into the account: %s", resp.StatusCode, truncate(readBody(t, resp)))
	}
	if loc := resp.Header.Get("Location"); loc != "/dashboard" {
		t.Fatalf("landed on %q, want /dashboard", loc)
	}

	session := ""
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("a verified code started no session")
	}
	// And it is the number's holder who is signed in, not some other account.
	signed, err := st.SessionUser(context.Background(), tokens.HashOpaque(session))
	if err != nil {
		t.Fatalf("resolve session: %v", err)
	}
	if signed.ID != user.ID {
		t.Fatalf("signed in user %d, want the account holding the number (%d)", signed.ID, user.ID)
	}
	if !signed.PhoneVerified {
		t.Fatal("the number proved itself and the account does not say so")
	}
}

func TestAWrongCodeDoesNotSignAnybodyIn(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	ts, st := newTestServer(t, withGateway(gw))
	seedUserWithPhone(t, st, "user@nabuxai.com", "+989121234567")

	client, sent := requestCode(t, ts, "IR", "09121234567")
	sent.Body.Close()

	resp := verifyCode(t, client, ts, "+989121234567", "IR", otherThan(t, gw.lastCode(t), 0))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("a wrong code started a session")
		}
	}
}

func TestAnExpiredCodeDoesNotSignAnybodyIn(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	ts, st := newTestServer(t, withGateway(gw))
	seedUserWithPhone(t, st, "user@nabuxai.com", "+989121234567")

	client, sent := requestCode(t, ts, "IR", "09121234567")
	sent.Body.Close()
	code := gw.lastCode(t)

	// Age the code past its window. Whoever read the message an hour later must
	// not still be able to walk in with it.
	if _, err := st.DB().ExecContext(context.Background(),
		`UPDATE phone_codes SET expires_at = now() - interval '1 minute' WHERE phone = $1`, "+989121234567"); err != nil {
		t.Fatalf("expire the code: %v", err)
	}

	resp := verifyCode(t, client, ts, "+989121234567", "IR", code)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
	if body := readBody(t, resp); !strings.Contains(body, phoneRefusal) {
		t.Fatalf("an expired code was refused with something other than %q: %s", phoneRefusal, truncate(body))
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("an expired code started a session")
		}
	}
}

func TestACodeIsSpentTheFirstTimeItWorks(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	ts, st := newTestServer(t, withGateway(gw))
	seedUserWithPhone(t, st, "user@nabuxai.com", "+989121234567")

	client, sent := requestCode(t, ts, "IR", "09121234567")
	sent.Body.Close()
	code := gw.lastCode(t)

	first := verifyCode(t, client, ts, "+989121234567", "IR", code)
	first.Body.Close()
	if first.StatusCode != http.StatusFound {
		t.Fatalf("the first use answered %d, want a redirect", first.StatusCode)
	}

	// Anyone else who read the message — a shared phone, a notification on a
	// lock screen, an SS7 intercept — gets nothing from it.
	second := &http.Client{
		Jar:           &cookieJar{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	replay := verifyCode(t, second, ts, "+989121234567", "IR", code)
	defer replay.Body.Close()
	if replay.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a replayed code answered %d, want 401", replay.StatusCode)
	}
	for _, c := range replay.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("a replayed code started a second session")
		}
	}
}

func TestThePhoneOptionIsAbsentWhenNoGatewayIsConfigured(t *testing.T) {
	// The same rule an external provider follows: a field that cannot send a
	// code would report one as sent, which is worse than no field at all.
	gw := newFakeGateway(t)
	ts, _ := newTestServer(t, withGateway(gw)) // configured, but TEST_SMS_KEY is unset

	form, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	defer form.Body.Close()
	if body := readBody(t, form); strings.Contains(body, `name="phone"`) {
		t.Fatal("a deployment with no SMS key is still offering the phone field")
	}

	resp, err := http.PostForm(ts.URL+"/login/phone", url.Values{"country": {"IR"}, "phone": {"09121234567"}})
	if err != nil {
		t.Fatalf("post phone: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404 for a door this deployment cannot open", resp.StatusCode)
	}
	if gw.count() != 0 {
		t.Fatal("a deployment with no key still called the gateway")
	}
}

func TestTheFormOffersTheCountriesTheGatewayCanReach(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	ts, _ := newTestServer(t, withGateway(newFakeGateway(t)))

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	defer resp.Body.Close()

	body := readBody(t, resp)
	// A selector, not a country baked into the form: the complaint this answers
	// is that the only number anybody could sign in with was an Iranian one.
	for _, want := range []string{`name="country"`, `value="IR"`, `value="OM"`, `value="GB"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("the form does not offer %s: %s", want, truncate(body))
		}
	}
}

func TestANumberOutsideIranIsCarriedByTheRouteThatAcceptsIt(t *testing.T) {
	// The gateway's one-time-code route is declared for Iranian numbers only and
	// refuses anything else before a provider is tried, so a country selector
	// that did not also choose the route would be a selector whose other
	// entries never work.
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	ts, st := newTestServer(t, withGateway(gw))
	seedUserWithPhone(t, st, "omani@nabuxai.com", "+96891234567")

	client, sent := requestCode(t, ts, "OM", "91234567")
	sent.Body.Close()

	if to := gw.at(t, 0).To; to != "+96891234567" {
		t.Fatalf("the gateway was given %q; the selected country was not applied", to)
	}
	if route := gw.at(t, 0).Route; route != "international" {
		t.Fatalf("an Omani number went out on route %q, which the gateway refuses for anything but Iran", route)
	}
	if gw.at(t, 0).Template != "" {
		t.Fatal("the international route was given a message template, and the provider behind it has none")
	}

	resp := verifyCode(t, client, ts, "+96891234567", "OM", gw.lastCode(t))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want a redirect into the account: %s", resp.StatusCode, truncate(readBody(t, resp)))
	}
}

func TestAGatewayThatSentNothingIsNotReportedAsHavingSent(t *testing.T) {
	// NabuSms answers 200 even when every message failed. A form that reads only
	// the status code tells somebody to wait for a code that is not coming, and
	// they have no way to find out otherwise.
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	gw.refuse = true
	ts, st := newTestServer(t, withGateway(gw))
	seedUserWithPhone(t, st, "user@nabuxai.com", "+989121234567")

	_, resp := requestCode(t, ts, "IR", "09121234567")
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatal("a message the gateway refused was answered as though it had gone out")
	}
	body := readBody(t, resp)
	if strings.Contains(body, phoneSentNotice) {
		t.Fatalf("the page says a code is on its way when none was sent: %s", truncate(body))
	}
	// And no code is left behind, or the cooldown would refuse the retry the
	// page just invited.
	if _, err := st.PhoneCode(context.Background(), "+989121234567"); err == nil {
		t.Fatal("a code was kept for a message that never went out")
	}
}

func TestAClosedDeploymentWillNotSayWhichPhonesHaveAccounts(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	ts, st := newTestServer(t, withGateway(gw), func(cfg *config.Config) { cfg.Server.AllowRegistration = false })
	// An account has to exist, or sign-up stays open regardless so a fresh
	// deployment can still be claimed.
	seedUserWithPhone(t, st, "user@nabuxai.com", "+989121234567")

	strangerClient, strangerSent := requestCode(t, ts, "IR", "09129999999")
	defer strangerSent.Body.Close()
	strangerAsked := readBody(t, strangerSent)

	holderClient, holderSent := requestCode(t, ts, "IR", "09121234567")
	defer holderSent.Body.Close()
	holderAsked := readBody(t, holderSent)

	if strangerSent.StatusCode != holderSent.StatusCode {
		t.Fatalf("a stranger's number answered %d and the holder's %d — the difference is the answer to \"does this number have an account\"",
			strangerSent.StatusCode, holderSent.StatusCode)
	}
	for name, body := range map[string]string{"unknown number": strangerAsked, "known number": holderAsked} {
		if !strings.Contains(body, phoneSentNotice) {
			t.Fatalf("asking for a code on an %s did not give the usual answer, which tells an outsider which numbers hold accounts", name)
		}
	}

	// But the stranger's number cost no message: there is nothing it could sign
	// into, and a real SMS would be paid for to tell somebody the number is
	// unknown.
	for i := 0; i < gw.count(); i++ {
		if gw.at(t, i).To == "+989129999999" {
			t.Fatal("a closed deployment spent an SMS on a number no account holds")
		}
	}

	// And typing anything back is refused in the same words a wrong code gets.
	strangerTry := verifyCode(t, strangerClient, ts, "+989129999999", "IR", "123456")
	defer strangerTry.Body.Close()
	holderTry := verifyCode(t, holderClient, ts, "+989121234567", "IR", "not-the-code")
	defer holderTry.Body.Close()

	if strangerTry.StatusCode != holderTry.StatusCode {
		t.Fatalf("verification answered %d for an unknown number and %d for a wrong code", strangerTry.StatusCode, holderTry.StatusCode)
	}
	for name, body := range map[string]string{"unknown number": readBody(t, strangerTry), "wrong code": readBody(t, holderTry)} {
		if !strings.Contains(body, phoneRefusal) {
			t.Fatalf("%s was refused with something other than %q", name, phoneRefusal)
		}
	}
	if count, err := st.CountUsers(context.Background()); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v, want no account created while sign-up is closed", count, err)
	}
}

func TestAVerifiedNumberNobodyHoldsBecomesAnAccount(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	ts, st := newTestServer(t, withGateway(gw))

	client, sent := requestCode(t, ts, "IR", "09121234567")
	sent.Body.Close()

	resp := verifyCode(t, client, ts, "+989121234567", "IR", gw.lastCode(t))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want a redirect into the new account: %s", resp.StatusCode, truncate(readBody(t, resp)))
	}

	user, err := st.UserByPhone(context.Background(), "+989121234567")
	if err != nil {
		t.Fatalf("no account was created for the verified number: %v", err)
	}
	// It has no email, and none was invented for it: email_verified would then
	// be a false claim about an address nobody owns.
	if user.Email != "" {
		t.Fatalf("the account was given the address %q, which nobody proved", user.Email)
	}
	if !user.PhoneVerified {
		t.Fatal("the account was created from a proved number and does not say so")
	}
	// And the address column must still be free for the next phone-only account
	// rather than taken by an empty string.
	if _, err := st.CreateUser(context.Background(), "second", "", "+989120000000", "x", false); err != nil {
		t.Fatalf("a second account with no email was refused: %v", err)
	}
}

func TestAResendInsideTheCooldownDoesNotBuyMoreGuesses(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	ts, st := newTestServer(t, withGateway(gw))
	seedUserWithPhone(t, st, "user@nabuxai.com", "+989121234567")

	client, first := requestCode(t, ts, "IR", "09121234567")
	first.Body.Close()
	code := gw.lastCode(t)

	// Spend one guess, then ask for another code straight away. If the resend
	// went through, the attempt counter would reset and the code could be
	// guessed at indefinitely.
	wrong := verifyCode(t, client, ts, "+989121234567", "IR", otherThan(t, code, 0))
	wrong.Body.Close()

	_, again := requestCode(t, ts, "IR", "09121234567")
	defer again.Body.Close()
	if again.StatusCode != http.StatusOK {
		t.Fatalf("a resend inside the cooldown answered %d, want the same 200 as a send", again.StatusCode)
	}
	if gw.count() != 1 {
		t.Fatalf("the gateway was called %d times; a resend inside the cooldown must not send again", gw.count())
	}

	pending, err := st.PhoneCode(context.Background(), "+989121234567")
	if err != nil {
		t.Fatalf("phone code: %v", err)
	}
	if pending.Attempts != 1 {
		t.Fatalf("attempts = %d, want the wrong guess still counted after the resend", pending.Attempts)
	}
	// And the original code still works, because nothing replaced it.
	resp := verifyCode(t, client, ts, "+989121234567", "IR", code)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want the original code to still sign in", resp.StatusCode)
	}
}

func TestACodeDiesAfterTooManyWrongGuesses(t *testing.T) {
	t.Setenv("TEST_SMS_KEY", "test-sms-key")
	gw := newFakeGateway(t)
	ts, st := newTestServer(t, withGateway(gw))
	seedUserWithPhone(t, st, "user@nabuxai.com", "+989121234567")

	client, sent := requestCode(t, ts, "IR", "09121234567")
	sent.Body.Close()
	code := gw.lastCode(t)

	for i := 0; i < store.MaxPhoneCodeAttempts; i++ {
		resp := verifyCode(t, client, ts, "+989121234567", "IR", otherThan(t, code, i))
		resp.Body.Close()
	}

	// Six digits is a million possibilities, which is a lot for a person and
	// nothing for a script. The budget, not the length, is what protects it.
	resp := verifyCode(t, client, ts, "+989121234567", "IR", code)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		t.Fatal("the right code still worked after its guess budget was spent")
	}
	if _, err := st.PhoneCode(context.Background(), "+989121234567"); err == nil {
		t.Fatal("a code with no remaining guesses was left in the database")
	}
}
