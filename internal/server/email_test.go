package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"testing"

	"nabuauth/internal/config"
	"nabuauth/internal/store"
	"nabuauth/internal/tokens"
)

// Email-code sign-in against a stand-in submission server. The relay is faked
// rather than called, but faked accurately in the one way that matters: a
// message counts as sent only when the server accepted the DATA. A handler that
// treats silence as success is how a form comes to promise a code it never
// sent.

// fakeRelay stands in for the submission server. It records every message it
// accepts so a test can read the code that was "delivered", and can be told to
// refuse authentication the way a misconfigured deployment fails.
type fakeRelay struct {
	ln net.Listener

	mu       sync.Mutex
	accepted []recordedMail
	refuse   bool
}

type recordedMail struct {
	to   string
	data string
}

func newFakeRelay(t *testing.T) *fakeRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeRelay{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.converse(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeRelay) converse(conn net.Conn) {
	defer conn.Close()
	tc := textproto.NewConn(conn)
	defer tc.Close()

	var to string
	if err := tc.PrintfLine("220 fake ESMTP ready"); err != nil {
		return
	}
	for {
		line, err := tc.ReadLine()
		if err != nil {
			return
		}
		verb := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(verb, "EHLO"), strings.HasPrefix(verb, "HELO"):
			reply(tc, "250-fake greets you")
			reply(tc, "250-AUTH PLAIN")
			reply(tc, "250 8BITMIME")
		case strings.HasPrefix(verb, "AUTH PLAIN "):
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH PLAIN "):]))
			parts := strings.Split(string(decoded), "\x00")
			if err != nil || len(parts) != 3 || f.refuse || parts[1] != "noreply@nabuxai.com" || parts[2] != "test-smtp-password" {
				reply(tc, "535 5.7.8 authentication credentials invalid")
				continue
			}
			reply(tc, "235 2.7.0 authentication successful")
		case strings.HasPrefix(verb, "MAIL FROM:"):
			reply(tc, "250 2.1.0 sender ok")
		case strings.HasPrefix(verb, "RCPT TO:"):
			to = strings.Trim(strings.Fields(line[len("RCPT TO:"):])[0], "<>")
			reply(tc, "250 2.1.5 recipient ok")
		case verb == "DATA":
			reply(tc, "354 End data with <CR><LF>.<CR><LF>")
			data, err := tc.ReadDotBytes()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.accepted = append(f.accepted, recordedMail{to: to, data: string(data)})
			f.mu.Unlock()
			reply(tc, "250 2.0.0 queued")
		case verb == "RSET" || verb == "NOOP":
			reply(tc, "250 2.0.0 ok")
		case verb == "QUIT":
			reply(tc, "221 2.0.0 closing connection")
			return
		default:
			reply(tc, "502 5.5.2 command not recognised")
		}
	}
}

func reply(tc *textproto.Conn, line string) {
	if err := tc.PrintfLine("%s", line); err != nil {
		panic(err)
	}
}

func (f *fakeRelay) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.accepted)
}

// lastCode returns the code the relay was last asked to deliver, read out of
// the sentence that carries it.
func (f *fakeRelay) lastCode(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.accepted) == 0 {
		t.Fatal("no message reached the relay")
	}
	data := f.accepted[len(f.accepted)-1].data
	const marker = "sign-in code is "
	i := strings.Index(data, marker)
	if i < 0 {
		t.Fatalf("the message carried no code:\n%s", data)
	}
	code := data[i+len(marker):]
	if len(code) < 6 {
		t.Fatalf("the code ran out at %q", code)
	}
	return code[:6]
}

// deliveredTo reports whether the relay was ever handed a message for the
// address — the question a closed deployment must always answer with no.
func (f *fakeRelay) deliveredTo(addr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.accepted {
		if m.to == addr {
			return true
		}
	}
	return false
}

// withMail configures the SMTP relay on the server under test.
func withMail(f *fakeRelay) func(*config.Config) {
	return func(cfg *config.Config) {
		cfg.Mail = config.Mail{
			Host:     "127.0.0.1",
			Port:     f.ln.Addr().(*net.TCPAddr).Port,
			Username: "noreply@nabuxai.com",
			Password: "test-smtp-password",
		}
		cfg.Mail.ApplyDefaults()
	}
}

// requestEmailCode asks for a code on the address and returns the client
// holding whatever cookies came back.
func requestEmailCode(t *testing.T, ts *httptest.Server, email string) (*http.Client, *http.Response) {
	t.Helper()
	client := &http.Client{
		Jar:           &cookieJar{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.PostForm(ts.URL+"/login/email", url.Values{"email": {email}})
	if err != nil {
		t.Fatalf("request code: %v", err)
	}
	return client, resp
}

func verifyEmailCode(t *testing.T, client *http.Client, ts *httptest.Server, email, code string) *http.Response {
	t.Helper()
	resp, err := client.PostForm(ts.URL+"/login/email/verify", url.Values{
		"email": {email}, "code": {code},
	})
	if err != nil {
		t.Fatalf("verify code: %v", err)
	}
	return resp
}

// otherEmailCode is a six-digit code that is definitely not the right one, so a
// test about wrong guesses cannot pass or fail on a one-in-a-million
// coincidence.
func otherEmailCode(t *testing.T, code string, nth int) string {
	t.Helper()
	n := 0
	if _, err := fmt.Sscanf(code, "%d", &n); err != nil {
		t.Fatalf("the relay carried %q, which is not a code", code)
	}
	return fmt.Sprintf("%06d", (n+nth+1)%1000000)
}

func TestACodeThatArrivesSignsInTheAccountHoldingThatAddress(t *testing.T) {
	fake := newFakeRelay(t)
	ts, st := newTestServer(t, withMail(fake))
	user := seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	// Typed in whatever case the person happened to use; the row the code is
	// stored under is the one canonical lowercase form.
	client, sent := requestEmailCode(t, ts, "User@NabuxAI.com")
	defer sent.Body.Close()
	if sent.StatusCode != http.StatusOK {
		t.Fatalf("requesting a code answered %d, want 200", sent.StatusCode)
	}
	if !fake.deliveredTo("user@nabuxai.com") {
		t.Fatal("the code was not mailed to the canonical form of what was typed")
	}

	resp := verifyEmailCode(t, client, ts, "user@nabuxai.com", fake.lastCode(t))
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
	// And it is the address's holder who is signed in, not some other account.
	signed, err := st.SessionUser(context.Background(), tokens.HashOpaque(session))
	if err != nil {
		t.Fatalf("resolve session: %v", err)
	}
	if signed.ID != user.ID {
		t.Fatalf("signed in user %d, want the account holding the address (%d)", signed.ID, user.ID)
	}
	// The mailbox proved itself, and /api/v1/user may now say so truthfully.
	if !signed.EmailVerified {
		t.Fatal("the address proved itself and the account does not say so")
	}
}

func TestAWrongEmailCodeDoesNotSignAnybodyIn(t *testing.T) {
	fake := newFakeRelay(t)
	ts, st := newTestServer(t, withMail(fake))
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	client, sent := requestEmailCode(t, ts, "user@nabuxai.com")
	sent.Body.Close()

	resp := verifyEmailCode(t, client, ts, "user@nabuxai.com", otherEmailCode(t, fake.lastCode(t), 0))
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

func TestAnExpiredEmailCodeDoesNotSignAnybodyIn(t *testing.T) {
	fake := newFakeRelay(t)
	ts, st := newTestServer(t, withMail(fake))
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	client, sent := requestEmailCode(t, ts, "user@nabuxai.com")
	sent.Body.Close()
	code := fake.lastCode(t)

	// Age the code past its window. Whoever read the message an hour later must
	// not still be able to walk in with it.
	if _, err := st.DB().ExecContext(context.Background(),
		`UPDATE email_codes SET expires_at = now() - interval '1 minute' WHERE email = $1`, "user@nabuxai.com"); err != nil {
		t.Fatalf("expire the code: %v", err)
	}

	resp := verifyEmailCode(t, client, ts, "user@nabuxai.com", code)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
	if body := readBody(t, resp); !strings.Contains(body, emailRefusal) {
		t.Fatalf("an expired code was refused with something other than %q: %s", emailRefusal, truncate(body))
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("an expired code started a session")
		}
	}
}

func TestAnEmailCodeIsSpentTheFirstTimeItWorks(t *testing.T) {
	fake := newFakeRelay(t)
	ts, st := newTestServer(t, withMail(fake))
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	client, sent := requestEmailCode(t, ts, "user@nabuxai.com")
	sent.Body.Close()
	code := fake.lastCode(t)

	first := verifyEmailCode(t, client, ts, "user@nabuxai.com", code)
	first.Body.Close()
	if first.StatusCode != http.StatusFound {
		t.Fatalf("the first use answered %d, want a redirect", first.StatusCode)
	}

	// Anyone else who read the message — a shared inbox, a notification preview,
	// a forwarded thread — gets nothing from it.
	second := &http.Client{
		Jar:           &cookieJar{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	replay := verifyEmailCode(t, second, ts, "user@nabuxai.com", code)
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

func TestTheEmailCodeOfferIsAbsentWhenNoRelayIsConfigured(t *testing.T) {
	// The same rule an external provider follows: an offer that cannot send a
	// code would report one as sent, which is worse than no offer at all.
	fake := newFakeRelay(t)
	ts, _ := newTestServer(t) // no mail configured at all

	step := postLogin(t, ts.URL+"/login", url.Values{"identifier": {"someone@nabuxai.com"}})
	defer step.Body.Close()
	if body := readBody(t, step); strings.Contains(body, `action="/login/email"`) {
		t.Fatal("a deployment with no relay is still offering the email code")
	}

	resp, err := http.PostForm(ts.URL+"/login/email", url.Values{"email": {"someone@nabuxai.com"}})
	if err != nil {
		t.Fatalf("post email: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404 for a door this deployment cannot open", resp.StatusCode)
	}
	if fake.count() != 0 {
		t.Fatal("a deployment with no relay still called one")
	}
}

func TestThePasswordStepOffersTheCodeByEmail(t *testing.T) {
	// The trigger: an address typed into the one box leads to the password step,
	// and that step is where the code is offered. The address is never asked
	// twice.
	fake := newFakeRelay(t)
	ts, st := newTestServer(t, withMail(fake))
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	step := postLogin(t, ts.URL+"/login", url.Values{"identifier": {"user@nabuxai.com"}})
	defer step.Body.Close()
	body := readBody(t, step)
	if !strings.Contains(body, `action="/login/email"`) {
		t.Fatalf("the password step does not offer the code: %s", truncate(body))
	}
	if !strings.Contains(body, `value="user@nabuxai.com"`) {
		t.Fatalf("the offer does not carry the address already typed: %s", truncate(body))
	}
}

func TestAClosedDeploymentWillNotSayWhichAddressesHaveAccounts(t *testing.T) {
	fake := newFakeRelay(t)
	ts, st := newTestServer(t, withMail(fake), func(cfg *config.Config) { cfg.Server.AllowRegistration = false })
	// An account has to exist, or sign-up stays open regardless so a fresh
	// deployment can still be claimed.
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	strangerClient, strangerSent := requestEmailCode(t, ts, "stranger@nabuxai.com")
	defer strangerSent.Body.Close()
	strangerAsked := readBody(t, strangerSent)

	holderClient, holderSent := requestEmailCode(t, ts, "user@nabuxai.com")
	defer holderSent.Body.Close()
	holderAsked := readBody(t, holderSent)

	if strangerSent.StatusCode != holderSent.StatusCode {
		t.Fatalf("a stranger's address answered %d and the holder's %d — the difference is the answer to \"does this address have an account\"",
			strangerSent.StatusCode, holderSent.StatusCode)
	}
	for name, body := range map[string]string{"unknown address": strangerAsked, "known address": holderAsked} {
		if !strings.Contains(body, emailSentNotice) {
			t.Fatalf("asking for a code on an %s did not give the usual answer, which tells an outsider which addresses hold accounts", name)
		}
	}

	// But the stranger's address cost no message: there is nothing it could sign
	// into, and a real mail would be sent to tell somebody the address is
	// unknown.
	if fake.deliveredTo("stranger@nabuxai.com") {
		t.Fatal("a closed deployment spent a message on an address no account holds")
	}

	// And typing anything back is refused in the same words a wrong code gets.
	strangerTry := verifyEmailCode(t, strangerClient, ts, "stranger@nabuxai.com", "123456")
	defer strangerTry.Body.Close()
	holderTry := verifyEmailCode(t, holderClient, ts, "user@nabuxai.com", "000000")
	defer holderTry.Body.Close()

	if strangerTry.StatusCode != holderTry.StatusCode {
		t.Fatalf("verification answered %d for an unknown address and %d for a wrong code", strangerTry.StatusCode, holderTry.StatusCode)
	}
	for name, body := range map[string]string{"unknown address": readBody(t, strangerTry), "wrong code": readBody(t, holderTry)} {
		if !strings.Contains(body, emailRefusal) {
			t.Fatalf("%s was refused with something other than %q", name, emailRefusal)
		}
	}
	if count, err := st.CountUsers(context.Background()); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v, want no account created while sign-up is closed", count, err)
	}
}

func TestAVerifiedAddressNobodyHoldsBecomesAnAccount(t *testing.T) {
	fake := newFakeRelay(t)
	ts, st := newTestServer(t, withMail(fake))

	client, sent := requestEmailCode(t, ts, "new@nabuxai.com")
	sent.Body.Close()

	resp := verifyEmailCode(t, client, ts, "new@nabuxai.com", fake.lastCode(t))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want a redirect into the new account: %s", resp.StatusCode, truncate(readBody(t, resp)))
	}

	user, err := st.UserByEmail(context.Background(), "new@nabuxai.com")
	if err != nil {
		t.Fatalf("no account was created for the verified address: %v", err)
	}
	// The mailbox is the proof, so the claim is true from the first moment —
	// unlike a password-made account, whose address nothing has verified.
	if !user.EmailVerified {
		t.Fatal("the account was created from a proved address and does not say so")
	}
	// And the number column stays free rather than holding a placeholder.
	if user.Phone != "" {
		t.Fatalf("the account was given the number %q, which nobody proved", user.Phone)
	}
}

func TestAnEmailResendInsideTheCooldownDoesNotBuyMoreGuesses(t *testing.T) {
	fake := newFakeRelay(t)
	ts, st := newTestServer(t, withMail(fake))
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	client, first := requestEmailCode(t, ts, "user@nabuxai.com")
	first.Body.Close()
	code := fake.lastCode(t)

	// Spend one guess, then ask for another code straight away. If the resend
	// went through, the attempt counter would reset and the code could be
	// guessed at indefinitely.
	wrong := verifyEmailCode(t, client, ts, "user@nabuxai.com", otherEmailCode(t, code, 0))
	wrong.Body.Close()

	_, again := requestEmailCode(t, ts, "user@nabuxai.com")
	defer again.Body.Close()
	if again.StatusCode != http.StatusOK {
		t.Fatalf("a resend inside the cooldown answered %d, want the same 200 as a send", again.StatusCode)
	}
	if fake.count() != 1 {
		t.Fatalf("the relay was called %d times; a resend inside the cooldown must not send again", fake.count())
	}

	pending, err := st.EmailCode(context.Background(), "user@nabuxai.com")
	if err != nil {
		t.Fatalf("email code: %v", err)
	}
	if pending.Attempts != 1 {
		t.Fatalf("attempts = %d, want the wrong guess still counted after the resend", pending.Attempts)
	}
	// And the original code still works, because nothing replaced it.
	resp := verifyEmailCode(t, client, ts, "user@nabuxai.com", code)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want the original code to still sign in", resp.StatusCode)
	}
}

func TestAnEmailCodeDiesAfterTooManyWrongGuesses(t *testing.T) {
	fake := newFakeRelay(t)
	ts, st := newTestServer(t, withMail(fake))
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	client, sent := requestEmailCode(t, ts, "user@nabuxai.com")
	sent.Body.Close()
	code := fake.lastCode(t)

	for i := 0; i < store.MaxEmailCodeAttempts; i++ {
		resp := verifyEmailCode(t, client, ts, "user@nabuxai.com", otherEmailCode(t, code, i))
		resp.Body.Close()
	}

	// Six digits is a million possibilities, which is a lot for a person and
	// nothing for a script. The budget, not the length, is what protects it.
	resp := verifyEmailCode(t, client, ts, "user@nabuxai.com", code)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		t.Fatal("the right code still worked after its guess budget was spent")
	}
	if _, err := st.EmailCode(context.Background(), "user@nabuxai.com"); err == nil {
		t.Fatal("a code with no remaining guesses was left in the database")
	}
}
