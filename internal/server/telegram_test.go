package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"nabuauth/internal/config"
	"nabuauth/internal/store"
)

const testBotToken = "123456789:AAtest-token-for-signing"

// signTelegram builds a tgAuthResult exactly as Telegram does: the profile as
// JSON with an HMAC of its sorted key=value lines, base64 encoded.
func signTelegram(t *testing.T, token string, fields map[string]any) string {
	t.Helper()
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("%s=%v", k, fields[k]))
	}
	secret := sha256.Sum256([]byte(token))
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte(strings.Join(lines, "\n")))
	signed := map[string]any{"hash": hex.EncodeToString(mac.Sum(nil))}
	for k, v := range fields {
		signed[k] = v
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func profileFields(id int64, at time.Time) map[string]any {
	return map[string]any{
		"id": id, "first_name": "Reza", "last_name": "Karimi", "username": "rezak",
		"photo_url": "https://t.me/i/userpic/320/rezak.jpg", "auth_date": at.Unix(),
	}
}

func TestVerifyTelegram(t *testing.T) {
	now := time.Now()
	good := signTelegram(t, testBotToken, profileFields(987654321, now))

	p, err := verifyTelegram(testBotToken, good, now)
	if err != nil {
		t.Fatalf("a correctly signed login was refused: %v", err)
	}
	if p.ID != 987654321 || p.displayName() != "Reza Karimi" || p.Username != "rezak" || !strings.HasPrefix(p.PhotoURL, "https://") {
		t.Errorf("profile = %+v", p)
	}

	if _, err := verifyTelegram("999:another-bot", good, now); err == nil {
		t.Error("a login signed for another bot was accepted")
	}

	// Change one field after signing: the id an attacker would most like to
	// swap for someone else's.
	raw, _ := base64.StdEncoding.DecodeString(good)
	tampered := base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), "987654321", "111111111", 1)))
	if _, err := verifyTelegram(testBotToken, tampered, now); err == nil {
		t.Error("a login with an altered id was accepted")
	}

	old := signTelegram(t, testBotToken, profileFields(987654321, now.Add(-time.Hour)))
	if _, err := verifyTelegram(testBotToken, old, now); err == nil {
		t.Error("an hour-old login was accepted; a captured one could be replayed")
	}

	if _, err := verifyTelegram(testBotToken, "not base64 at all!", now); err == nil {
		t.Error("garbage was accepted")
	}
}

func telegramServer(t *testing.T, tweaks ...func(*config.Config)) (*httptest.Server, *store.Store, func() *http.Client) {
	t.Helper()
	t.Setenv("TEST_TELEGRAM_BOT_TOKEN", testBotToken)
	ts, st := newTestServer(t, append([]func(*config.Config){func(c *config.Config) {
		c.Telegram.BotTokenEnv = "TEST_TELEGRAM_BOT_TOKEN"
	}}, tweaks...)...)
	newClient := func() *http.Client {
		return &http.Client{Jar: &cookieJar{}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return ts, st, newClient
}

// telegramRoundTrip leaves for Telegram through start (a path on this server),
// comes back with result, and posts it the way telegram.js would.
func telegramRoundTrip(t *testing.T, ts *httptest.Server, client *http.Client, start, method string, form url.Values, result string) *http.Response {
	t.Helper()
	var resp *http.Response
	var err error
	if method == http.MethodPost {
		resp, err = client.PostForm(ts.URL+start, form)
	} else {
		resp, err = client.Get(ts.URL + start)
	}
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Host != "oauth.telegram.org" || loc.Query().Get("bot_id") != "123456789" {
		t.Fatalf("start answered %d to %q, want Telegram's login for bot 123456789", resp.StatusCode, resp.Header.Get("Location"))
	}
	if rt := loc.Query().Get("return_to"); rt != "http://nabuauth.test/login/telegram/callback" {
		t.Fatalf("return_to = %q", rt)
	}

	resp, err = client.Get(ts.URL + "/login/telegram/callback")
	if err != nil {
		t.Fatalf("return page: %v", err)
	}
	nonce := extractInput(readBody(t, resp), "nonce")
	resp.Body.Close()
	if nonce == "" {
		t.Fatal("the return page carries no nonce")
	}

	resp, err = client.PostForm(ts.URL+"/login/telegram/callback", url.Values{"nonce": {nonce}, "result": {result}})
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	return resp
}

func TestTelegramSignInCreatesThenReusesTheAccount(t *testing.T) {
	ts, st, newClient := telegramServer(t)
	result := signTelegram(t, testBotToken, profileFields(555000111, time.Now()))

	first := telegramRoundTrip(t, ts, newClient(), "/login/telegram?next=%2Fdashboard", http.MethodGet, nil, result)
	first.Body.Close()
	if first.StatusCode != http.StatusFound || first.Header.Get("Location") != "/dashboard" {
		t.Fatalf("first Telegram sign-in answered %d to %q", first.StatusCode, first.Header.Get("Location"))
	}

	second := telegramRoundTrip(t, ts, newClient(), "/login/telegram", http.MethodGet, nil, signTelegram(t, testBotToken, profileFields(555000111, time.Now())))
	second.Body.Close()
	if second.StatusCode != http.StatusFound {
		t.Fatalf("second sign-in answered %d", second.StatusCode)
	}

	var count int
	var name string
	var pwSet bool
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT count(*), max(name), bool_or(password_set_at IS NOT NULL) FROM users WHERE telegram_id = 555000111`).Scan(&count, &name, &pwSet); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("%d accounts for one Telegram account, want 1", count)
	}
	if name != "Reza Karimi" || pwSet {
		t.Errorf("account name=%q passwordSet=%v, want the Telegram name and no known password", name, pwSet)
	}
}

func TestTelegramCallbackNeedsThisBrowsersNonce(t *testing.T) {
	ts, _, newClient := telegramServer(t)
	result := signTelegram(t, testBotToken, profileFields(555000222, time.Now()))

	// An attacker's page posting their own signed login into a victim's
	// browser: the victim never started a flow, so there is no nonce to match.
	victim := newClient()
	resp, err := victim.PostForm(ts.URL+"/login/telegram/callback", url.Values{"nonce": {"guessed"}, "result": {result}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		t.Fatal("a callback with no flow of this browser's signed someone in")
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("a forged callback started a session")
		}
	}
}

func TestTelegramLinkAndUnlink(t *testing.T) {
	ts, st, _ := telegramServer(t)
	seedUser(t, st, "owner@nabuxai.com", "owner-password-1")
	client := signIn(t, ts, "owner@nabuxai.com", "owner-password-1")

	csrf := func() string {
		resp, err := client.Get(ts.URL + "/dashboard")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return extractInput(readBody(t, resp), "csrf")
	}

	resp := telegramRoundTrip(t, ts, client, "/dashboard/telegram/link", http.MethodPost, url.Values{"csrf": {csrf()}},
		signTelegram(t, testBotToken, profileFields(555000333, time.Now())))
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "telegram=linked") {
		t.Fatalf("link answered %d to %q, want linked", resp.StatusCode, loc)
	}

	// Now Telegram signs in to the same account, not a new one.
	other := &http.Client{Jar: &cookieJar{}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp = telegramRoundTrip(t, ts, other, "/login/telegram", http.MethodGet, nil, signTelegram(t, testBotToken, profileFields(555000333, time.Now())))
	resp.Body.Close()
	var n int
	if err := st.DB().QueryRowContext(context.Background(), `SELECT count(*) FROM users`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("signing in with the linked Telegram made %d accounts, want the one it is linked to", n)
	}

	resp, err := client.PostForm(ts.URL+"/dashboard/telegram/unlink", url.Values{"csrf": {csrf()}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "telegram=unlinked") {
		t.Fatalf("unlink answered %q, want unlinked", loc)
	}
}

// An account made by Telegram has no other way in; disconnecting Telegram from
// it would lock its owner out for good.
func TestTelegramUnlinkRefusesTheLastWayIn(t *testing.T) {
	ts, _, newClient := telegramServer(t)
	client := newClient()
	resp := telegramRoundTrip(t, ts, client, "/login/telegram", http.MethodGet, nil, signTelegram(t, testBotToken, profileFields(555000444, time.Now())))
	resp.Body.Close()

	page, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	token := extractInput(readBody(t, page), "csrf")
	page.Body.Close()

	resp, err = client.PostForm(ts.URL+"/dashboard/telegram/unlink", url.Values{"csrf": {token}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "telegram=last") {
		t.Fatalf("unlink of the only way in answered %q, want last", loc)
	}
}
