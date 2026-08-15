package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"nabuauth/internal/config"
)

// The door asks one question at a time: one box that takes an address, a number
// or a handle, and a second step that asks for the proof which fits what was
// typed. These hold that shape, and hold the second step to the same silence
// the first one keeps about which accounts exist.

func TestTheFirstStepAsksForTheProofThatFitsAnAddress(t *testing.T) {
	ts, _ := newTestServer(t)

	resp := postLogin(t, ts.URL+"/login", url.Values{"identifier": {"someone@nabuxai.com"}})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want the password step", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, `action="/login/password"`) || !strings.Contains(body, `name="password"`) {
		t.Fatalf("the second step does not ask for a password: %s", truncate(body))
	}
	if !strings.Contains(body, "someone@nabuxai.com") {
		t.Fatalf("the second step does not say which account it is asking about: %s", truncate(body))
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("typing an address alone started a session")
		}
	}
}

func TestTheSecondStepSignsTheAccountIn(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	resp := postLogin(t, ts.URL+"/login/password", url.Values{
		"identifier": {"user@nabuxai.com"},
		"password":   {"correct-horse-battery"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/dashboard" {
		t.Fatalf("got %d to %q, want a redirect into the account", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestAUsernameIsAWayIn(t *testing.T) {
	ts, st := newTestServer(t)
	user := seedUser(t, st, "hussein@nabuxai.com", "correct-horse-battery")
	if err := st.SetUsername(context.Background(), user.ID, "Hussein"); err != nil {
		t.Fatalf("set username: %v", err)
	}

	// Typed in the case the person happens to use. The index is on lower(), so
	// the lookup has to be too or the handle answers to one spelling only.
	first := postLogin(t, ts.URL+"/login", url.Values{"identifier": {"HUSSEIN"}})
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want the password step", first.StatusCode)
	}

	resp := postLogin(t, ts.URL+"/login/password", url.Values{
		"identifier": {"hussein"},
		"password":   {"correct-horse-battery"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/dashboard" {
		t.Fatalf("got %d to %q, want a redirect into the account", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestAHandleNobodyHoldsIsNeverASignUp(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	resp := postLogin(t, ts.URL+"/login/password", url.Values{
		"identifier": {"nobody"},
		"password":   {"a-long-enough-password"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
	// A username on its own has no address and no number behind it, so an
	// account made from one could never be reached again.
	if count, err := st.CountUsers(context.Background()); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v, want the original account only", count, err)
	}
}

func TestSomethingThatIsNoneOfTheThreeIsRefusedAtTheFirstStep(t *testing.T) {
	ts, _ := newTestServer(t)

	resp := postLogin(t, ts.URL+"/login", url.Values{"identifier": {"not an identifier!"}})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.StatusCode)
	}
	if body := readBody(t, resp); !strings.Contains(body, "not an email address, a phone number or a username") {
		t.Fatalf("the page does not say what the box takes: %s", truncate(body))
	}
}

func TestTheFormShowsOneBoxAndNoChoiceOfDoor(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	defer resp.Body.Close()

	body := readBody(t, resp)
	if !strings.Contains(body, `name="identifier"`) {
		t.Fatalf("the form has no single identifier box: %s", truncate(body))
	}
	// The password field belongs to the second step. On the first one it would
	// be the same "which kind of account am I" question in a new arrangement.
	if strings.Contains(body, `name="password"`) {
		t.Fatalf("the first step still asks for a password: %s", truncate(body))
	}
}

func TestAFormThatPostsBothFieldsStillWorksInOneStep(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	// Every app in the ecosystem posted email+password here before this page had
	// two steps, and a browser that fills both should not be sent back a step.
	resp := postLogin(t, ts.URL+"/login", url.Values{
		"email":    {"user@nabuxai.com"},
		"password": {"correct-horse-battery"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/dashboard" {
		t.Fatalf("got %d to %q, want a redirect into the account", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestTheTwoStepPathWillNotSayWhichEmailsHaveAccounts(t *testing.T) {
	ts, st := newTestServer(t, func(cfg *config.Config) { cfg.Server.AllowRegistration = false })
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	// The first step never looks the account up, so both addresses get the same
	// page. The second step is where the refusal happens, and it has to be the
	// same refusal for an address nobody holds and an address with the wrong
	// password — the property the one-step form held, in the shape it has now.
	for _, address := range []string{"stranger@nabuxai.com", "user@nabuxai.com"} {
		step1 := postLogin(t, ts.URL+"/login", url.Values{"identifier": {address}})
		if step1.StatusCode != http.StatusOK {
			t.Fatalf("%s: the first step answered %d, want 200 for every address", address, step1.StatusCode)
		}
		step1.Body.Close()
	}

	unknown := postLogin(t, ts.URL+"/login/password", url.Values{
		"identifier": {"stranger@nabuxai.com"}, "password": {"a-long-enough-password"},
	})
	defer unknown.Body.Close()
	wrong := postLogin(t, ts.URL+"/login/password", url.Values{
		"identifier": {"user@nabuxai.com"}, "password": {"not-the-password"},
	})
	defer wrong.Body.Close()

	if unknown.StatusCode != wrong.StatusCode {
		t.Fatalf("an unknown address answered %d and a wrong password %d — the difference is the answer to \"does this account exist\"", unknown.StatusCode, wrong.StatusCode)
	}
	const refusal = "Wrong email or password."
	for name, body := range map[string]string{"unknown address": readBody(t, unknown), "wrong password": readBody(t, wrong)} {
		if !strings.Contains(body, refusal) {
			t.Fatalf("%s was refused with something other than %q: %s", name, refusal, truncate(body))
		}
	}
	if count, err := st.CountUsers(context.Background()); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v, want no account created while sign-up is closed", count, err)
	}
}

func TestTheSignUpUrlIsTheSameDoor(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")

	// POST /register has always been an alias for the sign-in form, and stays
	// one: same handler, same two steps, no way in that /login does not have.
	first := postLogin(t, ts.URL+"/register", url.Values{"identifier": {"user@nabuxai.com"}})
	defer first.Body.Close()

	if first.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want the password step", first.StatusCode)
	}
	if body := readBody(t, first); !strings.Contains(body, `action="/login/password"`) {
		t.Fatalf("the sign-up URL does not lead to the same second step: %s", truncate(body))
	}
	for _, c := range first.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("posting an address to /register started a session")
		}
	}
}

func TestClassifyingWhatWasTyped(t *testing.T) {
	cases := []struct {
		typed string
		kind  identifierKind
		value string
	}{
		{"Someone@Nabuxai.com", kindEmail, "someone@nabuxai.com"},
		{"09121234567", kindPhone, "+989121234567"},
		{"+968 9123 4567", kindPhone, "+96891234567"},
		{"۰۹۱۲۱۲۳۴۵۶۷", kindPhone, "+989121234567"},
		{"Hussein", kindUsername, "hussein"},
		{"nabu.desk-01", kindUsername, "nabu.desk-01"},
		{"", kindUnknown, ""},
		{"not an identifier!", kindUnknown, "not an identifier!"},
		{"broken@", kindUnknown, "broken@"},
	}

	for _, c := range cases {
		kind, value := classifyIdentifier(c.typed, "98")
		if kind != c.kind || value != c.value {
			t.Errorf("%q became (%q, %q), want (%q, %q)", c.typed, kind, value, c.kind, c.value)
		}
	}
}
