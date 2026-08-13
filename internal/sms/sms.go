// Package sms carries one-time codes to the NabuSms gateway and turns whatever
// a visitor typed into the one number format the gateway reads.
//
// Two things about that gateway shape this package and are easy to get wrong.
// It answers HTTP 200 even when every message failed — the outcome is per
// recipient, inside the body — so a caller that checks only the status code
// tells the visitor a code is on its way when nothing was sent. And its
// one-time-code route is declared for Iranian numbers only, refusing anything
// else before a provider is tried, so a foreign number has to be handed to the
// international route instead, which carries plain text because the provider
// behind it has no message templates.
package sms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"nabuauth/internal/config"
)

var (
	digitsOnly = regexp.MustCompile(`[^0-9]`)

	// Numbers are typed on Persian and Arabic keyboards as often as on Latin
	// ones, and a number that arrives in eastern digits is a number the gateway
	// cannot read.
	easternDigits = strings.NewReplacer(
		"۰", "0", "۱", "1", "۲", "2", "۳", "3", "۴", "4",
		"۵", "5", "۶", "6", "۷", "7", "۸", "8", "۹", "9",
		"٠", "0", "١", "1", "٢", "2", "٣", "3", "٤", "4",
		"٥", "5", "٦", "6", "٧", "7", "٨", "8", "٩", "9",
	)
)

// dialRules is what a calling code's own numbers look like, for the codes this
// deployment routes. It is the same table App\Support\PhoneNumber holds on the
// NabuDesk side, and it exists because two guesses cannot be made safely
// without it.
//
// trunk is the prefix a local caller dials and E.164 drops. It is '0' across
// most of the world but empty in the +1 plan and in the Gulf, and '8' in the +7
// plan, so stripping a leading zero everywhere mangles a North American number
// and leaving an '8' on a Russian one keeps a digit that is not part of it.
//
// nsn is the lengths a national number may have. Without it there is no way to
// tell a number that carries its own calling code from one that merely starts
// with the same digits — an Omani 96812345 is a whole valid number, not +968
// followed by 12345.
var dialRules = map[string]struct {
	trunk string
	nsn   []int
}{
	"1":   {"", []int{10}},
	"7":   {"8", []int{10}},
	"39":  {"", nil},
	"44":  {"0", []int{9, 10}},
	"49":  {"0", nil},
	"90":  {"0", []int{10}},
	"91":  {"0", []int{10}},
	"92":  {"0", []int{10}},
	"98":  {"0", []int{10}},
	"961": {"0", nil},
	"964": {"0", nil},
	"965": {"", []int{8}},
	"966": {"0", []int{9}},
	"968": {"", []int{8}},
	"971": {"0", []int{8, 9}},
	"973": {"", []int{8}},
	"974": {"", []int{8}},
}

func trunkFor(dial string) string {
	if rule, ok := dialRules[dial]; ok {
		return rule.trunk
	}
	return "0"
}

func hasLength(lengths []int, n int) bool {
	for _, l := range lengths {
		if l == n {
			return true
		}
	}
	return false
}

// carriesOwnDial reports whether a number typed without a '+' has nonetheless
// been written with its own calling code in front.
//
// This is only ever answerable where the national length is known. Where it is
// not, the answer is no and the visitor has to write '+' or '00' to mean it:
// guessing wrong here does not produce a wrong-looking number, it produces a
// plausible one addressed to nobody, and the code goes off into the void with
// the gateway reporting success.
func carriesOwnDial(s, dial string) bool {
	if !strings.HasPrefix(s, dial) || len(s) <= len(dial) {
		return false
	}
	rule, ok := dialRules[dial]
	if !ok || len(rule.nsn) == 0 {
		return false
	}
	if hasLength(rule.nsn, len(s)) {
		// The whole thing is already a complete national number, so the leading
		// digits that match the calling code are part of it — an Omani 96812345
		// is a subscriber's number, not +968 with five digits after it.
		return false
	}
	return hasLength(rule.nsn, len(s)-len(dial))
}

// Normalise turns whatever a number arrived as into E.164 with a leading '+',
// which is the single canonical form written to users.phone and keyed in
// phone_codes. It reports false when nothing usable is left.
//
// dial is the calling code of the country the visitor selected, with no '+'.
// Without it "09121234567" means nothing in particular.
func Normalise(raw, dial string) (string, bool) {
	s := easternDigits.Replace(strings.TrimSpace(raw))

	// Whether the number was written international has to be decided *before*
	// the punctuation is stripped: "+968…" and "968…" are identical afterwards,
	// and assuming the selected country for the second turns an Omani mobile
	// into a nonexistent Iranian one.
	international := strings.HasPrefix(s, "+")

	s = digitsOnly.ReplaceAllString(s, "")
	dial = digitsOnly.ReplaceAllString(dial, "")

	trunk := trunkFor(dial)

	switch {
	case s == "":
		return "", false
	// 0098… — the international prefix typed the old way.
	case strings.HasPrefix(s, "00"):
		s = strings.TrimPrefix(s, "00")
	case international:
		// Already E.164.
	case dial == "":
		// Nothing to prefix with, so take it as written rather than guessing.
	case carriesOwnDial(s, dial):
		// Already carries its own calling code.
	case trunk != "" && strings.HasPrefix(s, trunk) && len(s) > len(trunk):
		// National format, written with the trunk prefix E.164 drops.
		s = dial + strings.TrimPrefix(s, trunk)
	default:
		s = dial + s
	}

	// Short enough to be a typo or a landline fragment rather than a mobile
	// nobody would receive a code on, and long enough to be nothing at all.
	if len(s) < 8 || len(s) > 15 {
		return "", false
	}
	return "+" + s, true
}

// Iranian reports whether an E.164 number belongs to Iran, which is the one
// question that decides which gateway route can carry the message.
func Iranian(e164 string) bool { return strings.HasPrefix(e164, "+98") }

// Client sends one-time codes through NabuSms.
type Client struct {
	cfg  config.Sms
	http *http.Client
}

// New builds a client for a configured gateway.
func New(cfg config.Sms) *Client {
	return &Client{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}}
}

type sendRequest struct {
	To       []string          `json:"to"`
	Text     string            `json:"text,omitempty"`
	Route    string            `json:"route"`
	Template string            `json:"template,omitempty"`
	Params   map[string]string `json:"params,omitempty"`
	Country  string            `json:"default_country"`
}

type sendResponse struct {
	Sent     int `json:"sent"`
	Failed   int `json:"failed"`
	Messages []struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	} `json:"messages"`
}

// SendCode delivers one code to one number. It returns an error unless the
// gateway says the message actually went out.
func (c *Client) SendCode(ctx context.Context, e164, code string) error {
	body := sendRequest{To: []string{e164}, Country: c.cfg.DefaultCountry}
	if Iranian(e164) {
		// The domestic route is pattern-only: Iranian numbers on the
		// do-not-disturb list never receive free text, so a code sent as plain
		// text silently reaches nobody.
		body.Route = c.cfg.Route
		body.Template = c.cfg.Template
		// Both names, because the providers behind the one route do not agree
		// on what the placeholder is called. sms.ir reads the configured name;
		// Kavenegar's lookup endpoint copies only token/token2/token3 and
		// refuses the message outright — "kavenegar templates need at least a
		// `token` parameter" — when token is missing. Kavenegar is last on the
		// route, so sending one name alone means every send works until the
		// providers ahead of it are rate-limited or down, and then no phone
		// sign-in works at all. NabuDesk's path already sends both; this is the
		// same gateway, so it should not disagree with it.
		body.Params = map[string]string{"token": code}
		if c.cfg.CodeParam != "" {
			body.Params[c.cfg.CodeParam] = code
		}
	} else {
		// The international provider has no patterns, and the domestic route
		// would refuse the number outright.
		body.Route = c.cfg.InternationalRoute
		body.Text = strings.ReplaceAll(c.cfg.Text, "{code}", code)
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/v1/messages", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Key())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sms gateway returned %s", resp.Status)
	}

	// The status code only says the gateway accepted the request. Whether a
	// message went anywhere is in the body, and reading the code alone is
	// exactly how a form comes to claim a code was sent when none was.
	var out sendResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("sms gateway returned an unreadable body: %w", err)
	}
	if out.Sent < 1 {
		if len(out.Messages) > 0 && out.Messages[0].Error != "" {
			return errors.New("sms gateway did not send the message: " + out.Messages[0].Error)
		}
		return errors.New("sms gateway did not send the message")
	}
	return nil
}
