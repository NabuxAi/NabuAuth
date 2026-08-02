package server

import (
	"net/url"
	"testing"
)

// Refresh rotation is implemented: ConsumeRefreshToken revokes a token as it
// hands it over, so the same token never works twice. What is missing is the
// half that makes rotation useful — reacting when the refusal happens.
//
// The docs describe the current behaviour as "the theft surfaces as the
// legitimate client suddenly failing". It does not surface anywhere the
// operator can see, and more importantly the thief is unaffected: whoever
// redeemed the stolen token first holds a live replacement, and the victim's
// failed refresh does nothing to it.
//
// RFC 9700 §4.14.2 calls for revoking the whole refresh token family when a
// reuse is detected, precisely because a rotated token that is presented twice
// is proof that one of the two holders should not have it, and the server
// cannot tell which.
func TestRefreshReuseRevokesTheWholeFamily(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")

	code := grantCode(t, ts, client, "testapp", "http://app.test/callback", "openid profile", "", "")
	tok := postForm(t, ts, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://app.test/callback"},
		"client_id":     {"testapp"},
		"client_secret": {"test-confidential-secret"},
	})
	stolen, _ := tok["refresh_token"].(string)
	if stolen == "" {
		t.Fatalf("no refresh token in %v", tok)
	}

	refresh := func(rt string) map[string]any {
		return postForm(t, ts, "/oauth/token", url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {rt},
			"client_id":     {"testapp"},
			"client_secret": {"test-confidential-secret"},
		})
	}

	// The thief gets there first and receives a replacement.
	stolenUse := refresh(stolen)
	successor, _ := stolenUse["refresh_token"].(string)
	if successor == "" {
		t.Fatalf("rotation did not return a replacement token: %v", stolenUse)
	}

	// The legitimate client then presents the same token. Refusing it is
	// correct, and already works — this is the detection moment.
	reuse := refresh(stolen)
	if reuse["error"] != "invalid_grant" {
		t.Fatalf("a reused refresh token returned %v, want invalid_grant", reuse)
	}

	// Having detected the reuse, the server should have revoked the successor
	// too. Otherwise the only party still holding a working token is the thief,
	// and the detection changed nothing.
	afterDetection := refresh(successor)
	if afterDetection["error"] != "invalid_grant" {
		t.Fatalf("the successor token still works after a reuse was detected: %v\n"+
			"whoever redeemed the stolen token keeps access, and the victim's failed "+
			"refresh is the only trace", afterDetection)
	}
}

// A public client has no secret, so PKCE is the whole defence. With method
// `plain` the verifier equals the challenge, and the challenge is sent in the
// authorize URL — so anyone positioned to steal the authorization code from the
// redirect can usually read the verifier from the same place. `/.well-known`
// still advertises `plain` because confidential clients may use it: their
// secret is what protects their exchange.
func TestPublicClientMustUseS256(t *testing.T) {
	ts, st := newTestServer(t)
	seedUser(t, st, "user@nabuxai.com", "correct-horse-battery")
	client := signIn(t, ts, "user@nabuxai.com", "correct-horse-battery")

	q := url.Values{
		"client_id":             {"spa"},
		"redirect_uri":          {"http://spa.test/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"code_challenge":        {"a-verifier-in-the-clear"},
		"code_challenge_method": {"plain"},
	}
	resp, err := client.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()

	location, err := resp.Location()
	if err != nil {
		t.Fatalf("expected an error redirect, got none: %v", err)
	}
	if got := location.Query().Get("error"); got != "invalid_request" {
		t.Fatalf("plain PKCE from a public client returned error=%q, want invalid_request", got)
	}
}
