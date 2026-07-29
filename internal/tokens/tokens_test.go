package tokens

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	kid, pem, err := GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kr, err := NewKeyring([]struct{ KID, PEM string }{{kid, pem}})
	if err != nil {
		t.Fatalf("new keyring: %v", err)
	}
	return kr
}

func TestSignVerifyRoundTrip(t *testing.T) {
	kr := testKeyring(t)
	now := time.Now()
	in := Claims{
		Issuer:    "https://auth.nabuxai.com",
		Subject:   "42",
		Audience:  "nabudesk",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		TokenType: "access",
		Scope:     "openid profile wallet",
	}
	token, err := kr.Sign(in)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := kr.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if out.Subject != in.Subject || out.Audience != in.Audience || out.Scope != in.Scope {
		t.Fatalf("claims round-tripped wrong: %+v", out)
	}
	if !out.HasScope("wallet") || out.HasScope("wallet.write") {
		t.Fatalf("scope check wrong for %q", out.Scope)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	kr := testKeyring(t)
	token, err := kr.Sign(Claims{Subject: "1", ExpiresAt: time.Now().Add(-2 * time.Hour).Unix()})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := kr.Verify(token); err == nil {
		t.Fatal("expired token was accepted")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	kr := testKeyring(t)
	token, err := kr.Sign(Claims{Subject: "1", ExpiresAt: time.Now().Add(time.Hour).Unix(), Scope: "profile"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parts := strings.Split(token, ".")
	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1","scope":"wallet.write","exp":9999999999}`))
	if _, err := kr.Verify(parts[0] + "." + forged + "." + parts[2]); err == nil {
		t.Fatal("a re-signed payload with escalated scope was accepted")
	}
}

// A token whose header claims "none" must never be accepted; historically this
// is the single most exploited JWT bug.
func TestVerifyRejectsAlgNone(t *testing.T) {
	kr := testKeyring(t)
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := enc.EncodeToString([]byte(`{"sub":"1","exp":9999999999}`))
	if _, err := kr.Verify(header + "." + payload + "."); err == nil {
		t.Fatal("alg=none token was accepted")
	}
}

func TestVerifyRejectsForeignKey(t *testing.T) {
	signer := testKeyring(t)
	other := testKeyring(t)
	token, err := signer.Sign(Claims{Subject: "1", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := other.Verify(token); err == nil {
		t.Fatal("a token signed by another server was accepted")
	}
}

func TestJWKSExposesSigningKey(t *testing.T) {
	kr := testKeyring(t)
	jwks := kr.JWKS()
	keys, ok := jwks["keys"].([]map[string]string)
	if !ok || len(keys) != 1 {
		t.Fatalf("unexpected jwks shape: %#v", jwks)
	}
	k := keys[0]
	if k["kid"] != kr.SigningKID() || k["alg"] != "RS256" || k["kty"] != "RSA" {
		t.Fatalf("unexpected key: %#v", k)
	}
	// The exponent is almost always 65537, which is AQAB in base64url. A wrong
	// encoding here breaks every downstream verifier while everything else looks
	// fine locally.
	if k["e"] != "AQAB" {
		t.Fatalf("exponent encoded as %q, want AQAB", k["e"])
	}
	if n, err := base64.RawURLEncoding.DecodeString(k["n"]); err != nil || len(n) != 256 {
		t.Fatalf("modulus is %d bytes (err %v), want 256", len(n), err)
	}
}

func TestVerifyPKCE(t *testing.T) {
	// Values from RFC 7636 appendix B.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	cases := []struct {
		name      string
		challenge string
		method    string
		verifier  string
		want      bool
	}{
		{"s256 match", challenge, "S256", verifier, true},
		{"s256 mismatch", challenge, "S256", "wrong-verifier", false},
		{"default method is s256", challenge, "", verifier, true},
		{"plain match", verifier, "plain", verifier, true},
		{"plain mismatch", verifier, "plain", "other", false},
		{"unknown method", challenge, "MD5", verifier, false},
		{"no challenge, no verifier", "", "", "", true},
		{"challenge set, verifier missing", challenge, "S256", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := VerifyPKCE(tc.challenge, tc.method, tc.verifier); got != tc.want {
				t.Fatalf("VerifyPKCE = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOpaqueTokensAreUniqueAndHashed(t *testing.T) {
	a, hashA, err := NewOpaque()
	if err != nil {
		t.Fatalf("new opaque: %v", err)
	}
	b, hashB, err := NewOpaque()
	if err != nil {
		t.Fatalf("new opaque: %v", err)
	}
	if a == b || hashA == hashB {
		t.Fatal("two opaque tokens collided")
	}
	if hashA == a {
		t.Fatal("the stored hash is the token itself")
	}
	if HashOpaque(a) != hashA {
		t.Fatal("HashOpaque is not stable")
	}
}
