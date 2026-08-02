# Security audit — 2026-08-02

Read against the claims in `CLAUDE.md` and `README.md` rather than assuming them. Two
findings, both fixed here with tests that fail on the old code. Everything else checked
held up.

## Verified as claimed

| Claim | Evidence |
|---|---|
| `redirect_uri` is exact-match, never prefix | `store.Client.AllowsRedirect` compares strings; nothing normalises or prefixes |
| No error redirects before the URI is verified | `parseAuthRequest` renders an error page for unknown clients and unregistered URIs, and only redirects afterwards |
| PKCE mandatory for public clients | enforced in `parseAuthRequest` |
| Refresh tokens rotate | `ConsumeRefreshToken` revokes as it reads — but see finding 1 |
| Scope cannot widen on refresh | `grantRefreshToken` rejects any scope not already held |
| Refresh token bound to its client | `rt.ClientID != client.ClientID` is refused |
| Deactivated accounts cannot refresh | `UserByID` + `IsActive` checked on every refresh |
| `email_verified` is never asserted falsely | derived from `email_verified_at IS NOT NULL`; pinned by a test |
| Client secrets compared in constant time | `subtle.ConstantTimeCompare` |
| Token endpoint throttled per client + IP | `authenticateClient` |
| Debits idempotent, overdraft-protected, signed amounts | `Adjust` with `ErrDuplicate` / `ErrInsufficientFunds` |

## Finding 1 · Refresh reuse was detected but nothing acted on it — fixed

Rotation was implemented correctly: a refresh token works exactly once. What was missing
was the reaction. When a rotated token came back a second time it was refused, and that was
all — the successor stayed live.

That leaves the attacker in the better position. Whoever redeems the stolen token *first*
receives the replacement and can keep rotating indefinitely; the victim's client is the one
that breaks. `CLAUDE.md` describes this as "the theft surfaces as the legitimate client
suddenly failing", but nothing surfaced anywhere an operator could see — no log line, no
revocation, no signal beyond a confused user.

RFC 9700 §4.14.2 asks for the whole refresh token family to be revoked on detected reuse,
precisely because a token presented twice proves that two parties hold it and the server
cannot tell which one is legitimate.

Proven by `internal/server/refresh_reuse_test.go`, which failed on the old code with the
successor token still returning a fresh access token after the replay was refused.

**Fix.** `oauth_refresh_tokens` gains a nullable `family_id`, set to the root token's hash
and carried forward by every rotation. `ConsumeRefreshToken` now distinguishes an unknown
hash from one we issued and already revoked; the latter is a replay, so the whole family is
revoked and `ErrReplayed` is returned. `grantRefreshToken` logs it with the client id and
source address — the signal the docs promised.

Two deliberate details:
- An *unknown* hash revokes nothing. Treating a guess as a replay would hand anyone a way
  to sign other people out by posting random strings.
- Rows written before the column existed have no family, so their descendants cannot be
  identified. Those fall back to revoking that user's tokens for that client: broader than
  necessary, wrong in the safe direction, and self-limiting as old tokens expire.

The schema change is an `ADD COLUMN IF NOT EXISTS`, matching the existing contract that
`schema.sql` runs on every boot and every statement is idempotent.

## Finding 2 · Public clients could use `plain` PKCE — fixed

`code_challenge_method=plain` was accepted from any client. For a public client that
reduces PKCE to nothing: with `plain` the verifier *is* the challenge, and the challenge is
sent in the authorize URL — through the address bar, browser history, `Referer` headers and
every proxy log along the way. An attacker able to steal the authorization code out of the
redirect can usually read that URL as well, which is the exact attacker PKCE exists to
defeat. RFC 8252 §8.1 requires S256 for native apps for this reason.

No public client is registered in `apps.yaml` today, so requiring S256 breaks nothing now
and closes the hole before the first SPA or mobile app is added.

**Fix.** Public clients must send `code_challenge_method=S256`. Confidential clients may
still use `plain` — their secret, not the challenge, is what protects the exchange — so
`/.well-known` continues to advertise both. Covered by `TestPublicClientMustUseS256`.

## Noted, not changed

When `code_challenge_method` is omitted but a challenge is present, the server assumes
`S256`. RFC 7636 §4.3 specifies `plain` as the default. The divergence is in the safe
direction and would only affect a client deliberately sending a plain challenge with no
method — which finding 2 now rejects for public clients anyway. Left as is, recorded so it
is a decision rather than an accident.

## How to run this

```bash
createdb nabuauth_test
NABUAUTH_TEST_DATABASE_URL="postgres://localhost/nabuauth_test?sslmode=disable" go test ./...
```

Integration tests skip silently without that variable, so a run that prints `ok` in
milliseconds has tested almost nothing — the suite takes a few seconds when the database is
actually reachable.
