# NabuAuth

One account for the Nabu products, and one wallet they spend from.

An OAuth 2.0 / OpenID Connect provider at `auth.nabuxai.com`. Go, standard
library plus a Postgres driver and bcrypt; a static binary on distroless.

## What it is for

Six products would otherwise each hold their own user table, their own password
reset, their own session cookie and their own idea of who is signed in. The
cost of that is not the code — it is that a person has six accounts, an
offboarding removes five of them, and nobody can answer "what is this user
allowed to do" in one place.

The wallet is here for the same reason: usage is metered by NabuGate and paid
for once, rather than per product.

## Who may sign in

`apps.yaml` is the source of truth and the README's list is checked against it
by a test, in both directions. Anything not registered there cannot sign
anybody in — including products the documentation once said could.

Secrets are never in that file. Each app names an environment variable
(`NABUAUTH_SECRET_<APP>`) and the value is read at boot, so the file stays
publishable and a rotation is not a commit.

## What is enforced

Probed against the running deployment, 2026-08-03:

- An unregistered `redirect_uri` is refused with `400` and **no redirect** — a
  code cannot be delivered to a host somebody else chose.
- An unknown `client_id` is refused.
- The token endpoint requires client authentication.
- `/oauth/jwks.json` serves public keys only, with no private component.

Covered by tests but **not exercised against the deployment**, because doing so
needs a real account and a real client secret:

- Refresh tokens rotate: one works exactly once, and reuse revokes the whole
  family — `TestRefreshReuseRevokesTheWholeFamily`. That is what makes a stolen
  token visible instead of silently useful.
- PKCE (`S256`, `plain`) is mandatory for public clients. All six registered
  apps are confidential today, so the rule is correct and unexercised in
  production as well as here.

## Scopes

Listed in `apps.yaml` with the sentence a user reads on the consent screen. An
app asking for a scope that is not listed is refused rather than granted a
default — a scope nobody wrote a sentence for is a permission nobody described
to the person granting it.

## Registration

`allow_registration: false` — an administrator creates accounts. The sign-up
form stays reachable while the database has no users at all, so a fresh
deployment can be claimed by the first person to arrive and then closes.

## Configuration

| variable | meaning |
|---|---|
| `NABUAUTH_ISSUER` | the public origin; it goes into every token and every discovery document |
| `NABUAUTH_SECRET_<APP>` | one per confidential app, named in `apps.yaml` |
| Postgres connection | users, sessions, consents, the ledger, and the RSA signing key |

The signing key is generated on first boot and stored in the database, so a
restart does not invalidate every token in circulation.

## What this does not do

- It does not hold provider credentials for anything — that is NabuSms for SMS
  and NabuGate for models.
- It does not decide what a user may do inside an application. It says who they
  are and what they consented to share.
