# NabuAuth — central single sign-on for the Nabu ecosystem

NabuAuth is the OAuth 2.0 / OpenID Connect identity provider every Nabu product
signs users in with, plus the shared prepaid wallet those products spend from.
One account at `auth.nabuxai.com` signs a user in to every application
registered in `apps.yaml`. That list, and nothing else, is what works today:

<!-- registered-apps:begin -->
- NabuGate AI
- NabuDesk
- NabuGen
- NabuVoice
- NabuWrite
- ReelMind
<!-- registered-apps:end -->

The markers are not decoration: a test reads the list between them and compares
it to `apps.yaml`, because this sentence used to name NabuSu, NabuWatch and the
Nabux store — none of which has ever contained a single reference to NabuAuth.
A README that lists an integration nobody built is worse than one that lists
none, because it is the thing someone reads before deciding not to build it.

Written in Go with the standard library, a Postgres driver and bcrypt. It builds
to a single static binary and ships as a distroless image.

## What it does

- **Authorization code flow with PKCE** — `S256` and `plain`, mandatory for
  public clients (SPAs, mobile).
- **Refresh tokens with rotation** — a refresh token works exactly once; reusing
  one is refused, which is what makes a stolen token show up.
- **Client credentials** — service-to-service tokens, used by NabuGate to meter
  usage against a wallet.
- **RS256 access and identity tokens**, published at `/oauth/jwks.json` so apps
  verify offline without calling back.
- **Consent, remembered per app**, revocable from the account dashboard.
- **Prepaid wallet** with a signed ledger, idempotent debits and overdraft
  protection.
- **One sign-in form** — email and password in a single step. An email no
  account uses is created from the same submission where the deployment allows
  it; there is no separate sign-up form to pick first.
- **External sign-in methods** — any OIDC provider (Google, Microsoft, an
  enterprise IdP) configured in `login_methods`, matched to an account by the
  verified email it asserts.
- **Phone sign-in** — a number, a country, and a one-time code by SMS, on the
  same form. Offered only where an SMS gateway is configured, because a field
  that cannot send a code would report one as sent.
- **Account UI**: sign in, app launcher, wallet history.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | Discovery document |
| `GET /oauth/jwks.json` | Public signing keys |
| `GET /oauth/authorize` | Login and consent screen |
| `GET /login` | The one sign-in form: signs in, or creates the account |
| `POST /login/phone` | Send a one-time code to a phone number |
| `POST /login/phone/verify` | Type the code back and sign in |
| `GET /login/{provider}` | Start an external sign-in method |
| `GET /login/{provider}/callback` | Finish one |
| `POST /oauth/token` | `authorization_code`, `refresh_token`, `client_credentials` |
| `POST /oauth/introspect` | RFC 7662 token introspection |
| `POST /oauth/revoke` | RFC 7009 revocation |
| `GET /oauth/userinfo` | OIDC profile claims |
| `GET /api/v1/user` | Same profile, the name the Nabu SDKs call |
| `GET /api/v1/apps` | Ecosystem app registry |
| `GET /api/v1/wallet/balance` | Current balance |
| `GET /api/v1/wallet/transactions` | Ledger |
| `POST /api/v1/wallet/topup` | Credit a wallet (service token only) |
| `POST /api/v1/wallet/debit` | Charge a wallet (`wallet.write` scope) |
| `GET /healthz` | Liveness |

## Scopes

| Scope | Grants |
|---|---|
| `openid` | An `id_token` is issued |
| `profile` | Name, avatar, phone |
| `email` | Email address |
| `wallet` | Read balance and ledger |
| `wallet.write` | Charge the wallet — only NabuGate holds this |
| `offline` | Long-lived refresh |

Email and phone appear in `/api/v1/user` only when the token carries the scope
for them, so a `profile`-only token cannot read contact details.

## Configuration

`apps.yaml` is the source of truth for which applications may sign users in.
Secrets never appear in it — each app names an environment variable:

```yaml
apps:
  - id: nabudesk
    name: NabuDesk
    url: https://desk.nabuxai.com
    redirect_uris:
      - https://desk.nabuxai.com/auth/nabu/callback
    scopes: [openid, profile, email, wallet, offline]
    secret_env: NABUAUTH_SECRET_NABUDESK
```

Set `public: true` for a client that cannot hold a secret; it must then use PKCE
and cannot use `client_credentials`. Set `hidden: true` to keep a service client
out of the dashboard launcher.

Environment:

| Variable | Meaning |
|---|---|
| `DATABASE_URL` | Postgres DSN (or the discrete `DB_HOST`/`DB_PORT`/`DB_DATABASE`/`DB_USERNAME`/`DB_PASSWORD`) |
| `NABUAUTH_ISSUER` | Public base URL; every issued token names it |
| `NABUAUTH_CONFIG` | Config path, default `apps.yaml` |
| `NABUAUTH_SECRET_*` | One client secret per app, named by its `secret_env` |
| `NABUAUTH_ALLOW_REGISTRATION` | `true` lets an unknown email create its own account from the sign-in form |
| `NABUAUTH_PROVIDER_SECRET_*` | One client secret per external sign-in method, named by its `secret_env` |
| `NABUAUTH_SMS_URL` | NabuSms base URL; unset means phone sign-in is not offered |
| `NABUAUTH_SMS_KEY` | NabuSms bearer key, named by `sms.key_env` |

The RSA signing key is generated on first boot and stored in the database, so a
fresh deployment issues valid tokens with no key ceremony and every replica signs
with the same key.

## Adding an app to the ecosystem

1. Add an entry to `apps.yaml` with its redirect URI and the scopes it needs.
2. Generate a secret (`openssl rand -base64 32`) and set the named env var on
   the NabuAuth deployment and in the app.
3. Redeploy NabuAuth. The client is upserted at boot.
4. In the app, redirect to `/oauth/authorize`, exchange the code at
   `/oauth/token`, and read `/api/v1/user`.

## Running it

```bash
go build ./...   # build
go vet ./...     # static checks
go test ./...    # unit tests

# Integration tests need a throwaway Postgres database:
createdb nabuauth_test
NABUAUTH_TEST_DATABASE_URL="postgres://localhost/nabuauth_test?sslmode=disable" go test ./...

# Locally:
createdb nabuauth_dev
DATABASE_URL="postgres://localhost/nabuauth_dev?sslmode=disable" \
NABUAUTH_SECRET_NABUDESK="dev-secret" \
go run ./cmd/nabuauth -config apps.local.yaml
```

`apps.local.yaml` points every app at localhost and opens sign-up. In
production, sign-up is closed except while the database holds no accounts at
all, so the first person to reach a fresh deployment claims it as administrator.

## Adding people

Sign-up is closed in production and every app treats a Nabu account as the way
in, so accounts are created deliberately rather than by anyone who finds the
URL. An administrator adds people from **Manage accounts** on their dashboard
(`/admin/users`): the password is generated, shown once, and never stored in
readable form. Disabling an account there stops it signing in and ends every
session it has open.

The first account on a fresh deployment has nobody to create it, so there are
two ways to bootstrap: claim it by signing in with the email and password you
want, which creates the account only while the database has no users at all, or
create it from a shell:

```bash
docker compose exec app /app/nabuauth -create-user you@example.com -name "You" -admin
```

## Adding a sign-in method

Every external method is an ordinary OIDC authorization-code provider, so one
implementation covers all of them:

1. Register `<issuer>/login/<id>/callback` as a redirect URI with the provider.
2. Add an entry to `login_methods` in `apps.yaml` with its three endpoints and
   its client id.
3. Set the secret in the env var named by `secret_env` and redeploy.

The method appears on the sign-in form only once all of that is present. An
account is matched on the email the provider asserts and **only** when the
provider says it verified that email — without that check, a provider that lets
somebody type an address is a way into whichever Nabu account already uses it.

## Turning phone sign-in on

1. Point `sms.base_url` at NabuSms and set the key in the variable named by
   `sms.key_env` (`NABUAUTH_SMS_KEY`).
2. Grant that key **both** the `otp` and `international` routes in NabuSms.
   The `otp` route is declared for Iranian numbers only and refuses anything
   else before a provider is tried, so a foreign number is carried as plain
   text on `international` instead — which is also why the country selector
   chooses the route, not just the calling code.
3. Redeploy. The field appears once the URL and the key are both present, and
   the startup log says `phone_sign_in`.

The selector's contents come from `sms.countries`; the default is the set the
gateway is known to route, and a deployment that sends elsewhere lists its own.
A verified number signs in whoever holds it, and creates the account where
registration is open — with no email address, because inventing one would be a
claim about a mailbox nobody owns. Where registration is closed, a number no
account holds is answered exactly as a known one is and costs no message.

## Recovering an account

There is no email-based password reset: the deployment has no outbound mail, so a
reset link would be a flow that can never complete. An operator with shell access
resets the password instead — the same trust boundary, since that operator can
already read the database.

```bash
docker compose exec app /app/nabuauth -reset-password you@example.com
```

It prints a freshly generated password once (rather than taking one as an
argument, which would leave it in the shell history and the process list) and
revokes every existing session and refresh token for that account — a reset is
also the lever for "someone else is in my account".

## Deployment

`docker compose up` builds the image and starts Postgres alongside it. The
compose file carries Coolify and Traefik labels for `auth.nabuxai.com` and
exposes port 8099.
