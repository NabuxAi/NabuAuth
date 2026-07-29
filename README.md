# NabuAuth — central single sign-on for the Nabu ecosystem

NabuAuth is the OAuth 2.0 / OpenID Connect identity provider every Nabu product
signs users in with, plus the shared prepaid wallet those products spend from.
One account at `auth.nabuxai.com` works in NabuDesk, NabuGen, NabuGate,
NabuVoice, NabuWrite, NabuSu, NabuWatch and the Nabux store.

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
- **Account UI**: sign in, sign up, app launcher, wallet history.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | Discovery document |
| `GET /oauth/jwks.json` | Public signing keys |
| `GET /oauth/authorize` | Login and consent screen |
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

## Deployment

`docker compose up` builds the image and starts Postgres alongside it. The
compose file carries Coolify and Traefik labels for `auth.nabuxai.com` and
exposes port 8099.
