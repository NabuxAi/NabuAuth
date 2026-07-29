# Putting an app behind NabuAuth

Every Nabu product signs users in with one account. This is what it takes to add
one, end to end.

## 1. Decide the callback URL

NabuAuth matches `redirect_uri` **exactly** — not by prefix, because prefix
matching is how open redirectors happen. So the URL registered here has to be
character-for-character the path the app actually serves.

The apps registered today, and where each one really listens:

| App | Callback |
|---|---|
| NabuDesk | `https://desk.nabuxai.com/auth/nabu/callback` |
| NabuGen | `https://gen.nabuxai.com/auth/nabu/callback` |
| NabuVoice | `https://voice.nabuxai.com/auth/nabu/callback` |
| NabuWrite | `https://write.nabuxai.com/api/auth/nabu/callback` |
| NabuGate console | `https://gate.nabuxai.com/admin/api/nabu/callback` |

NabuWrite and the NabuGate console differ from the rest because their APIs are
mounted under `/api` and `/admin`. Getting this wrong does not fail quietly: the
user is stopped at NabuAuth with "redirect not allowed" before any code is
issued.

## 2. Register it in `apps.yaml`

```yaml
  - id: myapp
    name: My App
    description: What it does
    url: https://myapp.nabuxai.com
    redirect_uris:
      - https://myapp.nabuxai.com/auth/nabu/callback
    scopes: [openid, profile, email, offline]
    secret_env: NABUAUTH_SECRET_MYAPP
```

Only `wallet.write` needs thought: it is the scope that charges a user's
balance, and NabuGate holds it because metering is its job. An app that merely
displays a balance asks for `wallet`.

Add `public: true` for a client that cannot keep a secret (a SPA or mobile app);
it then must use PKCE and cannot use `client_credentials`. Add `hidden: true` to
keep a service client out of the dashboard launcher.

## 3. Generate the secret

```bash
openssl rand -base64 32
```

Set it as `NABUAUTH_SECRET_MYAPP` on the NabuAuth deployment **and** as
`NABUAUTH_CLIENT_SECRET` on the app. The secret never goes in `apps.yaml`, which
is why that file is safe to commit and to bake into the image.

An app whose secret is missing is still registered, but it cannot complete a
token exchange. NabuAuth says so in its startup log rather than letting the
failure surface later inside a redirect.

## 4. Redeploy NabuAuth

Clients are upserted from `apps.yaml` at boot. The file is the source of truth —
there is no dashboard that can contradict it.

## 5. Implement the app side

Four moving parts, in this order:

1. **Start** — generate a `state` and a PKCE verifier, keep both server-side,
   and redirect to `/oauth/authorize` with the verifier's SHA-256 hash as
   `code_challenge`.
2. **Callback** — refuse anything whose `state` does not match the flow this
   browser started, *before* making any token request.
3. **Exchange** — POST to `/oauth/token` with the code, the verifier and the
   client secret. Read the profile from `/api/v1/user`.
4. **Session** — match the account on email, adopt an existing local user rather
   than duplicating it, and issue your own session.

The verifier must never leave the server. Only its hash goes in the redirect;
that is the whole point of PKCE, and it is what makes a code captured in transit
useless to whoever captured it.

Where the app has no server-side session for an anonymous visitor, the state and
verifier can travel in a cookie — but sign it. An unsigned cookie lets a visitor
forge a state to match a code they obtained elsewhere. NabuGen, NabuWrite and the
NabuGate console all do this with an HMAC keyed on the client secret.

## 6. Gate the console differently

Authentication is not authorisation. NabuAuth proves who someone is; it says
nothing about whether they may administer a gateway that holds provider secrets
and mints tokens. The NabuGate console therefore checks an explicit allow-list
(`NABU_CONSOLE_NABUAUTH_ADMINS`) after a successful sign-in, and refuses to
offer single sign-on at all when that list is empty — an empty list must read as
"nobody", never as "everyone".

## Refresh tokens rotate

`/oauth/token` returns a new refresh token every time and revokes the one just
used. Persist the replacement or the next refresh fails. This is deliberate: a
stolen refresh token then works at most once, and the theft shows up as the
legitimate client suddenly being refused.
