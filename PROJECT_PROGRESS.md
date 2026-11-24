# Progress

## 2026-08-03 — checked the claims against the running service

NabuAuth had no progress file. This is the first, and it starts by testing what
the README says rather than restating it.

### The security properties hold, on the deployment, today

Probed `auth.nabuxai.com` directly — read-only requests, nothing sent, nothing
guessed:

| claim | result |
|---|---|
| an unregistered `redirect_uri` is refused | **400, and no `Location` header** — no open redirect, so a code cannot be delivered to somebody else's host |
| an unknown `client_id` is refused | **400** |
| the token endpoint needs client authentication | **401** |
| `/oauth/jwks.json` publishes public keys only | RSA-2048, `alg=RS256`, `use=sig`, **no `d` component** — the private half is not there |
| discovery is complete | `authorization_endpoint`, `introspection_endpoint`, `end_session_endpoint`, PKCE `S256`+`plain`, all three grant types |

Nothing here is pretending. That is worth writing down as plainly as a fault
would be.

### One claim was not true

The README said:

> One account at `auth.nabuxai.com` works in NabuDesk, NabuGen, NabuGate,
> NabuVoice, NabuWrite, **NabuSu, NabuWatch and the Nabux store**.

`apps.yaml` registers six applications and none of those last three is among
them. Grepping all three repositories for `auth.nabuxai.com`, `NABUAUTH` or
`nabuauth` returns nothing at all — not a stub, not a config key, nothing.

The sentence had been true as an intention and was being read as a statement of
fact. A README that lists an integration nobody built is worse than one that
lists none: it is the thing somebody reads before deciding not to build it.

The list is now the six that exist, and it sits between
`<!-- registered-apps:begin -->` / `<!-- registered-apps:end -->` markers with a
test comparing it to `apps.yaml` in both directions — an app promised but not
registered fails, and an app registered but undocumented fails too, because
somebody integrating will not know it is already possible.

Marker-delimited rather than parsed out of prose. A test that reads English
breaks when the English improves, and then it gets deleted.

Verified it bites: putting NabuWatch and NabuSu back into the list turns the
suite red naming both.

### Two more checks on apps.yaml, for the same reason

- **Every secret is a variable name, never a value.** `apps.yaml` is in version
  control; a secret written here is a secret in every clone, fork and backup,
  and rotating it becomes a commit. The convention is `NABUAUTH_SECRET_<APP>`,
  and a name outside it is the one nobody sets on deploy.
- **Every app has a redirect URI, and none of them is plaintext http** (bar
  localhost). An app with none appears on the launcher and fails at the last
  step; a code sent in the clear can be exchanged by whoever reads it.

### PKCE is mandatory for public clients, and there are no public clients

All six registered apps are confidential. So that rule is correct and currently
unexercised — not a fault, but not evidence either, and worth knowing before
somebody registers an SPA and assumes it was proven.

## Needs you

**Register NabuSu, NabuWatch and the Nabux store, or leave them out.** Each
needs a redirect URI and a client secret set as `NABUAUTH_SECRET_<APP>` on the
deployment. The secret is a value only whoever deploys can create, so the
structure is here and the entry is not — adding one with an invented secret
would produce an app that appears in the launcher and fails at sign-in.

### 2026-08-13 — one door, and a place for other keys

**`/login` and `/register` are one form.** Email and password, one step. The
email either has an account behind it or it does not; the second case creates
the account from the same submission where `allow_registration` permits it, and
`/register` is now a redirect so nothing that linked to it breaks.

The reason is not tidiness. Every app in the ecosystem sends people here, and
somebody arriving from NabuCRM does not know whether NabuGate already made them
a Nabu account. "Sign in" or "Sign up" is a question they cannot answer, and
whichever they pick, half of them are on the wrong page.

Three things had to stay true through the merge:

- **A wrong password is never a sign-up.** The account exists, so the password
  is checked, and a second account is not created beside it.
- **A closed deployment does not say which emails have accounts.** With
  `allow_registration` off, an unknown email is refused with the same sentence a
  wrong password gets, and takes the same time, because the difference between
  the two answers is the answer to "does this address have an account here?".
- **A mistyped address does not silently become a new account with no
  explanation.** Below the password minimum it says so as a sign-up, naming the
  address: "No Nabu account uses …@… yet."

The form also names the app that sent the visitor, read out of the `client_id`
in `next`, and a session that began by creating the account carries a one-shot
marker so the consent screen can say the account is new. An approval prompt is
the second thing a brand-new user ever sees; without a word of context it reads
as a stranger asking for permission to something they did not sign up for.

**External sign-in methods.** `login_methods` in `apps.yaml` takes any OIDC
provider — Google, Microsoft, an enterprise IdP, another Nabu deployment — as
three endpoints, a client id and a secret env var. One implementation covers all
of them; adding one is configuration, not code.

Two rules make it safe to believe a provider:

- **The email must be one the provider says it verified.** A provider that lets
  a user type an address is otherwise a way into whichever Nabu account already
  uses it.
- **A method with a missing secret or endpoint is not offered at all.** A button
  that leads to an exchange this deployment cannot complete is worse than no
  button.

`allow_registration` now reads `NABUAUTH_ALLOW_REGISTRATION` from the
environment rather than being pinned in the file, because the one-door form
turns it into an operational decision rather than a build-time one.

## Needs you

**Set `NABUAUTH_ALLOW_REGISTRATION=true` on the deployment** if people are meant
to be able to sign themselves up. Unset still reads as closed, which is the
behaviour that shipped before — the sign-in form then refuses unknown emails
with the same wording as a wrong password, and accounts come from `/admin/users`
or the CLI.

### 2026-11-24 — the MCP gateways, silent sign-in, and a sign-in screen that looks the part

**Ten MCP gateways are registered**: the existing Instagram and WhatsApp, plus
Telegram (`tm.`), Facebook (`fb.`), X (`x.`), LinkedIn (`linkedin.`), Threads
(`threads.`), YouTube (`youtube.`), Snapchat (`snap.`) and Social (`social.`),
each at `https://<host>.nabuxai.com/auth/nabu/callback` with
`[openid, profile, email]` and its own `NABUAUTH_SECRET_<APP>_MCP`. A gateway
whose secret is not set yet does not stop the server — that was already true
(`SyncApps` warns and keeps going) and is now covered by a test.

**`prompt` is a set, and `prompt=login` no longer loops.** `prompt=none` already
answered `login_required` / `consent_required` at the app's callback; now there
are tests for it, and `none` combined with another value is `invalid_request`.
`prompt=login` used to end the session and send the visitor to `/login` with a
`next` that still said `prompt=login` — so signing in came back, ended the new
session and went round again, for ever. The `next` now drops `login`. "Not
you?" on the approval screen repeats the whole request with `prompt=login`
instead of a bare `client_id`, which only worked for apps with one redirect URI.

**The sign-in screens were redrawn**: a split layout on a desktop (the
ecosystem — the apps one account opens and the MCP gateways' marks — on the
ink-coloured side, the form on the other), one column on a phone; the app being
signed in to named in the heading with its platform mark beside Nabu's; a
reminder chip of who is signing in on every second step; one-time-code fields
that look like codes; light and dark; Vazirmatn embedded for Persian and Arabic
(Arabic-script subset only, 46 KB). Nabu the robot stays, in the ecosystem half,
with his pause control faint until hovered or focused. Every URL, form field and
flow is unchanged. Apps can carry an optional, validated `brand:`.

Also fixed on the way: three integration tests had been failing on `main` since
the rule that a non-https redirect needs PKCE — they now send a verifier.

## Needs you

Set these on the NabuAuth deployment (and the same value in each gateway):
`NABUAUTH_SECRET_TELEGRAM_MCP`, `NABUAUTH_SECRET_FACEBOOK_MCP`,
`NABUAUTH_SECRET_X_MCP`, `NABUAUTH_SECRET_LINKEDIN_MCP`,
`NABUAUTH_SECRET_THREADS_MCP`, `NABUAUTH_SECRET_YOUTUBE_MCP`,
`NABUAUTH_SECRET_SNAPCHAT_MCP`, `NABUAUTH_SECRET_SOCIAL_MCP`
(`openssl rand -base64 32` each), then redeploy.
