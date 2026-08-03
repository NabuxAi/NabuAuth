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
