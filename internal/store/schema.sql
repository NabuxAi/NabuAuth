-- NabuAuth schema. Applied on every boot; every statement is idempotent so a
-- redeploy against an existing database is a no-op rather than a failure.

CREATE TABLE IF NOT EXISTS users (
    id             BIGSERIAL PRIMARY KEY,
    name           TEXT        NOT NULL,
    email          TEXT        NOT NULL UNIQUE,
    phone          TEXT        UNIQUE,
    password_hash  TEXT        NOT NULL,
    avatar_url     TEXT,
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
    is_admin       BOOLEAN     NOT NULL DEFAULT FALSE,
    email_verified_at TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Registered ecosystem apps. Rows are upserted from apps.yaml on boot, so the
-- config file — not a dashboard click — is the source of truth for who may sign
-- users in.
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id       TEXT PRIMARY KEY,
    name            TEXT        NOT NULL,
    description     TEXT        NOT NULL DEFAULT '',
    icon            TEXT        NOT NULL DEFAULT '',
    app_url         TEXT        NOT NULL DEFAULT '',
    badge           TEXT        NOT NULL DEFAULT '',
    secret_hash     TEXT        NOT NULL DEFAULT '',
    redirect_uris   TEXT        NOT NULL DEFAULT '',
    scopes          TEXT        NOT NULL DEFAULT '',
    is_confidential BOOLEAN     NOT NULL DEFAULT TRUE,
    is_listed       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Authorization codes. Only the hash is stored: a database dump must not be
-- enough to redeem a code that is still inside its 10-minute window.
CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash        TEXT PRIMARY KEY,
    client_id        TEXT        NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id          BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri     TEXT        NOT NULL,
    scopes           TEXT        NOT NULL DEFAULT '',
    code_challenge   TEXT        NOT NULL DEFAULT '',
    challenge_method TEXT        NOT NULL DEFAULT '',
    nonce            TEXT        NOT NULL DEFAULT '',
    expires_at       TIMESTAMPTZ NOT NULL,
    consumed_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id  TEXT        NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id    BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes     TEXT        NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_user_idx ON oauth_refresh_tokens (user_id);

-- Browser sessions for the NabuAuth login screen itself. Separate from OAuth
-- tokens: this cookie proves "the user is signed in here", nothing more.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Remembered consent, so an already-approved app does not re-prompt on every
-- redirect through /oauth/authorize.
CREATE TABLE IF NOT EXISTS oauth_consents (
    user_id    BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  TEXT        NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    scopes     TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);

CREATE TABLE IF NOT EXISTS wallets (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT      NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    balance_cents BIGINT      NOT NULL DEFAULT 0,
    currency      TEXT        NOT NULL DEFAULT 'OMR',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- amount_cents is signed: a debit is negative, a top-up positive, so the ledger
-- sums to the balance and a wrong sign shows up as a reconciliation error
-- instead of silently crediting a spend.
CREATE TABLE IF NOT EXISTS wallet_transactions (
    id                  BIGSERIAL PRIMARY KEY,
    wallet_id           BIGINT      NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    type                TEXT        NOT NULL,
    amount_cents        BIGINT      NOT NULL,
    balance_after_cents BIGINT      NOT NULL,
    description         TEXT        NOT NULL DEFAULT '',
    meta                JSONB       NOT NULL DEFAULT '{}'::jsonb,
    idempotency_key     TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS wallet_transactions_wallet_idx ON wallet_transactions (wallet_id, id DESC);

-- Retrying a debit must not charge twice. The metering caller (NabuGate) sends a
-- stable key per request; the unique index turns a duplicate into a lookup.
CREATE UNIQUE INDEX IF NOT EXISTS wallet_transactions_idem_idx
    ON wallet_transactions (idempotency_key) WHERE idempotency_key IS NOT NULL;

-- The token signing key lives in the database rather than in an env var so a
-- fresh deploy signs valid tokens with no manual key ceremony, and every replica
-- signs with the same key.
CREATE TABLE IF NOT EXISTS signing_keys (
    kid         TEXT PRIMARY KEY,
    private_pem TEXT        NOT NULL,
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
