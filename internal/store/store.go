// Package store owns the NabuAuth database: schema, users, OAuth clients,
// codes, tokens, sessions and the wallet ledger.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx"
)

//go:embed schema.sql
var schemaSQL string

// ErrNotFound is returned by every lookup that finds nothing, so callers can
// tell "no such row" apart from "the database is broken".
var ErrNotFound = errors.New("not found")

// ErrDuplicate is returned when a unique constraint rejects a write (a taken
// email, a replayed idempotency key).
var ErrDuplicate = errors.New("duplicate")

// ErrInsufficientFunds is returned when a debit would overdraw the wallet.
var ErrInsufficientFunds = errors.New("insufficient funds")

// Store is the database handle plus the queries NabuAuth needs.
type Store struct {
	db *sql.DB
}

// Open connects to Postgres and applies the schema.
func Open(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the connection pool.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the raw handle for tests and one-off maintenance queries.
func (s *Store) DB() *sql.DB { return s.db }

func isUnique(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Lists are stored as delimited TEXT rather than Postgres arrays: scopes are
// space-delimited in the OAuth wire format already, so the column matches what
// goes over HTTP and no driver-specific array encoding sits in between.

// JoinList encodes a list for storage.
func JoinList(items []string) string { return strings.Join(items, " ") }

// SplitList decodes a stored list. Always returns non-nil for an empty value so
// callers can range over it without a check.
func SplitList(s string) []string {
	f := strings.Fields(s)
	if f == nil {
		return []string{}
	}
	return f
}

// ---------------------------------------------------------------- users

// User is an ecosystem account.
type User struct {
	ID           int64
	Name         string
	Email        string
	Phone        string
	PasswordHash string
	AvatarURL    string
	IsActive     bool
	IsAdmin      bool
	CreatedAt    time.Time
}

type scanner interface{ Scan(...any) error }

const userColumns = `id, name, email, COALESCE(phone, ''), password_hash, COALESCE(avatar_url, ''), is_active, is_admin, created_at`

// userColumnsQualified is the same list with a table alias, for queries that
// join sessions to users.
const userColumnsQualified = `u.id, u.name, u.email, COALESCE(u.phone, ''), u.password_hash, COALESCE(u.avatar_url, ''), u.is_active, u.is_admin, u.created_at`

func scanUser(row scanner) (User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Name, &u.Email, &u.Phone, &u.PasswordHash, &u.AvatarURL, &u.IsActive, &u.IsAdmin, &u.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	return u, nil
}

// CreateUser inserts an account and opens its wallet in one transaction, so a
// user can never exist without somewhere to hold credit.
func (s *Store) CreateUser(ctx context.Context, name, email, phone, passwordHash string, isAdmin bool) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	var phoneArg any
	if phone = strings.TrimSpace(phone); phone != "" {
		phoneArg = phone
	}
	u, err := scanUser(tx.QueryRowContext(ctx,
		`INSERT INTO users (name, email, phone, password_hash, is_admin) VALUES ($1, $2, $3, $4, $5) RETURNING `+userColumns,
		name, email, phoneArg, passwordHash, isAdmin))
	if err != nil {
		if isUnique(err) {
			return User{}, ErrDuplicate
		}
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO wallets (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING`, u.ID); err != nil {
		return User{}, err
	}
	return u, tx.Commit()
}

// UserByEmail looks an account up by its (case-insensitive) email.
func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1`, email))
}

// UserByID looks an account up by primary key.
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

// UpdateProfile changes the display name, phone and avatar of an account.
func (s *Store) UpdateProfile(ctx context.Context, id int64, name, phone, avatarURL string) error {
	var phoneArg any
	if phone = strings.TrimSpace(phone); phone != "" {
		phoneArg = phone
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET name = $2, phone = $3, avatar_url = NULLIF($4, ''), updated_at = now() WHERE id = $1`,
		id, name, phoneArg, avatarURL)
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// SetPassword replaces the stored password hash.
func (s *Store) SetPassword(ctx context.Context, id int64, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`, id, hash)
	return err
}

// CountUsers reports how many accounts exist; used to decide whether the first
// registration should be granted admin.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// ---------------------------------------------------------------- clients

// Client is a registered ecosystem application.
type Client struct {
	ClientID       string
	Name           string
	Description    string
	Icon           string
	AppURL         string
	Badge          string
	SecretHash     string
	RedirectURIs   []string
	Scopes         []string
	IsConfidential bool
	IsListed       bool
}

// AllowsRedirect reports whether uri is one of the client's registered redirect
// URIs. Exact match only: prefix matching is how open redirectors happen.
func (c Client) AllowsRedirect(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// AllowsScope reports whether the client may request a scope. An empty scope
// list means the client is restricted to the server defaults.
func (c Client) AllowsScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

const clientColumns = `client_id, name, description, icon, app_url, badge, secret_hash, redirect_uris, scopes, is_confidential, is_listed`

func scanClient(row scanner) (Client, error) {
	var c Client
	var redirects, scopes string
	err := row.Scan(&c.ClientID, &c.Name, &c.Description, &c.Icon, &c.AppURL, &c.Badge, &c.SecretHash,
		&redirects, &scopes, &c.IsConfidential, &c.IsListed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Client{}, ErrNotFound
		}
		return Client{}, err
	}
	c.RedirectURIs = SplitList(redirects)
	c.Scopes = SplitList(scopes)
	return c, nil
}

// UpsertClient registers or updates an app. The secret hash is only overwritten
// when a new one is supplied, so restarting without the secret env var set does
// not silently lock an app out.
func (s *Store) UpsertClient(ctx context.Context, c Client) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_clients (client_id, name, description, icon, app_url, badge, secret_hash, redirect_uris, scopes, is_confidential, is_listed)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (client_id) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			icon = EXCLUDED.icon,
			app_url = EXCLUDED.app_url,
			badge = EXCLUDED.badge,
			secret_hash = CASE WHEN EXCLUDED.secret_hash = '' THEN oauth_clients.secret_hash ELSE EXCLUDED.secret_hash END,
			redirect_uris = EXCLUDED.redirect_uris,
			scopes = EXCLUDED.scopes,
			is_confidential = EXCLUDED.is_confidential,
			is_listed = EXCLUDED.is_listed,
			updated_at = now()`,
		c.ClientID, c.Name, c.Description, c.Icon, c.AppURL, c.Badge, c.SecretHash,
		JoinList(c.RedirectURIs), JoinList(c.Scopes), c.IsConfidential, c.IsListed)
	return err
}

// ClientByID returns a registered app.
func (s *Store) ClientByID(ctx context.Context, clientID string) (Client, error) {
	return scanClient(s.db.QueryRowContext(ctx, `SELECT `+clientColumns+` FROM oauth_clients WHERE client_id = $1`, clientID))
}

// ListedClients returns the apps shown in the account dashboard launcher.
func (s *Store) ListedClients(ctx context.Context) ([]Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+clientColumns+` FROM oauth_clients WHERE is_listed ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- auth codes

// Code is a pending authorization code grant.
type Code struct {
	ClientID        string
	UserID          int64
	RedirectURI     string
	Scopes          []string
	CodeChallenge   string
	ChallengeMethod string
	Nonce           string
}

// SaveCode stores a hashed authorization code with its expiry.
func (s *Store) SaveCode(ctx context.Context, hash string, c Code, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, challenge_method, nonce, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		hash, c.ClientID, c.UserID, c.RedirectURI, JoinList(c.Scopes), c.CodeChallenge, c.ChallengeMethod, c.Nonce, expiresAt)
	return err
}

// ConsumeCode atomically marks a code used and returns it. A second call for the
// same code returns ErrNotFound, which is what makes a replayed code useless.
func (s *Store) ConsumeCode(ctx context.Context, hash string) (Code, error) {
	var c Code
	var scopes string
	err := s.db.QueryRowContext(ctx, `
		UPDATE oauth_codes SET consumed_at = now()
		WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > now()
		RETURNING client_id, user_id, redirect_uri, scopes, code_challenge, challenge_method, nonce`, hash).
		Scan(&c.ClientID, &c.UserID, &c.RedirectURI, &scopes, &c.CodeChallenge, &c.ChallengeMethod, &c.Nonce)
	if errors.Is(err, sql.ErrNoRows) {
		return Code{}, ErrNotFound
	}
	c.Scopes = SplitList(scopes)
	return c, err
}

// ---------------------------------------------------------------- refresh tokens

// RefreshToken is a stored refresh grant.
type RefreshToken struct {
	ClientID string
	UserID   int64
	Scopes   []string
}

// SaveRefreshToken stores a hashed refresh token.
func (s *Store) SaveRefreshToken(ctx context.Context, hash string, t RefreshToken, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, scopes, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		hash, t.ClientID, t.UserID, JoinList(t.Scopes), expiresAt)
	return err
}

// ConsumeRefreshToken revokes a refresh token and returns it, so the caller can
// issue a replacement. Rotation means a stolen refresh token works at most once,
// and the theft surfaces as the legitimate client suddenly failing.
func (s *Store) ConsumeRefreshToken(ctx context.Context, hash string) (RefreshToken, error) {
	var t RefreshToken
	var scopes string
	err := s.db.QueryRowContext(ctx, `
		UPDATE oauth_refresh_tokens SET revoked_at = now()
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
		RETURNING client_id, user_id, scopes`, hash).
		Scan(&t.ClientID, &t.UserID, &scopes)
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshToken{}, ErrNotFound
	}
	t.Scopes = SplitList(scopes)
	return t, err
}

// RevokeRefreshToken marks a single refresh token revoked, ignoring unknown
// tokens (RFC 7009 requires revocation to succeed regardless).
func (s *Store) RevokeRefreshToken(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`, hash)
	return err
}

// RevokeUserTokens revokes every refresh token of a user, for "sign out
// everywhere" and after a password change.
func (s *Store) RevokeUserTokens(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}

// ---------------------------------------------------------------- sessions

// CreateSession stores a browser session for the NabuAuth UI itself.
func (s *Store) CreateSession(ctx context.Context, hash string, userID int64, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`, hash, userID, expiresAt)
	return err
}

// SessionUser resolves a session cookie to its account.
func (s *Store) SessionUser(ctx context.Context, hash string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumnsQualified+` FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = $1 AND s.expires_at > now() AND u.is_active`, hash))
}

// DeleteSession signs a browser out.
func (s *Store) DeleteSession(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = $1`, hash)
	return err
}

// ---------------------------------------------------------------- consent

// GrantedScopes returns the scopes a user has already approved for a client.
func (s *Store) GrantedScopes(ctx context.Context, userID int64, clientID string) ([]string, error) {
	var scopes string
	err := s.db.QueryRowContext(ctx, `SELECT scopes FROM oauth_consents WHERE user_id = $1 AND client_id = $2`, userID, clientID).Scan(&scopes)
	if errors.Is(err, sql.ErrNoRows) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	return SplitList(scopes), nil
}

// HasConsent reports whether every requested scope was already approved.
func (s *Store) HasConsent(ctx context.Context, userID int64, clientID string, scopes []string) (bool, error) {
	granted, err := s.GrantedScopes(ctx, userID, clientID)
	if err != nil {
		return false, err
	}
	have := make(map[string]bool, len(granted))
	for _, g := range granted {
		have[g] = true
	}
	for _, want := range scopes {
		if !have[want] {
			return false, nil
		}
	}
	return true, nil
}

// SaveConsent records the union of previously and newly granted scopes.
func (s *Store) SaveConsent(ctx context.Context, userID int64, clientID string, scopes []string) error {
	granted, err := s.GrantedScopes(ctx, userID, clientID)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(granted)+len(scopes))
	merged := make([]string, 0, len(granted)+len(scopes))
	for _, s := range append(granted, scopes...) {
		if !seen[s] {
			seen[s] = true
			merged = append(merged, s)
		}
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO oauth_consents (user_id, client_id, scopes) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes`,
		userID, clientID, JoinList(merged))
	return err
}

// RevokeConsent forgets an app's approval and kills its refresh tokens.
func (s *Store) RevokeConsent(ctx context.Context, userID int64, clientID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM oauth_consents WHERE user_id = $1 AND client_id = $2`, userID, clientID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL`,
		userID, clientID); err != nil {
		return err
	}
	return tx.Commit()
}

// ConsentedClients lists the apps a user has approved.
func (s *Store) ConsentedClients(ctx context.Context, userID int64) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT client_id, scopes FROM oauth_consents WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var id, scopes string
		if err := rows.Scan(&id, &scopes); err != nil {
			return nil, err
		}
		out[id] = SplitList(scopes)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- wallet

// Wallet is a user's prepaid balance.
type Wallet struct {
	ID           int64
	UserID       int64
	BalanceCents int64
	Currency     string
}

// Transaction is one ledger entry.
type Transaction struct {
	ID                int64
	Type              string
	AmountCents       int64
	BalanceAfterCents int64
	Description       string
	Meta              map[string]any
	CreatedAt         time.Time
}

// WalletFor returns the user's wallet, creating it if an older account predates
// the wallet table.
func (s *Store) WalletFor(ctx context.Context, userID int64) (Wallet, error) {
	var w Wallet
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO wallets (user_id) VALUES ($1)
		ON CONFLICT (user_id) DO UPDATE SET updated_at = wallets.updated_at
		RETURNING id, user_id, balance_cents, currency`, userID).
		Scan(&w.ID, &w.UserID, &w.BalanceCents, &w.Currency)
	if err != nil {
		return Wallet{}, err
	}
	return w, nil
}

// Adjust moves money in or out of a wallet and writes the ledger entry, under a
// row lock so two concurrent debits cannot both read the same balance.
//
// amountCents is signed: negative debits, positive credits. allowNegative is
// false for user spending and true for administrative corrections.
func (s *Store) Adjust(ctx context.Context, userID int64, kind string, amountCents int64, description string, meta map[string]any, idempotencyKey string, allowNegative bool) (Transaction, Wallet, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Transaction{}, Wallet{}, err
	}
	defer tx.Rollback()

	var w Wallet
	err = tx.QueryRowContext(ctx, `
		INSERT INTO wallets (user_id) VALUES ($1)
		ON CONFLICT (user_id) DO UPDATE SET updated_at = wallets.updated_at
		RETURNING id, user_id, balance_cents, currency`, userID).
		Scan(&w.ID, &w.UserID, &w.BalanceCents, &w.Currency)
	if err != nil {
		return Transaction{}, Wallet{}, err
	}
	// Re-read under a lock: the upsert above does not serialise concurrent
	// callers, and the balance we write must be the one we decided from.
	if err := tx.QueryRowContext(ctx, `SELECT balance_cents FROM wallets WHERE id = $1 FOR UPDATE`, w.ID).Scan(&w.BalanceCents); err != nil {
		return Transaction{}, Wallet{}, err
	}

	if idempotencyKey != "" {
		existing, err := scanTx(tx.QueryRowContext(ctx,
			`SELECT id, type, amount_cents, balance_after_cents, description, meta, created_at
			 FROM wallet_transactions WHERE idempotency_key = $1`, idempotencyKey))
		if err == nil {
			// Already applied. Return the original entry and the current balance
			// so a retry is indistinguishable from the first call.
			return existing, w, tx.Commit()
		}
		if !errors.Is(err, ErrNotFound) {
			return Transaction{}, Wallet{}, err
		}
	}

	newBalance := w.BalanceCents + amountCents
	if newBalance < 0 && !allowNegative {
		return Transaction{}, w, ErrInsufficientFunds
	}
	if _, err := tx.ExecContext(ctx, `UPDATE wallets SET balance_cents = $2, updated_at = now() WHERE id = $1`, w.ID, newBalance); err != nil {
		return Transaction{}, Wallet{}, err
	}

	if meta == nil {
		meta = map[string]any{}
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return Transaction{}, Wallet{}, err
	}
	var idemArg any
	if idempotencyKey != "" {
		idemArg = idempotencyKey
	}
	entry, err := scanTx(tx.QueryRowContext(ctx, `
		INSERT INTO wallet_transactions (wallet_id, type, amount_cents, balance_after_cents, description, meta, idempotency_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, type, amount_cents, balance_after_cents, description, meta, created_at`,
		w.ID, kind, amountCents, newBalance, description, metaJSON, idemArg))
	if err != nil {
		if isUnique(err) {
			return Transaction{}, Wallet{}, ErrDuplicate
		}
		return Transaction{}, Wallet{}, err
	}
	w.BalanceCents = newBalance
	return entry, w, tx.Commit()
}

func scanTx(row scanner) (Transaction, error) {
	var t Transaction
	var metaJSON []byte
	err := row.Scan(&t.ID, &t.Type, &t.AmountCents, &t.BalanceAfterCents, &t.Description, &metaJSON, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Transaction{}, ErrNotFound
		}
		return Transaction{}, err
	}
	if len(metaJSON) > 0 {
		_ = json.Unmarshal(metaJSON, &t.Meta)
	}
	return t, nil
}

// Transactions returns the most recent ledger entries for a user.
func (s *Store) Transactions(ctx context.Context, userID int64, limit int) ([]Transaction, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.id, t.type, t.amount_cents, t.balance_after_cents, t.description, t.meta, t.created_at
		FROM wallet_transactions t JOIN wallets w ON w.id = t.wallet_id
		WHERE w.user_id = $1 ORDER BY t.id DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Transaction
	for rows.Next() {
		t, err := scanTx(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- signing keys

// SigningKey is a stored RSA private key in PEM form.
type SigningKey struct {
	KID        string
	PrivatePEM string
}

// ActiveSigningKeys returns every key still trusted for verification, newest
// first. The newest signs; the rest keep already-issued tokens valid across a
// rotation.
func (s *Store) ActiveSigningKeys(ctx context.Context) ([]SigningKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kid, private_pem FROM signing_keys WHERE is_active ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SigningKey
	for rows.Next() {
		var k SigningKey
		if err := rows.Scan(&k.KID, &k.PrivatePEM); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// InsertSigningKey stores a newly generated key. Concurrent boots race here; the
// primary key makes the loser's insert a no-op and both then read the winner.
func (s *Store) InsertSigningKey(ctx context.Context, k SigningKey) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO signing_keys (kid, private_pem) VALUES ($1, $2) ON CONFLICT (kid) DO NOTHING`, k.KID, k.PrivatePEM)
	return err
}

// Cleanup deletes expired codes, tokens and sessions.
func (s *Store) Cleanup(ctx context.Context) error {
	stmts := []string{
		`DELETE FROM oauth_codes WHERE expires_at < now() - interval '1 day'`,
		`DELETE FROM oauth_refresh_tokens WHERE expires_at < now() - interval '7 days'`,
		`DELETE FROM sessions WHERE expires_at < now()`,
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}
