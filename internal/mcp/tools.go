// The tools NabuAuth exposes. One file per repo; mcp.go beside it is identical
// in all four.
//
// Every tool is read-only, and every one of them builds its answer out of a
// struct declared here with named fields. Nothing in this file returns a
// config struct, a provider record, a store row that carries a credential, or
// an upstream error's text — see the secret rule in the contract.
//
// NabuAuth is the account every product signs in against and the wallet every
// product spends from, so the rows behind these tools carry password hashes,
// client secrets and refresh tokens. That is why the dependency below is a
// four-method read interface rather than *store.Store: this package cannot
// reach Adjust, SetActive, RevokeUserTokens or SetPassword even by mistake.
package mcp

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"

	"nabuauth/internal/config"
	"nabuauth/internal/store"
)

// Version is what serverInfo reports. Bump it when the tool set changes.
const Version = "1.0.0"

// Accounts is the slice of the store these tools are allowed to see: four
// reads, no writes. *store.Store satisfies it, so main.go passes the same
// handle server.New already gets — but the wallet's Adjust, the admin
// SetActive and every token revocation are outside this interface and so
// outside this package's reach. Gating the privileged wallet operations by
// leaving them out of the type is stronger than gating them by remembering
// not to call them.
type Accounts interface {
	ListUsers(ctx context.Context, limit int) ([]store.User, error)
	UserByID(ctx context.Context, id int64) (store.User, error)
	WalletFor(ctx context.Context, userID int64) (store.Wallet, error)
	Transactions(ctx context.Context, userID int64, limit int) ([]store.Transaction, error)
}

// The real store must keep satisfying it; a signature drift is a compile error
// here rather than a runtime surprise in main.
var _ Accounts = (*store.Store)(nil)

// listCeiling is how many accounts are read before the query filter runs.
// Filtering after a limited read would silently drop a match that sits past the
// limit, so the read takes the store's own ceiling and the limit is applied to
// what matched.
const listCeiling = 500

// Register wires NabuAuth's tools onto a Server.
func Register(s *Server, cfg *config.Config, accounts Accounts) {
	s.Register(Tool{
		Name:        "nabuauth_apps_list",
		Description: "List the applications registered to sign Nabu users in: id, name, url, requested scopes, and whether the client is public or hidden from the launcher. Client secrets, and the names of the variables they arrive in, are never included.",
		InputSchema: ObjectSchema(nil, nil),
		Handler: func(_ context.Context, _ map[string]any) (any, error) {
			apps := make([]appView, 0, len(cfg.Apps))

			// Field by field on purpose: config.App also holds SecretEnv, and
			// marshalling the struct whole would put the name of every client
			// secret's variable — a map of where to look — on the wire.
			for _, a := range cfg.Apps {
				apps = append(apps, appView{
					ID:     a.ID,
					Name:   a.Name,
					URL:    a.URL,
					Scopes: a.Scopes,
					Public: a.Public,
					Hidden: a.Hidden,
				})
			}

			sort.Slice(apps, func(i, j int) bool { return apps[i].ID < apps[j].ID })

			return map[string]any{"apps": apps}, nil
		},
	})

	s.Register(Tool{
		Name:        "nabuauth_scopes_list",
		Description: "List every scope an application may request, with the sentence a user reads about it on the consent screen.",
		InputSchema: ObjectSchema(nil, nil),
		Handler: func(_ context.Context, _ map[string]any) (any, error) {
			scopes := make([]scopeView, 0, len(cfg.Scopes))

			for id, description := range cfg.Scopes {
				scopes = append(scopes, scopeView{Scope: id, Description: description})
			}

			sort.Slice(scopes, func(i, j int) bool { return scopes[i].Scope < scopes[j].Scope })

			return map[string]any{"scopes": scopes}, nil
		},
	})

	s.Register(Tool{
		Name:        "nabuauth_login_methods_list",
		Description: "List the outside identity providers offered beside the email form, and whether each one is fully configured and therefore actually shown. Client ids and client secrets are never included.",
		InputSchema: ObjectSchema(nil, nil),
		Handler: func(_ context.Context, _ map[string]any) (any, error) {
			methods := make([]loginMethodView, 0, len(cfg.LoginMethods))

			// Neither ClientID nor SecretEnv leaves this loop. Configured() is
			// carried as a bare bool instead: it answers "is this button on the
			// form" without saying which variable would turn it on.
			for _, p := range cfg.LoginMethods {
				methods = append(methods, loginMethodView{
					ID:         p.ID,
					Name:       p.Name,
					Configured: p.Configured(),
				})
			}

			sort.Slice(methods, func(i, j int) bool { return methods[i].ID < methods[j].ID })

			return map[string]any{"login_methods": methods}, nil
		},
	})

	s.Register(Tool{
		Name:        "nabuauth_users_list",
		Description: "List Nabu accounts, newest first, optionally narrowed by a substring of the handle, email or display name. Each row says whether the account is active, so a disabled one is visible rather than missing. Password hashes and tokens are never included.",
		InputSchema: ObjectSchema(map[string]any{
			"query": StringProp("Substring to match against handle, email or display name; omit for every account"),
			"limit": IntProp("How many accounts to return", 1, 200),
		}, nil),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			query := strings.ToLower(strings.TrimSpace(OptString(args, "query", "")))
			limit := Int(args, "limit", 50, 1, 200)

			rows, err := accounts.ListUsers(ctx, listCeiling)
			if err != nil {
				// Not a ToolFailure: a driver error's text can carry the DSN,
				// and the DSN carries the database password. It goes to the log.
				return nil, err
			}

			users := make([]userView, 0, limit)

			for _, u := range rows {
				if !matchesUser(u, query) {
					continue
				}
				if len(users) == limit {
					break
				}

				users = append(users, newUserView(u))
			}

			if len(users) == 0 && query != "" {
				return nil, Failf("no account matches %q", query)
			}

			return map[string]any{"users": users}, nil
		},
	})

	s.Register(Tool{
		Name:        "nabuauth_user_get",
		Description: "Look one Nabu account up by its numeric id and return its handle, email, display name, administrator flag, active state and creation time. The password hash, sessions and refresh tokens are never included.",
		InputSchema: ObjectSchema(map[string]any{
			"id": StringProp("The numeric account id, as returned by nabuauth_users_list"),
		}, []string{"id"}),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			id, err := accountID(args, "id")
			if err != nil {
				return nil, err
			}

			user, err := accounts.UserByID(ctx, id)
			if err != nil {
				if isMissing(err) {
					// A ToolFailure, not a JSON-RPC error: the model asked a
					// reasonable question and can act on the answer.
					return nil, Failf("no account has id %d", id)
				}

				return nil, err
			}

			return newUserView(user), nil
		},
	})

	s.Register(Tool{
		Name:        "nabuauth_wallet_get",
		Description: "Read one account's shared wallet: its current balance, its currency, and its most recent ledger movements. Read-only — this tool cannot debit or top up a wallet, and the free-form meta an application attaches to a movement is deliberately left out.",
		InputSchema: ObjectSchema(map[string]any{
			"user_id": StringProp("The numeric account id whose wallet to read"),
			"limit":   IntProp("How many recent movements to return", 1, 100),
		}, []string{"user_id"}),
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			id, err := accountID(args, "user_id")
			if err != nil {
				return nil, err
			}

			// The account is resolved first so an unknown id is answered as an
			// unknown id, rather than as an empty wallet the caller believes in.
			if _, err := accounts.UserByID(ctx, id); err != nil {
				if isMissing(err) {
					return nil, Failf("no account has id %d, so there is no wallet to read", id)
				}

				return nil, err
			}

			wallet, err := accounts.WalletFor(ctx, id)
			if err != nil {
				return nil, err
			}

			entries, err := accounts.Transactions(ctx, id, Int(args, "limit", 20, 1, 100))
			if err != nil {
				return nil, err
			}

			movements := make([]movementView, 0, len(entries))
			for _, t := range entries {
				movements = append(movements, newMovementView(t))
			}

			return walletView{
				UserID:       wallet.UserID,
				BalanceCents: wallet.BalanceCents,
				Currency:     wallet.Currency,
				Movements:    movements,
			}, nil
		},
	})
}

// matchesUser reports whether an account matches a query. The password hash is
// not among the searched fields — matching on it would make this a probe.
func matchesUser(u store.User, query string) bool {
	if query == "" {
		return true
	}

	for _, field := range []string{u.Username, u.Email, u.Name} {
		if field != "" && strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}

	return false
}

// accountID reads a required account id, accepting the JSON string the schema
// declares and the JSON number a client may send instead.
//
// Deliberately not the Int helper: Int takes a fallback and clamps, so a
// missing id would silently become somebody else's account.
func accountID(args map[string]any, name string) (int64, error) {
	switch v := args[name].(type) {
	case string:
		id, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil || id <= 0 {
			return 0, Failf("%q must be a positive account id, and %q is not one", name, v)
		}

		return id, nil

	case float64:
		if v <= 0 || v != float64(int64(v)) {
			return 0, Failf("%q must be a positive whole account id", name)
		}

		return int64(v), nil

	default:
		return 0, Failf("%q is required and must be an account id", name)
	}
}

// isMissing reports whether a store lookup found nothing, as opposed to the
// database being broken. Only the first is something the model can act on; the
// second is logged and replaced, because a driver error's text can carry the
// connection string.
func isMissing(err error) bool { return errors.Is(err, store.ErrNotFound) }

// The response types. Named fields only — that is the whole defence.

type appView struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	URL    string   `json:"url,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	Public bool     `json:"public"`
	Hidden bool     `json:"hidden"`
}

type scopeView struct {
	Scope       string `json:"scope"`
	Description string `json:"description"`
}

type loginMethodView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Configured reports whether the provider is complete enough to be offered.
	// It is a bool rather than the missing field's name for a reason: naming the
	// variable would tell a reader where this deployment's secrets live.
	Configured bool `json:"configured"`
}

type userView struct {
	ID          int64  `json:"id"`
	Handle      string `json:"handle,omitempty"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name"`
	Admin       bool   `json:"admin"`
	Active      bool   `json:"active"`
	CreatedAt   string `json:"created_at"`
}

// newUserView copies the six fields worth reporting out of a store row. The row
// also holds PasswordHash; it is named nowhere below, which is why a later edit
// to store.User cannot widen this response by accident.
func newUserView(u store.User) userView {
	return userView{
		ID:          u.ID,
		Handle:      u.Username,
		Email:       u.Email,
		DisplayName: u.Name,
		Admin:       u.IsAdmin,
		Active:      u.IsActive,
		CreatedAt:   u.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

type walletView struct {
	UserID       int64          `json:"user_id"`
	BalanceCents int64          `json:"balance_cents"`
	Currency     string         `json:"currency"`
	Movements    []movementView `json:"movements"`
}

type movementView struct {
	ID                int64  `json:"id"`
	Type              string `json:"type"`
	AmountCents       int64  `json:"amount_cents"`
	BalanceAfterCents int64  `json:"balance_after_cents"`
	Description       string `json:"description,omitempty"`
	CreatedAt         string `json:"created_at"`
}

// newMovementView copies a ledger entry. store.Transaction also carries Meta, a
// free-form map whatever application charged the wallet wrote — an idempotency
// context, a request id, or whatever else that app happened to put there. It is
// the one field of the ledger whose contents nothing in this repo controls, so
// it does not travel.
func newMovementView(t store.Transaction) movementView {
	return movementView{
		ID:                t.ID,
		Type:              t.Type,
		AmountCents:       t.AmountCents,
		BalanceAfterCents: t.BalanceAfterCents,
		Description:       t.Description,
		CreatedAt:         t.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}
