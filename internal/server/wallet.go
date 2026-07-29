package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"nabuauth/internal/store"
	"nabuauth/internal/tokens"
)

// walletRequest is the body of a top-up or a debit.
type walletRequest struct {
	// UserID names the account to charge. Required for a service token (which
	// represents an app, not a person) and ignored for a user token, which can
	// only ever touch its own wallet.
	UserID         int64          `json:"user_id"`
	AmountCents    int64          `json:"amount_cents"`
	Description    string         `json:"description"`
	Meta           map[string]any `json:"meta"`
	IdempotencyKey string         `json:"idempotency_key"`
}

// walletSubject resolves which wallet a request may act on.
//
// A user token is bound to its own wallet, full stop. A service token must name
// the user, because it acts on behalf of many.
func (s *Server) walletSubject(w http.ResponseWriter, claims tokens.Claims, requested int64) (int64, bool) {
	if strings.HasPrefix(claims.Subject, "client:") {
		if requested <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "user_id is required when calling with a service token",
			})
			return 0, false
		}
		return requested, true
	}
	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return 0, false
	}
	if requested != 0 && requested != userID {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":             "access_denied",
			"error_description": "this token may only act on its own wallet",
		})
		return 0, false
	}
	return userID, true
}

func (s *Server) handleWalletBalance(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireScope(w, r, "wallet")
	if !ok {
		return
	}
	requested, _ := strconv.ParseInt(r.URL.Query().Get("user_id"), 10, 64)
	userID, ok := s.walletSubject(w, claims, requested)
	if !ok {
		return
	}
	wallet, err := s.store.WalletFor(r.Context(), userID)
	if err != nil {
		s.log.Error("wallet lookup", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":       wallet.UserID,
		"balance_cents": wallet.BalanceCents,
		"currency":      wallet.Currency,
	})
}

func (s *Server) handleWalletTransactions(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireScope(w, r, "wallet")
	if !ok {
		return
	}
	requested, _ := strconv.ParseInt(r.URL.Query().Get("user_id"), 10, 64)
	userID, ok := s.walletSubject(w, claims, requested)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.store.Transactions(r.Context(), userID, limit)
	if err != nil {
		s.log.Error("wallet transactions", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]map[string]any, 0, len(entries))
	for _, t := range entries {
		out = append(out, transactionJSON(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (s *Server) handleWalletTopup(w http.ResponseWriter, r *http.Request) {
	s.adjustWallet(w, r, "topup")
}

func (s *Server) handleWalletDebit(w http.ResponseWriter, r *http.Request) {
	s.adjustWallet(w, r, "debit")
}

// adjustWallet handles both directions. Both require wallet.write, because a
// user must not be able to credit their own balance with a read token.
func (s *Server) adjustWallet(w http.ResponseWriter, r *http.Request, kind string) {
	claims, ok := s.requireScope(w, r, "wallet.write")
	if !ok {
		return
	}
	var req walletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "malformed JSON body",
		})
		return
	}
	if req.AmountCents <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "amount_cents must be a positive number; the direction comes from the endpoint",
		})
		return
	}
	userID, ok := s.walletSubject(w, claims, req.UserID)
	if !ok {
		return
	}
	// A top-up is credited only by a service that has already taken the money
	// (a payment gateway callback); a user token must not mint credit.
	if kind == "topup" && !strings.HasPrefix(claims.Subject, "client:") {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":             "access_denied",
			"error_description": "top-ups are credited by the payment service, not by the account itself",
		})
		return
	}

	amount := req.AmountCents
	if kind == "debit" {
		amount = -amount
	}
	if req.Meta == nil {
		req.Meta = map[string]any{}
	}
	// Record who charged the wallet, so a disputed line in the ledger can be
	// traced back to the app that wrote it.
	req.Meta["client_id"] = claims.ClientID

	entry, wallet, err := s.store.Adjust(r.Context(), userID, kind, amount, req.Description, req.Meta, req.IdempotencyKey, false)
	switch {
	case errors.Is(err, store.ErrInsufficientFunds):
		writeJSON(w, http.StatusPaymentRequired, map[string]any{
			"error":             "insufficient_funds",
			"error_description": "the wallet does not hold enough credit for this charge",
			"balance_cents":     wallet.BalanceCents,
		})
		return
	case err != nil:
		s.log.Error("wallet adjust", "error", err, "kind", kind, "user", userID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"transaction":   transactionJSON(entry),
		"balance_cents": wallet.BalanceCents,
		"currency":      wallet.Currency,
	})
}

func transactionJSON(t store.Transaction) map[string]any {
	return map[string]any{
		"id":                  t.ID,
		"type":                t.Type,
		"amount_cents":        t.AmountCents,
		"balance_after_cents": t.BalanceAfterCents,
		"description":         t.Description,
		"meta":                t.Meta,
		"created_at":          t.CreatedAt,
	}
}
