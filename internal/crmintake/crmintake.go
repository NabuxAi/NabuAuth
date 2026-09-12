// Package crmintake reports new NabuAuth accounts to NabuCRM's intake door.
//
// Every Nabux product signs its users in here, so an account created in
// NabuAuth is the one signup that covers all of them. The store writes the
// report to the crm_outbox table in the same transaction that creates the
// account; Sender delivers it, signed with the secret every Nabux product
// shares with NabuCRM. A NabuCRM redeploy or an unset secret delays a report —
// it never loses one and never slows a sign-in. The contract is NabuCRM's
// docs/crm-intake.md.
package crmintake

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AppID is the name NabuCRM knows this service by (its gate allowed_apps).
const AppID = "nabuauth"

// DefaultURL is NabuCRM's intake endpoint in production.
const DefaultURL = "https://crm.nabuxai.com/api/v1/crm/intake"

// MaxAttempts caps delivery: with Backoff that is about four days of trying
// before a report is given up and marked failed.
const MaxAttempts = 24

// lease keeps a claimed row out of reach so an overlapping pass — or a second
// replica — cannot send the same report twice while the first is in flight.
const lease = 5 * time.Minute

// Sign returns the X-NabuGate-Signature for body: hex HMAC-SHA256 over
// "{app}:{timestamp}:{body}", exactly what NabuCRM's NabuGateService computes.
func Sign(app, timestamp string, body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(app + ":" + timestamp + ":"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// namespaceURL is RFC 4122's URL namespace — the one Python's uuid.NAMESPACE_URL
// names, so the other products' outboxes derive their ids the same way.
var namespaceURL = [16]byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}

// EventID is a name-based (v5) UUID. The same fact always gets the same id, so
// the live hook and the backfill can never report one account twice — neither
// here, where event_id is unique, nor in NabuCRM, which answers a repeat with
// "duplicate".
func EventID(name string) string {
	h := sha1.New()
	h.Write(namespaceURL[:])
	h.Write([]byte(name))
	var u [16]byte
	copy(u[:], h.Sum(nil))
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// SignupEventID is the id of an account's signup report.
func SignupEventID(userID int64) string {
	return EventID(fmt.Sprintf("%s:user:%d:signup", AppID, userID))
}

// Event is one report, in the shape NabuCRM's intake reads.
type Event struct {
	EventID    string            `json:"event_id"`
	Event      string            `json:"event"`
	OccurredAt string            `json:"occurred_at,omitempty"`
	Person     map[string]string `json:"person"`
}

// Signup describes a new account. An account made from a phone number is named
// after the number; that is not a name, so it is left out rather than filed as one.
func Signup(userID int64, name, email, phone string, createdAt time.Time) Event {
	person := map[string]string{"external_id": strconv.FormatInt(userID, 10)}
	if email = strings.TrimSpace(email); email != "" {
		person["email"] = email
	}
	if phone = strings.TrimSpace(phone); phone != "" {
		person["phone"] = phone
	}
	if name = strings.TrimSpace(name); name != "" && name != phone {
		person["name"] = name
	}
	return Event{
		EventID:    SignupEventID(userID),
		Event:      "signup",
		OccurredAt: createdAt.UTC().Format(time.RFC3339),
		Person:     person,
	}
}

// Row is one queued report as the outbox hands it out.
type Row struct {
	ID       int64
	EventID  string
	Payload  []byte
	Attempts int
}

// Outbox is the queue Sender drains. *store.Store implements it.
type Outbox interface {
	ClaimCRMEvents(ctx context.Context, limit int, lease time.Duration) ([]Row, error)
	RetryCRMEvent(ctx context.Context, id int64, attempts int, next time.Time, lastErr string) error
	FinishCRMEvent(ctx context.Context, id int64, status string, attempts int, lastErr string) error
}

// Outcome is what one delivery attempt means for the queued row.
type Outcome string

const (
	Done   Outcome = "done"
	Retry  Outcome = "retry"
	Failed Outcome = "failed"
)

// Classify maps NabuCRM's answer to what happens next. Any 2xx is filed (201)
// or was already filed (200). 429 and 5xx — 503 included, which is NabuCRM not
// configured yet — are worth trying again. Any other 4xx means the report or
// the secret is wrong, and sending it again would be refused the same way.
func Classify(status int) Outcome {
	switch {
	case status >= 200 && status < 300:
		return Done
	case status == http.StatusTooManyRequests || status >= 500:
		return Retry
	default:
		return Failed
	}
}

// Backoff is the wait after the given number of failed attempts: one minute,
// doubling, capped at six hours.
func Backoff(attempts int) time.Duration {
	d := time.Minute
	for i := 1; i < attempts && d < 6*time.Hour; i++ {
		d *= 2
	}
	if d > 6*time.Hour {
		d = 6 * time.Hour
	}
	return d
}

// Sender delivers queued reports to NabuCRM.
type Sender struct {
	Outbox    Outbox
	URL       string
	Secret    string
	Client    *http.Client
	Log       *slog.Logger
	BatchSize int

	warnOnce sync.Once
}

// Result counts what one pass did.
type Result struct{ Done, Retry, Failed int }

// DeliverDue sends every report whose time has come, once.
func (s *Sender) DeliverDue(ctx context.Context) (Result, error) {
	var res Result
	if s.Secret == "" {
		// Rows stay pending: setting the secret later sends everything queued.
		s.warnOnce.Do(func() {
			s.logger().Warn("NABUGATE_SECRET is unset: new accounts are queued for NabuCRM but not sent")
		})
		return res, nil
	}
	batch := s.BatchSize
	if batch <= 0 {
		batch = 20
	}
	rows, err := s.Outbox.ClaimCRMEvents(ctx, batch, lease)
	if err != nil {
		return res, err
	}
	for _, row := range rows {
		attempts := row.Attempts + 1
		outcome, lastErr, wait := s.send(ctx, row)
		if outcome == Retry && attempts >= MaxAttempts {
			outcome = Failed
		}
		switch outcome {
		case Done:
			err = s.Outbox.FinishCRMEvent(ctx, row.ID, string(Done), attempts, "")
			res.Done++
		case Failed:
			s.logger().Warn("NabuCRM intake gave up on a report", "event_id", row.EventID, "error", lastErr)
			err = s.Outbox.FinishCRMEvent(ctx, row.ID, string(Failed), attempts, lastErr)
			res.Failed++
		default:
			d := Backoff(attempts)
			if wait > d {
				d = wait
			}
			err = s.Outbox.RetryCRMEvent(ctx, row.ID, attempts, time.Now().Add(d), lastErr)
			res.Retry++
		}
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// send makes one signed attempt. It signs at send time, not when the report was
// queued: NabuCRM refuses a timestamp older than five minutes, and a report may
// wait days for its turn.
func (s *Sender) send(ctx context.Context, row Row) (Outcome, string, time.Duration) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(row.Payload))
	if err != nil {
		// A malformed CRM_INTAKE_URL is fixable; keep the report until it is.
		return Retry, "request: " + err.Error(), 0
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-NabuGate-App-Id", AppID)
	req.Header.Set("X-NabuGate-Timestamp", ts)
	req.Header.Set("X-NabuGate-Signature", Sign(AppID, ts, row.Payload, s.Secret))

	resp, err := s.client().Do(req)
	if err != nil {
		return Retry, "network: " + err.Error(), 0
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))

	outcome := Classify(resp.StatusCode)
	if outcome == Done {
		return Done, "", 0
	}
	var wait time.Duration
	if resp.StatusCode == http.StatusTooManyRequests {
		if secs, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && secs > 0 {
			wait = time.Duration(secs) * time.Second
		}
	}
	return outcome, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet))), wait
}

// Run delivers on a ticker until ctx ends. A failed pass is logged and the next
// tick tries again; nothing here can stop the server.
func (s *Sender) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := s.DeliverDue(ctx); err != nil && ctx.Err() == nil {
			s.logger().Warn("crm intake delivery pass failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Sender) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (s *Sender) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}
