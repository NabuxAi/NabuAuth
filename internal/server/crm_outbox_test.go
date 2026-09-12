package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"nabuauth/internal/crmintake"
	"nabuauth/internal/store"
)

type outboxRow struct {
	EventID, Event, Payload, Status string
	Attempts                        int
}

func outboxRows(t *testing.T, st *store.Store) []outboxRow {
	t.Helper()
	rows, err := st.DB().QueryContext(context.Background(), `SELECT event_id, event, payload, status, attempts FROM crm_outbox ORDER BY id`)
	if err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	defer rows.Close()
	var out []outboxRow
	for rows.Next() {
		var r outboxRow
		if err := rows.Scan(&r.EventID, &r.Event, &r.Payload, &r.Status, &r.Attempts); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, r)
	}
	return out
}

func reportingOn(t *testing.T, st *store.Store) {
	t.Helper()
	st.ReportSignups(true, func(err error) { t.Errorf("signup report not queued: %v", err) })
}

func TestANewAccountQueuesExactlyOneSignupReport(t *testing.T) {
	_, st := newTestServer(t)
	reportingOn(t, st)

	u := seedUser(t, st, "sara@example.com", "password-123")

	rows := outboxRows(t, st)
	if len(rows) != 1 {
		t.Fatalf("queued %d reports, want 1", len(rows))
	}
	r := rows[0]
	if r.EventID != crmintake.SignupEventID(u.ID) || r.Event != "signup" || r.Status != "pending" || r.Attempts != 0 {
		t.Fatalf("unexpected row %+v", r)
	}
	var event crmintake.Event
	if err := json.Unmarshal([]byte(r.Payload), &event); err != nil {
		t.Fatalf("payload: %v", err)
	}
	want := map[string]string{"external_id": itoa(u.ID), "email": "sara@example.com", "name": "Test User"}
	if !reflect.DeepEqual(event.Person, want) || event.EventID != r.EventID {
		t.Fatalf("person = %v, want %v", event.Person, want)
	}
}

func TestAnAdministratorIsNotReportedAsASignup(t *testing.T) {
	_, st := newTestServer(t)
	reportingOn(t, st)

	if _, err := st.CreateUser(context.Background(), "Staff", "staff@nabuxai.com", "", "x", true); err != nil {
		t.Fatal(err)
	}
	if rows := outboxRows(t, st); len(rows) != 0 {
		t.Fatalf("an administrator was reported: %+v", rows)
	}
}

func TestWithReportingOffNothingIsQueued(t *testing.T) {
	_, st := newTestServer(t)

	seedUser(t, st, "quiet@example.com", "password-123")

	if rows := outboxRows(t, st); len(rows) != 0 {
		t.Fatalf("queued %d reports with reporting off", len(rows))
	}
}

func TestABrokenOutboxNeverStopsAnAccountBeingCreated(t *testing.T) {
	_, st := newTestServer(t)
	ctx := context.Background()
	if _, err := st.DB().ExecContext(ctx, `ALTER TABLE crm_outbox RENAME TO crm_outbox_away`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = st.DB().ExecContext(ctx, `ALTER TABLE crm_outbox_away RENAME TO crm_outbox`) })

	var heard error
	st.ReportSignups(true, func(err error) { heard = err })

	u, err := st.CreateUser(ctx, "Sara", "sara@example.com", "", "x", false)
	if err != nil {
		t.Fatalf("account creation failed because the outbox did: %v", err)
	}
	if _, err := st.UserByID(ctx, u.ID); err != nil {
		t.Fatalf("account was not committed: %v", err)
	}
	if heard == nil {
		t.Fatal("the failed report was not reported")
	}
}

func TestTheBackfillIsIdempotentAndAgreesWithTheLiveHook(t *testing.T) {
	_, st := newTestServer(t)
	ctx := context.Background()

	// Two accounts from before reporting existed, an administrator, then one live.
	seedUser(t, st, "old1@example.com", "password-123")
	seedUser(t, st, "old2@example.com", "password-123")
	if _, err := st.CreateUser(ctx, "Staff", "staff@nabuxai.com", "", "x", true); err != nil {
		t.Fatal(err)
	}
	reportingOn(t, st)
	seedUser(t, st, "new@example.com", "password-123")

	queued, total, err := st.QueueSignupBackfill(ctx)
	if err != nil || queued != 2 || total != 3 {
		t.Fatalf("first backfill: queued=%d total=%d err=%v, want 2 of 3", queued, total, err)
	}
	queued, total, err = st.QueueSignupBackfill(ctx)
	if err != nil || queued != 0 || total != 3 {
		t.Fatalf("second backfill: queued=%d total=%d err=%v, want 0 of 3", queued, total, err)
	}
	if rows := outboxRows(t, st); len(rows) != 3 {
		t.Fatalf("%d rows, want one per non-admin account", len(rows))
	}
}

func TestTheQueueHandsOutEachReportOnceAndBringsBackTheRefused(t *testing.T) {
	_, st := newTestServer(t)
	ctx := context.Background()
	reportingOn(t, st)
	seedUser(t, st, "sara@example.com", "password-123")

	rows, err := st.ClaimCRMEvents(ctx, 10, time.Minute)
	if err != nil || len(rows) != 1 || rows[0].Attempts != 0 {
		t.Fatalf("claim: %v %+v", err, rows)
	}
	if again, _ := st.ClaimCRMEvents(ctx, 10, time.Minute); len(again) != 0 {
		t.Fatal("a claimed report was handed out again inside its lease")
	}

	if err := st.RetryCRMEvent(ctx, rows[0].ID, 1, time.Now().Add(-time.Second), "HTTP 503"); err != nil {
		t.Fatal(err)
	}
	due, _ := st.ClaimCRMEvents(ctx, 10, time.Minute)
	if len(due) != 1 || due[0].Attempts != 1 {
		t.Fatalf("a report whose backoff ended was not handed out: %+v", due)
	}

	if err := st.FinishCRMEvent(ctx, rows[0].ID, "failed", 2, "HTTP 422"); err != nil {
		t.Fatal(err)
	}
	if n, err := st.RequeueFailedCRMEvents(ctx); err != nil || n != 1 {
		t.Fatalf("requeue: n=%d err=%v", n, err)
	}
	if back, _ := st.ClaimCRMEvents(ctx, 10, time.Minute); len(back) != 1 || back[0].Attempts != 0 {
		t.Fatalf("requeued report not handed out fresh: %+v", back)
	}
}

func TestTheSenderDeliversAQueuedAccountToNabuCRM(t *testing.T) {
	_, st := newTestServer(t)
	reportingOn(t, st)
	u := seedUser(t, st, "sara@example.com", "password-123")

	var gotSig, gotTS string
	var gotBody []byte
	crm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig, gotTS = r.Header.Get("X-NabuGate-Signature"), r.Header.Get("X-NabuGate-Timestamp")
		gotBody = make([]byte, r.ContentLength)
		_, _ = r.Body.Read(gotBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer crm.Close()

	sender := &crmintake.Sender{Outbox: st, URL: crm.URL, Secret: "test-nabugate-secret", Client: crm.Client()}
	res, err := sender.DeliverDue(context.Background())
	if err != nil || res != (crmintake.Result{Done: 1}) {
		t.Fatalf("deliver: res=%+v err=%v", res, err)
	}
	if gotSig != crmintake.Sign("nabuauth", gotTS, gotBody, "test-nabugate-secret") {
		t.Fatal("the report was not signed over the exact bytes sent")
	}
	rows := outboxRows(t, st)
	if rows[0].Status != "done" || rows[0].Attempts != 1 || rows[0].EventID != crmintake.SignupEventID(u.ID) {
		t.Fatalf("row after delivery: %+v", rows[0])
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
