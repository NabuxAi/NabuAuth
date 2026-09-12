package crmintake

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testSecret = "test-nabugate-secret"

func TestSignIsWhatNabuCRMComputes(t *testing.T) {
	body := []byte(`{"event_id":"7f1c2a9e-5d0b-4a8e-9c1f-2b3d4e5f6a7b","event":"signup","person":{"email":"sara@example.com"}}`)

	// php -r 'echo hash_hmac("sha256", "nabuauth:1757671200:".$body, "test-nabugate-secret");'
	want := "015563c1ad20be5a8b3300efe46b7d0d8110f838aeb84e61f054db3e0747bd5d"
	if got := Sign("nabuauth", "1757671200", body, testSecret); got != want {
		t.Fatalf("Sign = %s, want %s", got, want)
	}
}

func TestSignupEventIDIsTheNameBasedUUID(t *testing.T) {
	// python3 -c 'import uuid; print(uuid.uuid5(uuid.NAMESPACE_URL, "nabuauth:user:42:signup"))'
	if got := SignupEventID(42); got != "f612a893-22a6-56f6-85a0-ea7b1cdd0b28" {
		t.Fatalf("SignupEventID(42) = %s", got)
	}
	if SignupEventID(42) == SignupEventID(43) {
		t.Fatal("two accounts share an event id")
	}
}

func TestSignupNamesThePersonButNeverAfterTheirNumber(t *testing.T) {
	created := time.Date(2026, 9, 12, 10, 0, 0, 0, time.FixedZone("Tehran", 12600))

	byEmail := Signup(7, "Sara", "sara@example.com", "", created)
	if byEmail.Event != "signup" || byEmail.EventID != SignupEventID(7) || byEmail.OccurredAt != "2026-09-12T06:30:00Z" {
		t.Fatalf("unexpected event %+v", byEmail)
	}
	if want := map[string]string{"external_id": "7", "email": "sara@example.com", "name": "Sara"}; !reflect.DeepEqual(byEmail.Person, want) {
		t.Fatalf("person = %v, want %v", byEmail.Person, want)
	}

	byPhone := Signup(8, "+989121234567", "", "+989121234567", created)
	if want := map[string]string{"external_id": "8", "phone": "+989121234567"}; !reflect.DeepEqual(byPhone.Person, want) {
		t.Fatalf("person = %v, want %v", byPhone.Person, want)
	}
}

func TestClassify(t *testing.T) {
	for status, want := range map[int]Outcome{
		200: Done, 201: Done,
		429: Retry, 500: Retry, 502: Retry, 503: Retry,
		400: Failed, 403: Failed, 404: Failed, 422: Failed,
	} {
		if got := Classify(status); got != want {
			t.Errorf("Classify(%d) = %s, want %s", status, got, want)
		}
	}
}

func TestBackoffDoublesToACap(t *testing.T) {
	for attempts, want := range map[int]time.Duration{
		1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute,
		9: 256 * time.Minute, 10: 6 * time.Hour, 24: 6 * time.Hour,
	} {
		if got := Backoff(attempts); got != want {
			t.Errorf("Backoff(%d) = %s, want %s", attempts, got, want)
		}
	}
}

type fakeOutbox struct {
	rows    []Row
	claims  int
	status  map[int64]string
	tries   map[int64]int
	next    map[int64]time.Time
	lastErr map[int64]string
}

func newOutbox(rows ...Row) *fakeOutbox {
	return &fakeOutbox{rows: rows, status: map[int64]string{}, tries: map[int64]int{}, next: map[int64]time.Time{}, lastErr: map[int64]string{}}
}

func (f *fakeOutbox) ClaimCRMEvents(_ context.Context, limit int, _ time.Duration) ([]Row, error) {
	f.claims++
	out := f.rows
	f.rows = nil
	return out, nil
}

func (f *fakeOutbox) RetryCRMEvent(_ context.Context, id int64, attempts int, next time.Time, lastErr string) error {
	f.status[id], f.tries[id], f.next[id], f.lastErr[id] = "pending", attempts, next, lastErr
	return nil
}

func (f *fakeOutbox) FinishCRMEvent(_ context.Context, id int64, status string, attempts int, lastErr string) error {
	f.status[id], f.tries[id], f.lastErr[id] = status, attempts, lastErr
	return nil
}

func queuedRow(attempts int) Row {
	payload, _ := json.Marshal(Signup(42, "Sara", "sara@example.com", "", time.Now()))
	return Row{ID: 1, EventID: SignupEventID(42), Payload: payload, Attempts: attempts}
}

// deliverTo runs one pass against a NabuCRM that answers with handler.
func deliverTo(t *testing.T, handler http.HandlerFunc, row Row) (*fakeOutbox, Result) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	outbox := newOutbox(row)
	sender := &Sender{Outbox: outbox, URL: srv.URL + "/api/v1/crm/intake", Secret: testSecret, Client: srv.Client()}
	res, err := sender.DeliverDue(context.Background())
	if err != nil {
		t.Fatalf("DeliverDue: %v", err)
	}
	return outbox, res
}

func TestADeliveredReportIsDoneAndSignedForNabuCRM(t *testing.T) {
	row := queuedRow(0)
	var got *http.Request
	var body []byte
	outbox, res := deliverTo(t, func(w http.ResponseWriter, r *http.Request) {
		got = r
		body = make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		w.WriteHeader(http.StatusCreated)
	}, row)

	if res != (Result{Done: 1}) || outbox.status[1] != "done" || outbox.tries[1] != 1 {
		t.Fatalf("res=%+v status=%s tries=%d", res, outbox.status[1], outbox.tries[1])
	}
	ts := got.Header.Get("X-NabuGate-Timestamp")
	if got.URL.Path != "/api/v1/crm/intake" || got.Header.Get("X-NabuGate-App-Id") != "nabuauth" {
		t.Fatalf("path=%s app=%s", got.URL.Path, got.Header.Get("X-NabuGate-App-Id"))
	}
	if string(body) != string(row.Payload) {
		t.Fatalf("sent %s, queued %s", body, row.Payload)
	}
	if want := Sign("nabuauth", ts, row.Payload, testSecret); got.Header.Get("X-NabuGate-Signature") != want {
		t.Fatal("signature does not cover the timestamp and the exact body sent")
	}
}

func TestAnUnavailableCRMIsTriedAgainLater(t *testing.T) {
	for _, status := range []int{500, 502, 503} {
		before := time.Now()
		outbox, res := deliverTo(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }, queuedRow(0))

		if res != (Result{Retry: 1}) || outbox.status[1] != "pending" || outbox.tries[1] != 1 {
			t.Fatalf("%d: res=%+v status=%s", status, res, outbox.status[1])
		}
		if outbox.next[1].Before(before.Add(time.Minute)) {
			t.Fatalf("%d: retried after %s, want at least a minute", status, outbox.next[1].Sub(before))
		}
		if !strings.HasPrefix(outbox.lastErr[1], "HTTP ") {
			t.Fatalf("%d: last error %q", status, outbox.lastErr[1])
		}
	}
}

func TestAThrottledReportWaitsAsLongAsItWasTold(t *testing.T) {
	before := time.Now()
	outbox, _ := deliverTo(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "900")
		w.WriteHeader(http.StatusTooManyRequests)
	}, queuedRow(0))

	if outbox.status[1] != "pending" || outbox.next[1].Before(before.Add(900*time.Second)) {
		t.Fatalf("status=%s next in %s", outbox.status[1], outbox.next[1].Sub(before))
	}
}

func TestARefusedReportIsFailedAndNotRetried(t *testing.T) {
	for _, status := range []int{400, 403, 422} {
		outbox, res := deliverTo(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }, queuedRow(0))
		if res != (Result{Failed: 1}) || outbox.status[1] != "failed" {
			t.Fatalf("%d: res=%+v status=%s", status, res, outbox.status[1])
		}
	}
}

func TestANetworkFailureIsTriedAgainLater(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens any more

	outbox := newOutbox(queuedRow(0))
	sender := &Sender{Outbox: outbox, URL: url, Secret: testSecret}
	res, err := sender.DeliverDue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res != (Result{Retry: 1}) || !strings.HasPrefix(outbox.lastErr[1], "network: ") {
		t.Fatalf("res=%+v lastErr=%q", res, outbox.lastErr[1])
	}
}

func TestTheLastAttemptGivesUpInsteadOfRetryingForever(t *testing.T) {
	outbox, res := deliverTo(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }, queuedRow(MaxAttempts-1))
	if res != (Result{Failed: 1}) || outbox.status[1] != "failed" || outbox.tries[1] != MaxAttempts {
		t.Fatalf("res=%+v status=%s tries=%d", res, outbox.status[1], outbox.tries[1])
	}
}

func TestWithoutTheSecretNothingIsClaimedOrSent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a report was sent without a secret")
	}))
	defer srv.Close()

	outbox := newOutbox(queuedRow(0))
	sender := &Sender{Outbox: outbox, URL: srv.URL, Secret: ""}
	res, err := sender.DeliverDue(context.Background())
	if err != nil || res != (Result{}) || outbox.claims != 0 || len(outbox.rows) != 1 {
		t.Fatalf("err=%v res=%+v claims=%d left=%d", err, res, outbox.claims, len(outbox.rows))
	}
}
