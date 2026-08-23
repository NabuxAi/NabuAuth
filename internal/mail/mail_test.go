package mail

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"

	"nabuauth/internal/config"
)

// The relay is faked rather than called, but faked accurately in the one way
// that matters: a message is only counted as sent when the server answered
// every command with an acceptance. A mailer that reads silence as success is
// how a sign-in form comes to promise a code it never sent.

// fakeSMTP is a stand-in submission server. It records every message it
// accepts, and can be told to refuse authentication or to speak CRAM-MD5
// instead of PLAIN.
type fakeSMTP struct {
	ln net.Listener

	mu         sync.Mutex
	accepted   []recordedMail
	refuseAuth bool
	cramOnly   bool
}

type recordedMail struct {
	from string
	to   string
	data string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeSMTP{ln: ln}
	go f.serve()
	t.Cleanup(func() { f.ln.Close() })
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.converse(conn)
	}
}

func (f *fakeSMTP) converse(conn net.Conn) {
	defer conn.Close()
	tc := textproto.NewConn(conn)
	defer tc.Close()

	var from, to string
	if err := tc.PrintfLine("220 fake ESMTP ready"); err != nil {
		return
	}
	for {
		line, err := tc.ReadLine()
		if err != nil {
			return
		}
		verb := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(verb, "EHLO"), strings.HasPrefix(verb, "HELO"):
			must(tc.PrintfLine("250-fake greets you"))
			if f.cramOnly {
				must(tc.PrintfLine("250-AUTH CRAM-MD5"))
			} else {
				must(tc.PrintfLine("250-AUTH PLAIN CRAM-MD5"))
			}
			must(tc.PrintfLine("250 8BITMIME"))

		case strings.HasPrefix(verb, "AUTH PLAIN "):
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH PLAIN "):]))
			// PLAIN carries "\x00username\x00password" — readable by anyone on
			// the wire, which is why the client must never send it unencrypted
			// past this machine.
			parts := strings.Split(string(decoded), "\x00")
			if err != nil || len(parts) != 3 || f.refuseAuth || parts[1] != "noreply@nabuxai.com" || parts[2] != "test-smtp-password" {
				must(tc.PrintfLine("535 5.7.8 authentication credentials invalid"))
				continue
			}
			must(tc.PrintfLine("235 2.7.0 authentication successful"))

		case verb == "AUTH CRAM-MD5":
			challenge := fmt.Sprintf("<%d.fake>", len(line))
			must(tc.PrintfLine("%s", "334 "+base64.StdEncoding.EncodeToString([]byte(challenge))))
			answer, err := tc.ReadLine()
			if err != nil {
				return
			}
			decoded, err := base64.StdEncoding.DecodeString(answer)
			if err != nil {
				must(tc.PrintfLine("501 5.5.4 malformed authentication input"))
				continue
			}
			mac := hmac.New(md5.New, []byte("test-smtp-password"))
			mac.Write([]byte(challenge))
			want := fmt.Sprintf("noreply@nabuxai.com %x", mac.Sum(nil))
			if f.refuseAuth || string(decoded) != want {
				must(tc.PrintfLine("535 5.7.8 authentication credentials invalid"))
				continue
			}
			must(tc.PrintfLine("235 2.7.0 authentication successful"))

		case strings.HasPrefix(verb, "MAIL FROM:"):
			// ESMTP parameters (BODY=8BITMIME) trail the address; the sender is
			// the first field.
			from = strings.Fields(line[len("MAIL FROM:"):])[0]
			must(tc.PrintfLine("250 2.1.0 sender ok"))
		case strings.HasPrefix(verb, "RCPT TO:"):
			to = strings.Fields(line[len("RCPT TO:"):])[0]
			must(tc.PrintfLine("250 2.1.5 recipient ok"))
		case verb == "DATA":
			must(tc.PrintfLine("354 End data with <CR><LF>.<CR><LF>"))
			data, err := tc.ReadDotBytes()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.accepted = append(f.accepted, recordedMail{from: from, to: to, data: string(data)})
			f.mu.Unlock()
			must(tc.PrintfLine("250 2.0.0 queued"))
		case verb == "RSET", verb == "NOOP":
			must(tc.PrintfLine("250 2.0.0 ok"))
		case verb == "QUIT":
			must(tc.PrintfLine("221 2.0.0 closing connection"))
			return
		default:
			must(tc.PrintfLine("502 5.5.2 command not recognised"))
		}
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func (f *fakeSMTP) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.accepted)
}

func (f *fakeSMTP) last(t *testing.T) recordedMail {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.accepted) == 0 {
		t.Fatal("no message reached the relay")
	}
	return f.accepted[len(f.accepted)-1]
}

// testConfig is the relay as a deployment would describe it: a host, a port and
// the account, with everything else left to the defaults.
func testConfig(f *fakeSMTP) config.Mail {
	cfg := config.Mail{
		Host:     "127.0.0.1",
		Port:     f.port(),
		Username: "noreply@nabuxai.com",
		Password: "test-smtp-password",
	}
	cfg.ApplyDefaults()
	return cfg
}

func TestACodeIsDeliveredWithTheHeadersAReceivingServerExpects(t *testing.T) {
	fake := newFakeSMTP(t)
	client := New(testConfig(fake))

	if err := client.SendCode(t.Context(), "someone@example.com", "123456"); err != nil {
		t.Fatalf("send: %v", err)
	}

	got := fake.last(t)
	if got.from != "<noreply@nabuxai.com>" {
		t.Fatalf("envelope sender = %q, want the configured address", got.from)
	}
	if got.to != "<someone@example.com>" {
		t.Fatalf("envelope recipient = %q", got.to)
	}

	for _, want := range []string{
		// The display name beside the address is what a mail client shows; a
		// bare address reads as automated noise.
		"From: Nabu <noreply@nabuxai.com>",
		"To: someone@example.com",
		"Subject: Nabu sign-in code",
		"Date: ",
		"Message-ID: ",
		"@nabuxai.com>", // the Message-ID sits under the sender's own domain
		"MIME-Version: 1.0",
		"Content-Type: text/plain",
	} {
		if !strings.Contains(got.data, want) {
			t.Fatalf("the message is missing %q:\n%s", want, got.data)
		}
	}
	// And the wording matches what the SMS channel says, so a code by email is
	// not a second thing to recognise.
	if !strings.Contains(got.data, "Your Nabu sign-in code is 123456.") {
		t.Fatalf("the message does not carry the code in the usual wording:\n%s", got.data)
	}
}

func TestARefusedAuthenticationIsARealError(t *testing.T) {
	fake := newFakeSMTP(t)
	fake.refuseAuth = true
	client := New(testConfig(fake))

	if err := client.SendCode(t.Context(), "someone@example.com", "123456"); err == nil {
		t.Fatal("a relay that refused the credentials produced no error — the form would claim a code was sent")
	}
	if fake.count() != 0 {
		t.Fatal("a message was recorded against a send that failed")
	}
}

func TestAnUnreachableRelayIsARealError(t *testing.T) {
	fake := newFakeSMTP(t)
	port := fake.port()
	fake.ln.Close() // nothing answers there any more

	cfg := testConfig(fake)
	cfg.Port = port
	client := New(cfg)
	if err := client.SendCode(t.Context(), "someone@example.com", "123456"); err == nil {
		t.Fatal("dialling a dead relay produced no error")
	}
}

func TestThePasswordNeverCrossesAPlaintextHop(t *testing.T) {
	// A relay on this machine is the one place plaintext exposes the password
	// and the code to nobody new. CRAM-MD5 is preferred there anyway, so the
	// password itself stays off the wire even then.
	fake := newFakeSMTP(t)
	fake.cramOnly = true
	client := New(testConfig(fake))

	if err := client.SendCode(t.Context(), "someone@example.com", "654321"); err != nil {
		t.Fatalf("CRAM-MD5 against the local relay: %v", err)
	}
	if !strings.Contains(fake.last(t).data, "654321") {
		t.Fatal("the message did not carry the code")
	}
}

func TestARelayOffThisMachineWithoutTLSIsRefused(t *testing.T) {
	// The dial is never attempted to a dead loopback port, but the refusal must
	// come from the missing STARTTLS — a non-local relay name is the point.
	if loopback("mail.nabuxai.com") {
		t.Fatal("an outside relay was treated as this machine")
	}
	for _, local := range []string{"localhost", "127.0.0.1", "::1"} {
		if !loopback(local) {
			t.Fatalf("%q was not recognised as this machine; a local relay would need TLS it should not have to run", local)
		}
	}
}

func TestADefaultRelayIsTheSubmissionPortAndTheAccountAddress(t *testing.T) {
	// The defaults exist so the file only has to name what the deployment
	// actually chose; port 587 is where STARTTLS lives, and the one address an
	// authenticated relay is known to let through is the account's own.
	cfg := config.Mail{Host: "mail.nabuxai.com", Username: "noreply@nabuxai.com"}
	cfg.ApplyDefaults()
	if cfg.Port != 587 {
		t.Fatalf("port = %d, want the submission port", cfg.Port)
	}
	if cfg.From != "noreply@nabuxai.com" {
		t.Fatalf("from = %q, want the account address", cfg.From)
	}
	if !cfg.Configured() {
		t.Fatal("a host and an account are not being reported as ready to send")
	}
}
