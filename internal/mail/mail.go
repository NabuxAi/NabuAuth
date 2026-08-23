// Package mail carries one-time sign-in codes to an SMTP relay and builds the
// plain-text message that delivers them.
//
// One fact shapes the package: a code is a credential for the few minutes it
// lives, so it never crosses the wire unencrypted — except to a relay on this
// machine, where plaintext exposes it to nobody outside the host. A submission
// server speaks STARTTLS, and one that does not offer it is answered with an
// error rather than a plaintext send. The message itself is plain text and
// nothing else: a sign-in code has no layout worth marking up, and every part
// added to a MIME message is another place a filter can decide it is junk.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"nabuauth/internal/config"
)

// Client sends one-time codes through an SMTP relay.
type Client struct {
	cfg config.Mail
}

// New builds a client for a configured relay.
func New(cfg config.Mail) *Client {
	return &Client{cfg: cfg}
}

// SendCode delivers one code to one address. It returns an error unless the
// relay accepted the message — a form that claims a code is on its way when
// none was sent is the failure every caller of this exists to avoid.
func (c *Client) SendCode(ctx context.Context, to, code string) error {
	addr := net.JoinHostPort(c.cfg.Host, strconv.Itoa(c.cfg.Port))
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("mail: dial %s: %w", addr, err)
	}
	client, err := smtp.NewClient(conn, c.cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("mail: greet %s: %w", addr, err)
	}
	defer client.Close()

	// A stuck relay must not hold a sign-in request open past the point the
	// visitor has already hit the form again.
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	encrypted := false
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: c.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("mail: starttls: %w", err)
		}
		encrypted = true
	} else if !loopback(c.cfg.Host) {
		return errors.New("mail: the relay does not offer STARTTLS, and a code that is a credential while it lives is not sent over plaintext")
	}

	if c.cfg.Username != "" {
		var auth smtp.Auth
		_, mechs := client.Extension("AUTH")
		if !encrypted && strings.Contains(mechs, "CRAM-MD5") {
			// A plaintext hop (a relay on this machine) never sees the password:
			// CRAM-MD5 answers a challenge instead of sending it.
			auth = smtp.CRAMMD5Auth(c.cfg.Username, c.cfg.Password)
		} else {
			// Over TLS the plain mechanism is fine, and net/smtp itself refuses
			// it on a plaintext connection to anywhere but localhost.
			auth = smtp.PlainAuth("", c.cfg.Username, c.cfg.Password, c.cfg.Host)
		}
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("mail: auth: %w", err)
		}
	}

	if err := client.Mail(c.cfg.From); err != nil {
		return fmt.Errorf("mail: from: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("mail: to: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("mail: data: %w", err)
	}
	msg, err := c.message(to, code)
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("mail: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail: deliver: %w", err)
	}
	return client.Quit()
}

// message renders the RFC 5322 message a code goes out in. The headers are the
// set a receiving filter expects — Date, Message-ID, MIME-Version — because a
// message missing them reads as bot traffic, which for a sign-in code means the
// spam folder.
func (c *Client) message(to, code string) ([]byte, error) {
	from := c.cfg.From
	if c.cfg.FromName != "" {
		// The display name is encoded-word safe, so a deployment name in any
		// script survives the trip through ASCII-only headers.
		from = mime.QEncoding.Encode("utf-8", c.cfg.FromName) + " <" + c.cfg.From + ">"
	}

	// A Message-ID the receiving server can trust as unique: random, under the
	// sender's own domain.
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	domain := "localhost"
	if at := strings.IndexByte(c.cfg.From, '@'); at >= 0 {
		domain = c.cfg.From[at+1:]
	}

	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\n", from)
	fmt.Fprintf(&msg, "To: %s\r\n", to)
	fmt.Fprintf(&msg, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", c.cfg.FromName+" sign-in code"))
	fmt.Fprintf(&msg, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&msg, "Message-ID: <%x@%s>\r\n", id, domain)
	fmt.Fprintf(&msg, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&msg, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&msg, "Content-Transfer-Encoding: quoted-printable\r\n")
	fmt.Fprintf(&msg, "\r\n")

	// The wording matches the SMS text: a person who can receive a code by both
	// channels should not have to recognise two phrasings of the same thing.
	qw := quotedprintable.NewWriter(&msg)
	if _, err := fmt.Fprintf(qw, "Your %s sign-in code is %s. It expires in a few minutes.\r\n", c.cfg.FromName, code); err != nil {
		return nil, err
	}
	if err := qw.Close(); err != nil {
		return nil, err
	}
	return msg.Bytes(), nil
}

// loopback reports whether the relay is on this machine, the one case where a
// plaintext hop exposes a code to nobody outside the host.
func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	return net.ParseIP(host).IsLoopback()
}
