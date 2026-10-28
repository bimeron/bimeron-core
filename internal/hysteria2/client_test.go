package hysteria2

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	hyerrors "github.com/apernet/hysteria/core/v2/errors"
)

func TestSafeFailureCategories(t *testing.T) {
	secret := "synthetic-secret"
	uri := "hysteria2://" + secret + "@example.invalid:443"
	for _, tc := range []struct {
		name        string
		err         error
		code, stage string
		retry       bool
	}{
		{"timeout", context.DeadlineExceeded, "hysteria2_network_timeout", "connection", true},
		{"dns", &net.DNSError{Err: secret, Name: uri}, "hysteria2_network_failed", "endpoint_resolution", true},
		{"socket", &socketFailure{errors.New(uri)}, "hysteria2_outbound_socket_failed", "outbound_socket", true},
		{"tls", x509.UnknownAuthorityError{}, "hysteria2_tls_failed", "tls", false},
		{"auth", hyerrors.AuthError{StatusCode: 403}, "hysteria2_auth_rejected", "authentication", false},
		{"unknown", errors.New(uri), "hysteria2_unknown", "connection", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failure := classify(fmt.Errorf("wrapped %s: %w", secret, tc.err))
			if failure.Code != tc.code || failure.Stage != tc.stage || failure.Retry != tc.retry {
				t.Fatal(failure)
			}
			if strings.Contains(failure.Error(), secret) || strings.Contains(failure.Error(), uri) {
				t.Fatal("secret leaked")
			}
		})
	}
}

type fakeUDP struct {
	incoming chan packet
	closed   chan struct{}
}

func (f *fakeUDP) Receive() ([]byte, string, error) {
	select {
	case p := <-f.incoming:
		return p.data, p.addr, p.err
	case <-f.closed:
		return nil, "", net.ErrClosed
	}
}
func (*fakeUDP) Send([]byte, string) error { return nil }
func (f *fakeUDP) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func TestPacketDeadlineAndClose(t *testing.T) {
	u := &fakeUDP{incoming: make(chan packet), closed: make(chan struct{})}
	p := &packetConn{upstream: u, changed: make(chan struct{}), done: make(chan struct{}), incoming: make(chan packet, 1)}
	go p.receive()
	if err := p.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err := p.ReadFrom(make([]byte, 16))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("expected timeout, got %v", err)
	}
	if err := p.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	u.incoming <- packet{data: []byte("ok"), addr: "127.0.0.1:53"}
	b := make([]byte, 16)
	n, addr, err := p.ReadFrom(b)
	if err != nil || string(b[:n]) != "ok" || addr.String() != "127.0.0.1:53" {
		t.Fatalf("packet: %q %v %v", b[:n], addr, err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, err = p.ReadFrom(b)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected closed connection, got %v", err)
	}
}
