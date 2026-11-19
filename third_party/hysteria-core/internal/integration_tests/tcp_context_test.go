package integration_tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/server"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// stallingOutbound never completes TCP dials to stalled, so the server never
// sends a TCP response for them.
type stallingOutbound struct {
	stalled string
	release chan struct{}
}

func (o *stallingOutbound) TCP(reqAddr string) (net.Conn, error) {
	if reqAddr == o.stalled {
		<-o.release
		return nil, errors.New("released")
	}
	return net.Dial("tcp", reqAddr)
}

func (o *stallingOutbound) UDP(string) (server.UDPConn, error) {
	return nil, errors.New("unsupported")
}

func (o *stallingOutbound) CheckUDP(string) error { return nil }

// ephemeralTLSConfig avoids the upstream key fixture, which this snapshot
// does not ship.
func ephemeralTLSConfig(t *testing.T) server.TLSConfig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return server.TLSConfig{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// Bimeron patch: a cancelled TCPContext dial returns promptly and leaves no
// goroutine waiting for the server's TCP response. (Stream credit returns
// only when the server finishes with the reset stream, which this stalling
// server never does, so the test stays below the server's stream limit.)
func TestClientServerTCPContextReleasesStreams(t *testing.T) {
	const dials = 32
	ob := &stallingOutbound{stalled: "203.0.113.1:9", release: make(chan struct{})}
	defer close(ob.release)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	udpAddr := udpConn.LocalAddr()
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     ephemeralTLSConfig(t),
		Conn:          udpConn,
		Authenticator: auth,
		Outbound:      ob,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	echo := &tcpEchoServer{Listener: echoListener}
	defer echo.Close()
	go echo.Serve()

	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()
	dialer, ok := c.(interface {
		TCPContext(context.Context, string) (net.Conn, error)
	})
	if !ok {
		t.Fatal("client does not implement TCPContext")
	}

	baseline := runtime.NumGoroutine()
	for i := 0; i < dials; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		start := time.Now()
		_, err := dialer.TCPContext(ctx, ob.stalled)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("dial %d: %v", i, err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("dial %d ignored cancellation for %v", i, elapsed)
		}
	}
	// Before the patch every abandoned call kept a goroutine in
	// ReadTCPResponse; allow only scheduling noise.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline+dials/4 {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines grew from %d to %d after %d cancelled dials", baseline, runtime.NumGoroutine(), dials)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The connection stays usable.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.TCPContext(ctx, echoListener.Addr().String())
	if err != nil {
		t.Fatalf("dial after cancellations: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte("ping"))
	assert.NoError(t, err)
	buf := make([]byte, 4)
	_, err = conn.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, "ping", string(buf))

	// A context that is already done never opens a stream.
	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	if _, err := dialer.TCPContext(done, echoListener.Addr().String()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
}
