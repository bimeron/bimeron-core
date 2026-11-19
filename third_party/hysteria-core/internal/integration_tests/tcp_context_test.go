package integration_tests

import (
	"context"
	"errors"
	"net"
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

// Bimeron patch: cancelled TCPContext dials must reset their streams, so more
// abandoned dials than the server's stream limit never exhaust the connection.
func TestClientServerTCPContextReleasesStreams(t *testing.T) {
	const streamLimit = 8
	ob := &stallingOutbound{stalled: "203.0.113.1:9", release: make(chan struct{})}
	defer close(ob.release)

	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Authenticator: auth,
		Outbound:      ob,
		QUICConfig:    server.QUICConfig{MaxIncomingStreams: streamLimit},
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

	for i := 0; i < 4*streamLimit; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
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

	// Stream credit must have been returned: a normal dial still works.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var conn net.Conn
	for {
		conn, err = dialer.TCPContext(ctx, echoListener.Addr().String())
		if err == nil || ctx.Err() != nil {
			break
		}
		// MAX_STREAMS updates arrive asynchronously after the resets.
		time.Sleep(20 * time.Millisecond)
	}
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
