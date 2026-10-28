package vless

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"bimeron/internal/streamtransport"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
)

// A gRPC Hunk has one protobuf bytes field. Keeping the codec here avoids
// importing generated Xray types and their dependency graph.
type hunk struct{ data []byte }
type hunkCodec struct{}
type multiHunkCodec struct{ hunkCodec }

func (multiHunkCodec) Name() string { return "proto" }

func (hunkCodec) Name() string { return "proto" }
func (hunkCodec) Marshal(v any) ([]byte, error) {
	h, ok := v.(*hunk)
	if !ok {
		return nil, errors.New("invalid gRPC hunk")
	}
	b := []byte{0x0a}
	b = binary.AppendUvarint(b, uint64(len(h.data)))
	return append(b, h.data...), nil
}
func (hunkCodec) Unmarshal(b []byte, v any) error {
	h, ok := v.(*hunk)
	if !ok {
		return errors.New("invalid gRPC hunk")
	}
	if len(b) == 0 {
		h.data = nil
		return nil
	}
	if b[0] != 0x0a {
		return errors.New("invalid gRPC hunk")
	}
	n, used := binary.Uvarint(b[1:])
	if used <= 0 || n > uint64(len(b)-1-used) || int(n) != len(b)-1-used {
		return errors.New("invalid gRPC hunk")
	}
	h.data = append(h.data[:0], b[1+used:]...)
	return nil
}

func (multiHunkCodec) Unmarshal(b []byte, v any) error {
	h, ok := v.(*hunk)
	if !ok {
		return errors.New("invalid gRPC multi hunk")
	}
	h.data = h.data[:0]
	for len(b) > 0 {
		if b[0] != 0x0a {
			return errors.New("invalid gRPC multi hunk")
		}
		n, used := binary.Uvarint(b[1:])
		if used <= 0 || n > uint64(len(b)-1-used) {
			return errors.New("invalid gRPC multi hunk")
		}
		h.data = append(h.data, b[1+used:1+used+int(n)]...)
		b = b[1+used+int(n):]
	}
	return nil
}

func (c *Client) grpcStream(ctx context.Context) (net.Conn, error) {
	conn, err := c.grpcClient()
	if err != nil {
		return nil, err
	}
	address := net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port))
	// Callers cancel their setup context as soon as DialStream returns.
	// The stream therefore has its own lifetime, ended by Close.
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	setupTimer := time.AfterFunc(15*time.Second, cancel)
	stream, err := conn.NewStream(streamCtx, &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, grpcMethod(c.settings.GRPCServiceName, c.settings.GRPCMultiMode))
	setupTimer.Stop()
	if err != nil {
		cancel()
		return nil, err
	}
	return &grpcStreamConn{stream: stream, cancel: cancel, remote: grpcAddr(address)}, nil
}

func grpcMethod(serviceName string, multi bool) string {
	if strings.HasPrefix(serviceName, "/") {
		parts := strings.Split(strings.TrimPrefix(serviceName, "/"), "/")
		for i := range parts {
			parts[i] = url.PathEscape(parts[i])
		}
		return "/" + strings.Join(parts, "/")
	}
	method := "Tun"
	if multi {
		method = "TunMulti"
	}
	return "/" + url.PathEscape(serviceName) + "/" + method
}

func (c *Client) grpcClient() (*grpc.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.grpcConn != nil {
		return c.grpcConn, nil
	}
	address := net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port))
	name := c.settings.ServerName
	if name == "" {
		name = c.endpoint.Host
	}
	if c.settings.GRPCAuthority != "" {
		name = c.settings.GRPCAuthority
	}
	var codec encoding.Codec = hunkCodec{}
	if c.settings.GRPCMultiMode {
		codec = multiHunkCodec{}
	}
	conn, err := grpc.NewClient("passthrough:///"+address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithAuthority(name),
		grpc.WithContextDialer(func(dialCtx context.Context, _ string) (net.Conn, error) {
			raw, err := streamtransport.Dial(dialCtx, c.dialer, address, c.shadowTLS, c.rootCAs)
			if err != nil {
				return nil, err
			}
			var secure net.Conn
			if c.settings.Security == "reality" {
				secure, err = realityHandshake(dialCtx, raw, c.settings, c.publicKey, c.shortID)
			} else {
				secure, err = c.tlsHandshake(dialCtx, raw)
			}
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			return secure, nil
		}),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(codec)),
	)
	if err != nil {
		return nil, err
	}
	c.grpcConn = conn
	return conn, nil
}

type grpcAddr string

func (a grpcAddr) Network() string { return "tcp" }
func (a grpcAddr) String() string  { return string(a) }

type grpcStreamConn struct {
	stream   grpc.ClientStream
	cancel   context.CancelFunc
	remote   net.Addr
	mu       sync.Mutex
	read     []byte
	deadline *time.Timer
	once     sync.Once
}

func (g *grpcStreamConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	g.mu.Lock()
	if len(g.read) > 0 {
		n := copy(p, g.read)
		g.read = g.read[n:]
		g.mu.Unlock()
		return n, nil
	}
	g.mu.Unlock()
	for {
		var message hunk
		if err := g.stream.RecvMsg(&message); err != nil {
			return 0, err
		}
		if len(message.data) == 0 {
			continue
		}
		n := copy(p, message.data)
		g.mu.Lock()
		g.read = message.data[n:]
		g.mu.Unlock()
		return n, nil
	}
}
func (g *grpcStreamConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), 16*1024)
		if err := g.stream.SendMsg(&hunk{data: p[:n]}); err != nil {
			return written, err
		}
		p = p[n:]
		written += n
	}
	return written, nil
}
func (g *grpcStreamConn) Close() error {
	g.once.Do(func() {
		g.mu.Lock()
		if g.deadline != nil {
			g.deadline.Stop()
		}
		g.mu.Unlock()
		g.cancel()
		_ = g.stream.CloseSend()
	})
	return nil
}
func (g *grpcStreamConn) CloseWrite() error    { return g.stream.CloseSend() }
func (g *grpcStreamConn) LocalAddr() net.Addr  { return grpcAddr("local") }
func (g *grpcStreamConn) RemoteAddr() net.Addr { return g.remote }
func (g *grpcStreamConn) SetDeadline(t time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.deadline != nil {
		g.deadline.Stop()
		g.deadline = nil
	}
	if !t.IsZero() {
		g.deadline = time.AfterFunc(max(0, time.Until(t)), g.cancel)
	}
	return nil
}
func (g *grpcStreamConn) SetReadDeadline(t time.Time) error  { return g.SetDeadline(t) }
func (g *grpcStreamConn) SetWriteDeadline(t time.Time) error { return g.SetDeadline(t) }

var _ net.Conn = (*grpcStreamConn)(nil)
var _ io.Closer = (*grpcStreamConn)(nil)
