package vless

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPCHunkStream(t *testing.T) {
	listener := bufconn.Listen(64 * 1024)
	server := grpc.NewServer(grpc.ForceServerCodec(hunkCodec{}))
	desc := &grpc.ServiceDesc{ServiceName: "test", HandlerType: (*grpcEcho)(nil), Streams: []grpc.StreamDesc{{StreamName: "Tun", ClientStreams: true, ServerStreams: true, Handler: func(_ any, stream grpc.ServerStream) error {
		for {
			var message hunk
			if err := stream.RecvMsg(&message); err != nil {
				return err
			}
			if err := stream.SendMsg(&message); err != nil {
				return err
			}
		}
	}}}}
	server.RegisterService(desc, grpcEchoServer{})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithDefaultCallOptions(grpc.ForceCodec(hunkCodec{})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, "/test/Tun")
	if err != nil {
		t.Fatal(err)
	}
	g := &grpcStreamConn{stream: stream, cancel: cancel, remote: grpcAddr("test")}
	defer g.Close()
	if n, err := g.Write([]byte("grpc-ok")); err != nil || n != 7 {
		t.Fatalf("write: %d %v", n, err)
	}
	var got [7]byte
	if _, err := io.ReadFull(g, got[:]); err != nil || string(got[:]) != "grpc-ok" {
		t.Fatalf("read: %q %v", got, err)
	}
	if err := g.CloseWrite(); err != nil {
		t.Fatal(err)
	}
}

func TestGRPCMethod(t *testing.T) {
	for input, want := range map[string]string{"proxy": "/proxy/Tun", "/proxy/Custom": "/proxy/Custom", "/nested/proxy/Tun": "/nested/proxy/Tun"} {
		if got := grpcMethod(input, false); got != want {
			t.Fatalf("method for %q: got %q, want %q", input, got, want)
		}
	}
	if got := grpcMethod("proxy", true); got != "/proxy/TunMulti" {
		t.Fatalf("multi method: %q", got)
	}
}

func TestGRPCMultiHunkCodec(t *testing.T) {
	codec := multiHunkCodec{}
	var got hunk
	if err := codec.Unmarshal([]byte{0x0a, 2, 'o', 'k', 0x0a, 1, '!'}, &got); err != nil || string(got.data) != "ok!" {
		t.Fatalf("decode multi hunk: %q %v", got.data, err)
	}
	b, err := codec.Marshal(&hunk{data: []byte("ok")})
	if err != nil || string(b) != string([]byte{0x0a, 2, 'o', 'k'}) {
		t.Fatalf("encode multi hunk: %x %v", b, err)
	}
}

func TestGRPCMultiHunkStream(t *testing.T) {
	listener := bufconn.Listen(64 * 1024)
	server := grpc.NewServer(grpc.ForceServerCodec(multiHunkCodec{}))
	desc := &grpc.ServiceDesc{ServiceName: "test", HandlerType: (*grpcEcho)(nil), Streams: []grpc.StreamDesc{{StreamName: "TunMulti", ClientStreams: true, ServerStreams: true, Handler: func(_ any, stream grpc.ServerStream) error {
		var message hunk
		if err := stream.RecvMsg(&message); err != nil {
			return err
		}
		return stream.SendMsg(&message)
	}}}}
	server.RegisterService(desc, grpcEchoServer{})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithDefaultCallOptions(grpc.ForceCodec(multiHunkCodec{})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, grpcMethod("test", true))
	if err != nil {
		t.Fatal(err)
	}
	g := &grpcStreamConn{stream: stream, cancel: cancel, remote: grpcAddr("test")}
	defer g.Close()
	if _, err := g.Write([]byte("multi-ok")); err != nil {
		t.Fatal(err)
	}
	var got [8]byte
	if _, err := io.ReadFull(g, got[:]); err != nil || string(got[:]) != "multi-ok" {
		t.Fatalf("multi stream: %q %v", got, err)
	}
}

type grpcEcho interface{ echo() }
type grpcEchoServer struct{}

func (grpcEchoServer) echo() {}
