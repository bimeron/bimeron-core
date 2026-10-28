package anytls

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func pipeSession(t *testing.T) (*session, *stream, net.Conn) {
	t.Helper()
	local, remote := net.Pipe()
	scheme, _ := parsePadding(defaultPadding)
	c := &Client{active: make(map[*session]struct{})}
	s := &session{conn: local, owner: c, scheme: scheme, packet: scheme.stop, done: make(chan struct{})}
	stream := &stream{session: s, id: 1, incoming: make(chan received, 16)}
	s.stream = stream
	c.active[s] = struct{}{}
	t.Cleanup(func() { _ = remote.Close(); s.discard() })
	return s, stream, remote
}

func TestQueuedDataSurvivesTransportFailure(t *testing.T) {
	s, stream, remote := pipeSession(t)
	go s.readLoop()
	if err := writeAll(remote, frame(cmdPSH, stream.id, []byte("last bytes"))); err != nil {
		t.Fatal(err)
	}
	_ = remote.Close()
	<-s.done
	data := make([]byte, 10)
	if _, err := io.ReadFull(stream, data); err != nil || string(data) != "last bytes" {
		t.Fatalf("queued data: %q, %v", data, err)
	}
	if _, err := stream.Read(data); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("terminal error: %v", err)
	}
}

func TestReadPreservesTimeout(t *testing.T) {
	s, stream, remote := pipeSession(t)
	go s.readLoop()
	_ = stream.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err := stream.Read(make([]byte, 1))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("read lost timeout: %v", err)
	}
	_ = stream.SetReadDeadline(time.Time{})
	go func() { _ = writeAll(remote, frame(cmdPSH, stream.id, []byte("ok"))) }()
	data := make([]byte, 2)
	if _, err := io.ReadFull(stream, data); err != nil || string(data) != "ok" {
		t.Fatalf("read after extending deadline: %q, %v", data, err)
	}
}

func TestCanceledOpenDoesNotConsumeIdleSession(t *testing.T) {
	s, _, _ := pipeSession(t)
	s.idleSince = time.Now()
	s.owner.idle = []*session{s}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.owner.open(ctx, "example.com:443"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled open: %v", err)
	}
	if len(s.owner.idle) != 1 {
		t.Fatal("canceled open consumed idle session")
	}
}

func TestCancelUnblocksStreamSetup(t *testing.T) {
	s, _, remote := pipeSession(t)
	s.idleSince = time.Now()
	s.owner.idle = []*session{s}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := s.owner.open(ctx, "example.com:443"); finished <- err }()
	_ = remote.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := remote.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("setup cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled setup remained blocked")
	}
}

func TestClosedStreamCannotAffectReusedSession(t *testing.T) {
	s, old, _ := pipeSession(t)
	old.readEnd = true
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	reused, err := s.owner.acquire(context.Background())
	if err != nil || reused != s {
		t.Fatalf("session reuse: %p, %v", reused, err)
	}
	if err := old.CloseRead(); err != nil {
		t.Fatal(err)
	}
	if err := old.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed deadline accepted: %v", err)
	}
	select {
	case <-s.done:
		t.Fatal("old stream closed reused session")
	default:
	}
}

func TestCloseWriteUnblocksRead(t *testing.T) {
	s, stream, _ := pipeSession(t)
	go s.readLoop()
	reading := make(chan error, 1)
	go func() { _, err := stream.Read(make([]byte, 1)); reading <- err }()
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-reading:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("read after full close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CloseWrite left read blocked")
	}
}

type blockedCloseConn struct {
	net.Conn
	entered, release chan struct{}
}

func (c *blockedCloseConn) Close() error { close(c.entered); <-c.release; return c.Conn.Close() }

func TestDiscardDoesNotHoldPoolLockDuringClose(t *testing.T) {
	s, _, _ := pipeSession(t)
	conn := &blockedCloseConn{Conn: s.conn, entered: make(chan struct{}), release: make(chan struct{})}
	s.conn = conn
	defer close(conn.release)
	go s.discard()
	<-conn.entered
	if !s.owner.mu.TryLock() {
		t.Fatal("network Close holds client pool lock")
	}
	s.owner.mu.Unlock()
}

func TestCloseUnblocksWrite(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	scheme, _ := parsePadding(defaultPadding)
	c := &Client{active: make(map[*session]struct{})}
	s := &session{conn: local, owner: c, scheme: scheme, done: make(chan struct{})}
	c.active[s] = struct{}{}
	stream := &stream{session: s}
	go func() { _, _ = stream.Write([]byte("blocked")) }()
	_ = remote.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := remote.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { _ = stream.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		_ = local.Close()
		t.Fatal("Close did not unblock Write")
	}
}

func TestIdleSessionHandlesControlFrames(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	scheme, err := parsePadding(defaultPadding)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{padding: scheme, active: make(map[*session]struct{})}
	s := &session{conn: local, owner: c, scheme: scheme, packet: scheme.stop, done: make(chan struct{})}
	c.active[s] = struct{}{}
	go s.readLoop()
	defer s.discard()
	_ = remote.SetDeadline(time.Now().Add(2 * time.Second))
	if err := writeAll(remote, frame(cmdHeartRequest, 0, nil)); err != nil {
		t.Fatal(err)
	}
	command, _, _, err := readFrame(remote)
	if err != nil || command != cmdHeartResponse {
		t.Fatalf("idle heartbeat response: %d, %v", command, err)
	}
	updated := "stop=2\n0=31-31\n1=50-50"
	if err := writeAll(remote, frame(cmdUpdatePadding, 0, []byte(updated))); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := c.padding.text
		c.mu.Unlock()
		if got == updated {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("idle padding update not applied")
}
