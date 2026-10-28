package v2raymux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.getoutline.org/sdk/transport"
)

type pipeStream struct{ net.Conn }

func (c pipeStream) CloseRead() error  { return c.Close() }
func (c pipeStream) CloseWrite() error { return c.Close() }

func readTestFrame(c net.Conn) ([]byte, []byte, error) {
	var b [2]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return nil, nil, err
	}
	meta := make([]byte, int(binary.BigEndian.Uint16(b[:])))
	if _, err := io.ReadFull(c, meta); err != nil {
		return nil, nil, err
	}
	var data []byte
	if len(meta) >= 4 && meta[3]&1 != 0 {
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return nil, nil, err
		}
		data = make([]byte, int(binary.BigEndian.Uint16(b[:])))
		if _, err := io.ReadFull(c, data); err != nil {
			return nil, nil, err
		}
	}
	return meta, data, nil
}
func testFrame(id uint16, status, flags byte, data []byte) []byte {
	b := []byte{0, 4, byte(id >> 8), byte(id), status, flags}
	if flags&1 != 0 {
		b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
		b = append(b, data...)
	}
	return b
}
func testPool(t *testing.T, concurrency uint32, handler func(net.Conn)) (*Pool, *atomic.Int64) {
	t.Helper()
	count := &atomic.Int64{}
	e := transport.FuncStreamEndpoint(func(context.Context) (transport.StreamConn, error) {
		client, server := net.Pipe()
		count.Add(1)
		go func() { defer server.Close(); handler(server) }()
		return pipeStream{client}, nil
	})
	p, err := New(e, concurrency, "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p, count
}
func echoFrames(c net.Conn) {
	for {
		meta, data, err := readTestFrame(c)
		if err != nil {
			return
		}
		if meta[2] == 2 {
			if _, err = c.Write(testFrame(binary.BigEndian.Uint16(meta[:2]), 2, 1, data)); err != nil {
				return
			}
		}
	}
}
func openTestStream(t *testing.T, p *Pool) *stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s, err := p.ConnectStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return s.(*stream)
}
func echoTest(s net.Conn) error {
	_ = s.SetDeadline(time.Now().Add(time.Second))
	payload := bytes.Repeat([]byte("wire"), 100)
	if _, err := s.Write(payload); err != nil {
		return err
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(s, reply); err != nil {
		return err
	}
	if !bytes.Equal(payload, reply) {
		return errors.New("wrong payload")
	}
	return nil
}

func TestPoolConcurrentSessionsAndReuse(t *testing.T) {
	p, count := testPool(t, 4, echoFrames)
	streams := make([]*stream, 10)
	for i := range streams {
		streams[i] = openTestStream(t, p)
	}
	if count.Load() != 3 {
		t.Fatalf("expected 3 connections, got %d", count.Load())
	}
	var wg sync.WaitGroup
	for _, s := range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := echoTest(s); err != nil {
				t.Error(err)
			}
			s.Close()
		}()
	}
	wg.Wait()
	s := openTestStream(t, p)
	defer s.Close()
	if err := echoTest(s); err != nil {
		t.Fatal(err)
	}
	if count.Load() != 3 {
		t.Fatal("idle connection was not reused")
	}
}

func TestDeadlinesArePerSessionAndCanChange(t *testing.T) {
	p, _ := testPool(t, 4, echoFrames)
	a, b := openTestStream(t, p), openTestStream(t, p)
	defer a.Close()
	defer b.Close()
	read := make(chan error, 1)
	go func() { _, err := a.Read(make([]byte, 1)); read <- err }()
	a.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-read:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("read deadline did not wake read")
	}
	a.SetReadDeadline(time.Time{})
	if err := echoTest(b); err != nil {
		t.Fatal("peer affected by read deadline", err)
	}
	// Hold the shared writer: a deadline change must wake a queued write only.
	<-a.worker.token
	written := make(chan error, 1)
	go func() { _, err := a.Write([]byte("blocked")); written <- err }()
	a.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-written:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("write deadline did not wake queued write")
	}
	a.worker.token <- struct{}{}
	a.SetWriteDeadline(time.Time{})
	if err := echoTest(a); err != nil {
		t.Fatal(err)
	}
	if err := echoTest(b); err != nil {
		t.Fatal(err)
	}
}

func TestActiveWriteDeadlineChange(t *testing.T) {
	newRead := make(chan struct{})
	release := make(chan struct{})
	p, _ := testPool(t, 1, func(c net.Conn) {
		if _, _, err := readTestFrame(c); err != nil {
			return
		}
		close(newRead)
		<-release
	})
	s := openTestStream(t, p)
	<-newRead
	done := make(chan error, 1)
	go func() { _, err := s.Write([]byte("blocked")); done <- err }()
	s.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("active write ignored changed deadline")
	}
	close(release)
}

func TestSlowSessionDoesNotBlockPeer(t *testing.T) {
	start := make(chan struct{})
	sent := make(chan struct{})
	p, _ := testPool(t, 4, func(c net.Conn) {
		a, _, err := readTestFrame(c)
		if err != nil {
			return
		}
		b, _, err := readTestFrame(c)
		if err != nil {
			return
		}
		<-start
		for i := 0; i < 5; i++ {
			if _, err = c.Write(testFrame(binary.BigEndian.Uint16(a[:2]), 2, 1, make([]byte, 65535))); err != nil {
				return
			}
		}
		if _, err = c.Write(testFrame(binary.BigEndian.Uint16(b[:2]), 2, 1, []byte("peer"))); err != nil {
			return
		}
		close(sent)
		echoFrames(c)
	})
	a, b := openTestStream(t, p), openTestStream(t, p)
	defer a.Close()
	defer b.Close()
	close(start)
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(b, buf); err != nil || string(buf) != "peer" {
		t.Fatalf("stalled stream blocked peer: %q %v", buf, err)
	}
	<-sent
	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	if !closed {
		t.Fatal("overflowing session was not closed")
	}
}

func TestMalformedFramesRetireConnectionAndReconnect(t *testing.T) {
	for _, frame := range [][]byte{{0, 3, 0, 1, 2}, {2, 1}, {0, 4, 0, 1, 9, 0}, {0, 4, 0, 1, 2, 4}, {0, 4, 0, 0, 2, 0}, {0, 4, 0, 9, 2, 0}, {0, 4, 0, 1, 2, 1, 0, 8, 'x'}} {
		t.Run("frame", func(t *testing.T) {
			p, count := testPool(t, 1, func(c net.Conn) {
				if _, _, err := readTestFrame(c); err != nil {
					return
				}
				c.Write(frame)
			})
			s := openTestStream(t, p)
			s.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := s.Read(make([]byte, 1)); err == nil {
				t.Fatal("malformed frame accepted")
			}
			openTestStream(t, p)
			if count.Load() != 2 {
				t.Fatal("failed connection was reused")
			}
		})
	}
}

func TestCloseWakesReadsAndPreventsNewSessions(t *testing.T) {
	p, _ := testPool(t, 4, echoFrames)
	a, b := openTestStream(t, p), openTestStream(t, p)
	a.Close()
	if err := echoTest(b); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := b.Read(make([]byte, 1)); done <- err }()
	p.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed pool read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("pool close stranded reader")
	}
	if _, err := p.ConnectStream(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestCanceledSetupAndIdentifierRetirement(t *testing.T) {
	p, count := testPool(t, 4, echoFrames)
	s := openTestStream(t, p)
	p.mu.Lock()
	s.worker.next = 65535
	p.mu.Unlock()
	s.Close()
	next := openTestStream(t, p)
	defer next.Close()
	if count.Load() != 2 {
		t.Fatal("exhausted identifiers reused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.ConnectStream(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
