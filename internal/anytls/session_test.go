package anytls

import (
	"net"
	"testing"
	"time"
)

func TestCloseUnblocksWrite(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	scheme, _ := parsePadding(defaultPadding)
	c := &Client{active: make(map[*session]struct{})}
	s := &session{conn: local, owner: c, scheme: scheme, done: make(chan struct{})}
	c.active[s] = struct{}{}
	stream := &stream{session: s}
	writing := make(chan struct{})
	go func() { close(writing); _, _ = stream.Write([]byte("blocked")) }()
	<-writing
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
