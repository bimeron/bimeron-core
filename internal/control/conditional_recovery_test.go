package control

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestExpiredRecoveryInspection(t *testing.T) {
	s := NewServer(&holdEngine{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	earliestDeadline := time.Now().Add(5 * time.Second)
	s.ConditionalRecovery = func(ctx context.Context, _ string) (string, string) {
		deadline, ok := ctx.Deadline()
		if !ok || deadline.Before(earliestDeadline) || deadline.After(time.Now().Add(5*time.Second)) {
			t.Fatal("unexpected inspection deadline", deadline)
		}
		cancel()
		return strings.Repeat("a", 64), "eligible"
	}
	if s.inspectRecovery(ctx) != nil {
		t.Fatal("expired proof authorized recovery")
	}
}

func TestConditionalRecoveryAdmission(t *testing.T) {
	ctx := context.Background()
	s := NewServer(&holdEngine{})
	peer := fakeWatch{alive: true}
	good := RecoveryIdentity{"system", s.instance, strings.Repeat("d", 64)}
	effects := 0
	s.ConditionalRecovery = func(_ context.Context, g string) (string, string) {
		if s.command.TryLock() {
			s.command.Unlock()
			t.Fatal("update admission open during recovery")
		}
		if g == "" {
			return good.Generation, "eligible"
		}
		if g != good.Generation {
			return "", "conflict"
		}
		effects++
		return g, "recovered"
	}
	if got := s.inspectRecovery(ctx); got == nil || *got != good {
		t.Fatalf("missing positive identity: %v", got)
	}
	for _, i := range []RecoveryIdentity{{"developer", good.Instance, good.Generation}, {"system", strings.Repeat("0", 32), good.Generation}, {"system", good.Instance, strings.Repeat("e", 64)}} {
		if got := s.recoverConditionally(ctx, &i, peer); got != "conflict" {
			t.Fatal(got)
		}
	}
	if got := s.recoverConditionally(ctx, &good, nil); got != "unknown" {
		t.Fatal(got)
	}
	s.hold = &updateHold{}
	if s.inspectRecovery(ctx) != nil || s.recoverConditionally(ctx, &good, peer) != "conflict" || effects != 0 {
		t.Fatal("pending update admitted recovery")
	}
	s.hold = nil
	if got := s.recoverConditionally(ctx, &good, peer); got != "recovered" || effects != 1 {
		t.Fatal(got, effects)
	}
}

// The preparation must not arm until the recovery callback has completed.
func TestPrepareDuringConditionalRecovery(t *testing.T) {
	s := NewServer(&holdEngine{})
	entered, release := make(chan struct{}), make(chan struct{})
	s.ConditionalRecovery = func(context.Context, string) (string, string) { close(entered); <-release; return "", "recovered" }
	peer := fakeWatch{alive: true, closed: new(int)}
	recovered, prepared := make(chan string, 1), make(chan Response, 1)
	go func() {
		recovered <- s.recoverConditionally(context.Background(), &RecoveryIdentity{"system", s.instance, strings.Repeat("e", 64)}, peer)
	}()
	<-entered
	started := make(chan struct{})
	go func() {
		close(started)
		prepared <- s.readinessAnswer(Request{Version: Version, Command: "prepare_update", ID: strings.Repeat("A", 26)}, peer)
	}()
	<-started
	select {
	case <-prepared:
		close(release)
		t.Fatal("prepared during effect")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if <-recovered != "recovered" {
		t.Fatal("recovery failed")
	}
	if a := <-prepared; a.Error != "" || a.UpdateTransaction == "" {
		t.Fatal(a)
	}
}

func TestReadinessConsumesEntireConditionalRequestLine(t *testing.T) {
	s := NewServer(&holdEngine{})
	count := 0
	closed := 0
	s.PeerProcess = func(net.Conn) ProcessWatch { return fakeWatch{alive: true, closed: &closed} }
	s.ConditionalRecovery = func(context.Context, string) (string, string) { count++; return "", "recovered" }
	raw, err := json.Marshal(Request{Version: Version, Command: "conditional_recovery", ID: "repair", RecoveryIdentity: &RecoveryIdentity{"system", s.instance, strings.Repeat("e", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{" {}", " garbage", strings.Repeat(" ", 1024) + "{}", ""} {
		peer, server := net.Pipe()
		done := make(chan struct{})
		go func() { s.readinessConnection(context.Background(), server); close(done) }()
		_, err = io.WriteString(peer, string(raw)+suffix+"\n")
		if err != nil && suffix == "" {
			t.Fatal(err)
		}
		reply, err := io.ReadAll(peer)
		peer.Close()
		<-done
		if err != nil {
			t.Fatal(err)
		}
		if suffix != "" && (count != 0 || len(reply) != 0) {
			t.Fatalf("invalid suffix produced effect/reply: %d %q", count, reply)
		}
		if suffix == "" && (count != 1 || !strings.Contains(string(reply), `"disposition":"recovered"`)) {
			t.Fatalf("valid request: %d %q", count, reply)
		}
	}
}
