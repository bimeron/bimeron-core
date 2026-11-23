package control

import (
	"context"
	"strings"
	"testing"
	"time"
)

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
