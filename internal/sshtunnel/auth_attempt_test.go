package sshtunnel

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestAttemptBudgetAndCancellation(t *testing.T) {
	a := newAttempt(context.Background())
	defer a.close()
	a.remaining = 100 * time.Millisecond
	a.resume()
	p := a.prompt(func(ctx context.Context, c Challenge) ([]string, error) {
		time.Sleep(150 * time.Millisecond)
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		return []string{"x"}, nil
	})
	if _, e := p(a.ctx, Challenge{}); e != nil {
		t.Fatal(e)
	}
	select {
	case <-a.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("budget reset or lost")
	}
	calls := 0
	b := newAttempt(context.Background())
	defer b.close()
	q := b.prompt(func(context.Context, Challenge) ([]string, error) { calls++; return nil, errors.New("cancel") })
	q(b.ctx, Challenge{})
	q(b.ctx, Challenge{})
	if calls != 1 {
		t.Fatal("fallback reprompt")
	}
}
func TestAttemptRoundLimit(t *testing.T) {
	a := newAttempt(context.Background())
	defer a.close()
	calls := 0
	p := a.prompt(func(context.Context, Challenge) ([]string, error) { calls++; return []string{"x"}, nil })
	for i := 0; i < 9; i++ {
		p(a.ctx, Challenge{})
	}
	if calls != 8 || a.ctx.Err() == nil {
		t.Fatal("round limit")
	}
}

func TestAttemptParentDeadlineDuringPrompt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	a := newAttempt(ctx)
	defer a.close()
	a.resume()
	p := a.prompt(func(ctx context.Context, _ Challenge) ([]string, error) { <-ctx.Done(); return nil, ctx.Err() })
	if _, err := p(a.ctx, Challenge{}); err == nil || a.ctx.Err() == nil {
		t.Fatal("parent deadline lost")
	}
}

func TestAttemptNetworkClassification(t *testing.T) {
	plain := errors.New("ssh: unable to authenticate")
	refused := &net.OpError{Op: "dial", Err: errors.New("connection refused")}

	a := newAttempt(context.Background())
	if a.network(plain) || !a.network(refused) {
		t.Fatal("error type misclassified")
	}
	a.close()

	a = newAttempt(context.Background())
	a.remaining = time.Millisecond
	a.resume()
	<-a.ctx.Done()
	if !a.network(plain) {
		t.Fatal("expired network budget is not a network failure")
	}
	a.close()

	a = newAttempt(context.Background())
	a.resume()
	p := a.prompt(func(context.Context, Challenge) ([]string, error) { return nil, errors.New("dismissed") })
	if _, err := p(a.ctx, Challenge{}); err == nil {
		t.Fatal("prompt failure accepted")
	}
	if a.network(refused) {
		t.Fatal("dismissed prompt classified as network failure")
	}
	a.close()

	parent, cancel := context.WithCancel(context.Background())
	a = newAttempt(parent)
	cancel()
	if a.network(refused) {
		t.Fatal("caller cancellation classified as network failure")
	}
	a.close()

	parent, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	a = newAttempt(parent)
	<-parent.Done()
	if !a.network(plain) {
		t.Fatal("caller deadline is not a network failure")
	}
	a.close()
}
