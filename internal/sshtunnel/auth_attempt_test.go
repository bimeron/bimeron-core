package sshtunnel

import (
	"context"
	"errors"
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
