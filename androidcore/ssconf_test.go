package androidcore

import (
	"bimeron/core"
	"context"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type ssconfSockets struct {
	mu            sync.Mutex
	protect, bind bool
	calls         []string
	bySocket      map[int][]string
}

func (s *ssconfSockets) Protect(fd int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "protect")
	if s.bySocket == nil {
		s.bySocket = make(map[int][]string)
	}
	s.bySocket[fd] = append(s.bySocket[fd], "protect")
	return s.protect
}
func (s *ssconfSockets) Bind(fd int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "bind")
	if s.bySocket == nil {
		s.bySocket = make(map[int][]string)
	}
	s.bySocket[fd] = append(s.bySocket[fd], "bind")
	return s.bind
}

func TestSSConfFailClosed(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "fixture.invalid"} {
		for _, protect := range []bool{false, true} {
			s := &ssconfSockets{protect: protect}
			r, err := NewSSConfRequest("ssconf://"+host+"/secret", "wifi", "127.0.0.1", s)
			if err != nil {
				t.Fatal(err)
			}
			result, err := r.Resolve()
			if err == nil || result != nil {
				t.Fatal("expected failure")
			}
			s.mu.Lock()
			if len(s.calls) == 0 {
				t.Fatal("missing callback")
			}
			for _, calls := range s.bySocket {
				for i, call := range calls {
					if protect && call != []string{"protect", "bind"}[i%2] {
						t.Fatal(s.calls)
					}
					if !protect && call != "protect" {
						t.Fatal(s.calls)
					}
				}
			}
			s.mu.Unlock()
		}
	}
}
func TestSSConfLifecycle(t *testing.T) {
	r, err := NewSSConfRequest("ssconf://127.0.0.1/secret", "wifi", "127.0.0.1", &ssconfSockets{})
	if err != nil {
		t.Fatal(err)
	}
	r.Cancel()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Cancel()
			if v, e := r.Resolve(); v != nil || e == nil {
				t.Error("canceled request succeeded")
			}
		}()
	}
	wg.Wait()
	result := &SSConfResult{content: []byte("secret")}
	result.Content()[0] = 'X'
	if string(result.Content()) != "secret" || result.Metadata() != "{\"bytes\":6}" {
		t.Fatal("result mutation")
	}
}

func TestSSConfPublication(t *testing.T) {
	for _, cancelFirst := range []bool{false, true} {
		r, err := NewSSConfRequest("ssconf://fixture.invalid", "wifi", "127.0.0.1", &ssconfSockets{})
		if err != nil {
			t.Fatal(err)
		}
		entered, release := make(chan struct{}), make(chan struct{})
		r.resolve = func(context.Context, string, core.PacketNetwork) ([]byte, error) {
			close(entered)
			<-release
			return []byte("validated"), nil
		}
		done := make(chan *SSConfResult)
		go func() {
			v, e := r.Resolve()
			if (e != nil) != cancelFirst {
				t.Errorf("unexpected error: %v", e)
			}
			done <- v
		}()
		<-entered
		if v, e := r.Resolve(); v != nil || e == nil {
			t.Fatal("concurrent resolve accepted")
		}
		if cancelFirst {
			r.Cancel()
		}
		close(release)
		v := <-done
		if cancelFirst {
			if v != nil {
				t.Fatal("canceled publication")
			}
			continue
		}
		r.Cancel()
		v.Content()[0] = 'X'
		if string(v.Content()) != "validated" {
			t.Fatal("mutable success")
		}
	}
}
func TestSSConfConstructorValidation(t *testing.T) {
	for _, tc := range []struct{ source, network, dns string }{
		{"https://example.com", "wifi", "1.1.1.1"},
		{"ssconf://user:pass@example.com", "wifi", "1.1.1.1"},
		{"ssconf://", "wifi", "1.1.1.1"},
		{"ssconf://example.com", " ", "1.1.1.1"},
		{"ssconf://example.com", "wifi", ""},
		{"ssconf://example.com", "wifi", "::1"},
		{"ssconf://example.com", "wifi", "1.1.1.1,"},
		{"ssconf://example.com", "wifi", "1.1.1.1,1.1.1.1,1.1.1.1,1.1.1.1,1.1.1.1"},
	} {
		if r, e := NewSSConfRequest(tc.source, tc.network, tc.dns, &ssconfSockets{}); r != nil || e == nil {
			t.Fatal(tc)
		}
	}
	if r, e := NewSSConfRequest("ssconf://example.com", "wifi", "1.1.1.1", nil); r != nil || e == nil {
		t.Fatal("nil callbacks accepted")
	}
}

func TestSSConfCancellationAndSocketControl(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "fixture.invalid"} {
		t.Run(host, func(t *testing.T) {
			sockets := &ssconfSockets{protect: true, bind: true}
			r, err := NewSSConfRequest("ssconf://"+host, "wifi", "127.0.0.1", sockets)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Cancel()
			entered := make(chan string, 8)
			exited := make(chan struct{}, 8)
			control := r.network.Dialer.Control
			r.network.Dialer.ControlContext = func(ctx context.Context, network, address string, raw syscall.RawConn) error {
				if err := control(network, address, raw); err != nil {
					return err
				}
				select {
				case entered <- network:
				default:
				}
				<-ctx.Done()
				exited <- struct{}{}
				return ctx.Err()
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				v, e := r.Resolve()
				if v != nil || e == nil {
					t.Error("canceled request succeeded")
				}
			}()
			select {
			case network := <-entered:
				want := "tcp"
				if host == "fixture.invalid" {
					want = "udp"
				}
				if !strings.HasPrefix(network, want) {
					t.Errorf("network %q, want %s", network, want)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("socket gate not entered")
			}
			r.Cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("cancellation stalled")
			}
			select {
			case <-exited:
			case <-time.After(3 * time.Second):
				t.Fatal("socket gate did not observe cancellation")
			}
			sockets.mu.Lock()
			defer sockets.mu.Unlock()
			if len(sockets.calls) < 2 {
				t.Fatal("missing successful callbacks")
			}
			for _, calls := range sockets.bySocket {
				for i, call := range calls {
					if call != []string{"protect", "bind"}[i%2] {
						t.Fatal(sockets.calls)
					}
				}
			}
		})
	}
}

func TestSSConfDeadlineAndCancelPropagation(t *testing.T) {
	r, err := NewSSConfRequest("ssconf://127.0.0.1", "wifi", "127.0.0.1", &ssconfSockets{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Cancel()
	entered := make(chan context.Context, 1)
	r.resolve = func(ctx context.Context, _ string, _ core.PacketNetwork) ([]byte, error) {
		entered <- ctx
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		v, e := r.Resolve()
		if v != nil || e == nil {
			t.Error("canceled request succeeded")
		}
	}()
	select {
	case ctx := <-entered:
		deadline, ok := ctx.Deadline()
		if remaining := time.Until(deadline); !ok || remaining < 14*time.Second || remaining > 15*time.Second {
			t.Errorf("unexpected deadline: %v", deadline)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("resolver not entered")
	}
	r.Cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("resolver context not canceled")
	}
}

type ssconfRaw struct{ err error }

func (r ssconfRaw) Control(f func(uintptr)) error {
	if r.err == nil {
		f(1)
	}
	return r.err
}
func (ssconfRaw) Read(func(uintptr) bool) error  { return nil }
func (ssconfRaw) Write(func(uintptr) bool) error { return nil }

func TestSSConfTerminalSocketFailure(t *testing.T) {
	for _, stage := range []string{"protect", "bind", "control"} {
		t.Run(stage, func(t *testing.T) {
			sockets := &ssconfSockets{protect: stage != "protect", bind: false}
			r, err := NewSSConfRequest("ssconf://fixture.invalid", "wifi", "127.0.0.1", sockets)
			if err != nil {
				t.Fatal(err)
			}
			r.resolve = func(context.Context, string, core.PacketNetwork) ([]byte, error) {
				raw := ssconfRaw{}
				if stage == "control" {
					raw.err = context.Canceled
				}
				if r.network.Dialer.Control("tcp", "", raw) == nil {
					t.Error("first attempt succeeded")
				}
				sockets.mu.Lock()
				sockets.protect = true
				sockets.bind = true
				sockets.mu.Unlock()
				var wg sync.WaitGroup
				for i := 0; i < 8; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if r.network.Dialer.Control("tcp", "", ssconfRaw{}) == nil {
							t.Error("later attempt succeeded")
						}
					}()
				}
				wg.Wait()
				return []byte("validated"), nil
			}
			if result, err := r.Resolve(); result != nil || err == nil {
				t.Fatal("failure published success")
			}
		})
	}
}
