package androidcore

import (
	"sync"
	"testing"
)

type ssconfSockets struct {
	mu            sync.Mutex
	protect, bind bool
	calls         []string
}

func (s *ssconfSockets) Protect(int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "protect")
	return s.protect
}
func (s *ssconfSockets) Bind(int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "bind")
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
			if len(s.calls) == 0 {
				t.Fatal("missing callback")
			}
			for i, call := range s.calls {
				if protect && call != []string{"protect", "bind"}[i%2] {
					t.Fatal(s.calls)
				}
				if !protect && call != "protect" {
					t.Fatal(s.calls)
				}
			}
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
