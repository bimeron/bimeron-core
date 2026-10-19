package telemetry

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

func TestCopyUpdatesBeforeOpenStreamFinishes(t *testing.T) {
	for _, up := range []bool{true, false} {
		t.Run(map[bool]string{true: "upload", false: "download"}[up], func(t *testing.T) {
			source, writer := io.Pipe()
			defer source.Close()
			defer writer.Close()
			var c Counters
			var destination bytes.Buffer
			done := make(chan error, 1)
			go func() {
				var err error
				if up {
					_, err = c.CopyUp(&destination, source)
				} else {
					_, err = c.CopyDown(&destination, source)
				}
				done <- err
			}()
			defer func() {
				writer.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("copy stuck")
				}
			}()
			if _, err := writer.Write([]byte("live payload")); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for {
				s := c.Snapshot()
				n := s.BytesDown
				if up {
					n = s.BytesUp
				}
				if n == 12 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("stream still open but counters stale", s)
				}
				time.Sleep(time.Millisecond)
			}
			select {
			case <-done:
				t.Fatal("stream closed prematurely")
			default:
			}
		})
	}
}

type partialWriter struct{}

func (partialWriter) Write(p []byte) (int, error) { return 2, io.ErrShortWrite }
func TestCopyCountsOnlyAcceptedBytes(t *testing.T) {
	var c Counters
	n, err := c.CopyUp(partialWriter{}, bytes.NewBufferString("12345"))
	if n != 2 || !errors.Is(err, io.ErrShortWrite) || c.Snapshot().BytesUp != 2 {
		t.Fatal(n, err, c.Snapshot())
	}
	var nilCounters *Counters
	var dst bytes.Buffer
	if _, err := nilCounters.CopyDown(&dst, bytes.NewBufferString("ok")); err != nil || dst.String() != "ok" {
		t.Fatal(err, dst.String())
	}
}
