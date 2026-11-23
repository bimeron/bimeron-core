package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFirstRepairFrame(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		complete   bool
	}{
		{"full", "{}\n", true}, {"partial", "{}", false}, {"absent", "", false}, {"too large", strings.Repeat("x", 1024) + "\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			if tc.data != "" {
				go func() { _, _ = io.WriteString(client, tc.data) }()
			}
			budget := time.Second
			if tc.name == "partial" || tc.name == "absent" {
				budget = 100 * time.Millisecond
			}
			frame, err := readFirstRepairFrame(server, bufio.NewReader(server), time.Now().Add(budget))
			if (err == nil) != tc.complete || (err == nil && string(frame) != tc.data) {
				t.Fatalf("frame=%q err=%v", frame, err)
			}
		})
	}
	t.Run("buffered after expiry", func(t *testing.T) {
		s, c := net.Pipe()
		defer s.Close()
		defer c.Close()
		if _, err := readFirstRepairFrame(s, bufio.NewReader(bytes.NewBufferString("{}\n")), time.Now().Add(-time.Second)); err == nil {
			t.Fatal("late frame accepted")
		}
	})
}
