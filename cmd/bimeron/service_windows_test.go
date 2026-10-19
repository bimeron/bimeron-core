//go:build windows

package main

import (
	"golang.org/x/sys/windows/svc"
	"net"
	"testing"
	"time"
)

func TestServiceStopsIdleCore(t *testing.T) {
	requests := make(chan svc.ChangeRequest, 1)
	changes := make(chan svc.Status, 16)
	done := make(chan uint32, 1)
	h := windowsService{listen: func(string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }}
	go func() { _, code := h.Execute(nil, requests, changes); done <- code }()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case status := <-changes:
			if status.State == svc.Running {
				requests <- svc.ChangeRequest{Cmd: svc.Stop}
				goto waiting
			}
		case <-timeout:
			t.Fatal("service did not start")
		}
	}
waiting:
	select {
	case code := <-done:
		if code != 0 {
			t.Fatal(code)
		}
	case <-timeout:
		t.Fatal("service did not stop")
	}
}
