//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"time"
)

func TestRepairPipeAuthenticatesActualCaller(t *testing.T) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(random[:])
	listener, check, release, err := listenRepairSession(nonce, uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	defer listener.Close()
	if other, _, done, err := listenRepairSession(nonce, uint32(os.Getpid())); err == nil {
		other.Close()
		done()
		t.Fatal("duplicate pipe accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := winio.DialPipeContext(ctx, `\\.\pipe\Bimeron.Repair.`+nonce)
		if err == nil {
			defer conn.Close()
			<-ctx.Done()
		}
		result <- err
	}()
	timer := time.AfterFunc(3*time.Second, func() { listener.Close() })
	defer timer.Stop()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	identity, err := check(conn)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &session); err != nil {
		t.Fatal(err)
	}
	if identity != fmt.Sprintf("%s|%d", user.User.Sid.String(), session) {
		t.Fatal("incorrect caller identity")
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
