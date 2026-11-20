//go:build windows

package main

import (
	"bimeron/internal/testutil"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"testing"
	"time"
)

// listenTestRepairSession listens like the broker. Without elevation the test
// process cannot assign the Administrators owner or serve instances under the
// production DACL, so it owns the pipe and gets the instance right itself.
func listenTestRepairSession(nonce string) (net.Listener, repairPeerCheck, func(), error) {
	if windows.GetCurrentProcessToken().IsElevated() {
		return listenRepairSession(nonce, uint32(os.Getpid()))
	}
	return listenRepairPipe(nonce, uint32(os.Getpid()), func(caller string) string {
		return repairPipeSDDL(caller, caller) + "(A;;0x4;;;" + caller + ")"
	})
}

func TestRepairPipeAuthenticatesActualCaller(t *testing.T) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(random[:])
	listener, check, release, err := listenTestRepairSession(nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	defer listener.Close()
	if other, _, done, err := listenTestRepairSession(nonce); err == nil {
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

// The caller can connect, read and write, but cannot create pipe instances or
// change the pipe's security. Other users get nothing.
func TestRepairPipeCallerRights(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	if sid == "S-1-5-18" {
		t.Skip("test needs a non-SYSTEM user")
	}
	caller := testutil.LimitedToken(t, testutil.Administrators)
	const forbidden = 0x4 | windows.WRITE_DAC | windows.WRITE_OWNER
	if got := testutil.GrantedPipeRights(t, caller, repairPipeSDDL("BAG:BA", sid)); got != 0x12019b || got&forbidden != 0 {
		t.Errorf("repair pipe grants the caller %#x, want 0x12019b", got)
	}
	if got := testutil.GrantedPipeRights(t, caller, repairPipeSDDL("BAG:BA", "S-1-5-21-111-222-333-444")); got != 0 {
		t.Errorf("repair pipe grants another user %#x", got)
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("broker rights need an elevated test process")
	}
	if got := testutil.GrantedPipeRights(t, testutil.LimitedToken(t), repairPipeSDDL("BAG:BA", sid)); got != 0x1f01ff {
		t.Errorf("repair pipe grants the elevated broker %#x, want full control", got)
	}
}
