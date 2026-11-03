//go:build windows

package main

import (
	"context"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"time"
)

func TestDeveloperEndpointCredentials(t *testing.T) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf(`\\.\pipe\Bimeron.Test.Developer.%d.%d`, os.Getpid(), time.Now().UnixNano())
	ctxDone := make(chan struct{})
	defer close(ctxDone)
	l, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + u.User.Sid.String() + ")"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e == nil {
			<-ctxDone
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	c, err := winio.DialPipeContext(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !developerEndpointMatches(c, uint32(os.Getpid())) {
		t.Fatal("actual server rejected")
	}
	if developerEndpointMatches(c, uint32(os.Getpid()+1)) {
		t.Fatal("wrong server accepted")
	}
}
