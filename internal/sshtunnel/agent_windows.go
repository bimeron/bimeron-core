//go:build windows

package sshtunnel

import (
	"context"
	"github.com/Microsoft/go-winio"
	"net"
)

func dialAgent(ctx context.Context) (net.Conn, error) {
	return winio.DialPipeContext(ctx, `\\.\pipe\openssh-ssh-agent`)
}
