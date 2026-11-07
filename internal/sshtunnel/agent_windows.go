//go:build windows

package sshtunnel

import (
	"context"
	"github.com/Microsoft/go-winio"
	"net"
)

func dialAgent(ctx context.Context) (net.Conn, error) {
	const pipe = `\\.\pipe\openssh-ssh-agent`
	trace("agent", pipe)
	return winio.DialPipeContext(ctx, pipe)
}
