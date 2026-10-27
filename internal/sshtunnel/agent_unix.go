//go:build linux || darwin

package sshtunnel

import (
	"context"
	"fmt"
	"net"
	"os"
)

func dialAgent(ctx context.Context) (net.Conn, error) {
	path := os.Getenv("SSH_AUTH_SOCK")
	if path == "" {
		return nil, fmt.Errorf("SSH agent unavailable")
	}
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}
