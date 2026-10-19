//go:build !windows && !linux && !darwin

package control

import (
	"context"
	"fmt"
	"net"
)

func Listen() (net.Listener, error) {
	return nil, fmt.Errorf("local control currently requires Windows, Linux or macOS")
}
func Dial(context.Context) (net.Conn, error) {
	return nil, fmt.Errorf("local control currently requires Windows, Linux or macOS")
}
