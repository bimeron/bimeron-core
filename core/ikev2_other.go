//go:build !windows

package core

import "context"

type ikev2Backend struct{}

func newIKEv2Backend() backend { return ikev2Backend{} }
func (ikev2Backend) Acquire(context.Context) (func(), error) {
	return nil, fault("ikev2_platform_unsupported", false)
}
func (ikev2Backend) Open(context.Context, SessionConfig, func(string, string)) (session, error) {
	return nil, fault("ikev2_platform_unsupported", false)
}
