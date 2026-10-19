//go:build !windows && !linux && !darwin

package core

import (
	"context"
)

type unsupportedPlatform struct{}

func newPlatform(SessionConfig) platform { return unsupportedPlatform{} }
func (unsupportedPlatform) Acquire(context.Context) (func(), error) {
	return nil, fault("vpn_platform_unsupported", false)
}
func (unsupportedPlatform) Inspect(context.Context, string, bool) (networkPath, error) {
	return networkPath{}, fault("vpn_platform_unsupported", false)
}
func (unsupportedPlatform) Open(context.Context, SessionConfig, *flowRouter, func(string, string)) (link, error) {
	return nil, fault("vpn_platform_unsupported", false)
}
