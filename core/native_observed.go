package core

import "context"

type observedNativeSession struct {
	native session
	config SessionConfig
}

func (s *observedNativeSession) Wait(ctx context.Context) error { return s.native.Wait(ctx) }
func (s *observedNativeSession) Close() error {
	s.config.updateNative(func(n *NativeStatus) { n.RASCleanup = "pending" })
	err := s.native.Close()
	s.config.updateNative(func(n *NativeStatus) {
		if err != nil {
			n.RASCleanup = "failed"
		} else {
			n.RASCleanup = "succeeded"
		}
	})
	return err
}
