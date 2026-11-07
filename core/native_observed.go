package core

import "context"

type observedNativeSession struct {
	native session
	config SessionConfig
}

// Wait keeps cancellation as is; native failures become catalog codes.
func (s *observedNativeSession) Wait(ctx context.Context) error {
	err := s.native.Wait(ctx)
	if err == nil || ctx.Err() != nil {
		return err
	}
	return codeFault(err, "ikev2_native_operation_failed", false)
}
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
	if err != nil {
		return codeFault(err, "ikev2_cleanup_failed", false)
	}
	return nil
}
