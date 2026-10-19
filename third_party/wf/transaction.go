// Copyright (c) 2026 Bimeron contributors.
// BSD-3-Clause; see LICENSE.
package wf

// Transaction changes WFP configuration atomically. On errors (or panic) Windows
// aborts the transaction, retaining the preceding protection. Do not share this
// Session with other goroutines while a transaction is in progress.
func (s *Session) Transaction(fn func() error) (err error) {
	if err = fwpmTransactionBegin0(s.handle, 0); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = fwpmTransactionAbort0(s.handle)
		}
	}()
	if err = fn(); err != nil {
		return err
	}
	if err = fwpmTransactionCommit0(s.handle); err != nil {
		return err
	}
	committed = true
	return nil
}
