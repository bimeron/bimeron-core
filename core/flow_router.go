package core

import (
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"bimeron/internal/vpn"
	"sync"
)

// flowRouter keeps the packet stack and adapter alive while flow generations
// change. A nil generation rejects traffic; it never falls back to direct.
type flowRouter struct {
	mu      sync.RWMutex
	current *vpn.Handler
}

func (r *flowRouter) HandleTCP(c adapter.TCPConn) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.current == nil {
		_ = c.Close()
		return
	}
	r.current.HandleTCP(c)
}
func (r *flowRouter) HandleUDP(c adapter.UDPConn) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.current == nil {
		_ = c.Close()
		return
	}
	r.current.HandleUDP(c)
}
func (r *flowRouter) replace(next *vpn.Handler) {
	r.mu.Lock()
	old := r.current
	r.current = next
	r.mu.Unlock()
	if old != nil {
		old.Close()
	}
}
func (r *flowRouter) Close() { r.replace(nil) }
