package vless

import (
	"net"
	"sync"
)

// plainConn handles the VLESS response header without Vision framing.
type plainConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *plainConn) Read(b []byte) (int, error) {
	c.once.Do(func() { c.err = readResponseHeader(c.Conn) })
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(b)
}

func (c *plainConn) CloseRead() error { return c.Conn.Close() }

func (c *plainConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Conn.Close()
}
