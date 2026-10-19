package telemetry

import (
	"testing"

	"bimeron/internal/routing"
)

func TestNilCountersAreNoOps(t *testing.T) {
	var c *Counters
	c.AttemptTCP()
	c.EstablishTCP()
	c.EndTCP()
	c.FailTCP()
	c.AttemptUDP()
	c.EstablishUDP()
	c.EndUDP()
	c.FailUDP()
	c.DNSQuery()
	c.DNSFailure()
	c.Sent(10)
	c.Received(20)
	c.RouteDecided(routing.Proxy)
	if s := c.Snapshot(); s != (Snapshot{}) {
		t.Fatal(s)
	}
}

func TestCountersSnapshot(t *testing.T) {
	var c Counters
	c.AttemptTCP()
	c.AttemptTCP()
	c.EstablishTCP()
	c.FailTCP()
	c.AttemptUDP()
	c.EstablishUDP()
	c.FailUDP()
	c.DNSQuery()
	c.DNSFailure()
	c.Sent(5)
	c.Received(7)
	c.Sent(-1) // ignored
	c.RouteDecided(routing.Direct)
	c.RouteDecided(routing.Block)
	s := c.Snapshot()
	if s.TCPTotal != 2 || s.TCPActive != 1 || s.TCPFailed != 1 ||
		s.UDPTotal != 1 || s.UDPActive != 1 || s.UDPFailed != 1 ||
		s.DNSQueries != 1 || s.DNSFailed != 1 ||
		s.BytesUp != 5 || s.BytesDown != 7 ||
		s.RoutedDirect != 1 || s.RoutedBlock != 1 || s.RoutedProxy != 0 {
		t.Fatal(s)
	}
}
