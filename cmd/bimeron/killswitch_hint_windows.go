//go:build windows

package main

import (
	"bimeron/internal/accesskey"
	"bimeron/internal/sshtunnel"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"bimeron/internal/control"
	"bimeron/internal/killswitch"
	"golang.org/x/sys/windows"
)

// killSwitchHint explains a check or proxy failure that kill switch
// protection may cause. While protection is installed, the core executable is
// exempt from the filters only as SYSTEM or with an elevated token that
// contains the Administrators group; other processes, including this command
// started from a non-elevated terminal, reach only the tunnel and direct
// destinations.
func killSwitchHint(err error) error { return withKillSwitchHint(err, coreExempt, protectionInstalled) }

func withKillSwitchHint(err error, exempt, installed func() bool) error {
	// The system DNS client is not exempt, so name lookups of this command
	// fail under protection even where its connections would be permitted.
	if dnsFailure(err) {
		if !installed() {
			return err
		}
		return fmt.Errorf("%w\nhint: Bimeron kill switch protection blocks the system DNS client outside the tunnel; use the server's IP address or stop the protecting session first", err)
	}
	if !upstreamFailure(err) || exempt() || !installed() {
		return err
	}
	return fmt.Errorf("%w\nhint: Bimeron kill switch protection may be blocking this connection; run the protecting core executable from an elevated administrator terminal or stop the protecting session first", err)
}

// dnsFailure reports a failed name lookup of the upstream or ssconf host.
func dnsFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, accesskey.ErrSSConfDNS) || err.Error() == "endpoint_dns_failed" {
		return true
	}
	var dns *net.DNSError
	return errors.As(err, &dns)
}

// Proxy sessions return stable core error codes. Direct checks can retain the
// socket error, including when wrapped by a transport or HTTP client.
func upstreamFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sshtunnel.ErrNetwork) || errors.Is(err, accesskey.ErrSSConfNetwork) {
		return true
	}
	switch err.Error() {
	case "transport_check_failed", "ssh_network_failed", "hysteria2_network_failed", "hysteria2_network_timeout":
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) {
		switch op.Op {
		case "dial", "read", "write":
			return op.Net == "tcp" || op.Net == "tcp4" || op.Net == "tcp6" || op.Net == "udp" || op.Net == "udp4" || op.Net == "udp6"
		}
	}
	return false
}

// coreExempt reports whether this process matches the kill switch exemption
// for the core executable (SYSTEM or the Administrators group enabled).
func coreExempt() bool {
	for _, kind := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			continue
		}
		if member, err := windows.Token(0).IsMember(sid); err == nil && member {
			return killswitch.CurrentImagePermitted()
		}
	}
	return false
}

// protectionInstalled asks the daemon or service, which a standard user can
// reach, and otherwise inspects the filters directly where that is permitted.
func protectionInstalled() bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if a, err := control.Call(ctx, control.Request{Command: "status"}); err == nil && a.Error == "" && a.Status.KillSwitch != "" {
		return true
	}
	// A foreground owner's protection is not in the daemon's status.
	installed, err := killswitch.Pending()
	return err == nil && installed
}
