// Package linuxnet manages only Bimeron-owned Linux network settings.
package linuxnet

import (
	"fmt"
	"regexp"
	"bimeron/internal/killswitch"
	"bimeron/internal/routing"
	"strconv"
	"strings"
)

const Table = "51892"
const Mark = 0x524c
const MarkText = "0x524c"
const BypassPriority = "10900"
const TunnelPriority = "10901"
const TunnelInputPriority = "10902"
const Protocol = "242"
const FirewallTable = "bimeron_core"
const Owner = "Bimeron Core"

func ValidName(name string) bool {
	return regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,14}$`).MatchString(name)
}

// Firewall permits the core's marked sockets, never all root processes.
// No generic established permit is used in output: old connections must not leak.
func Firewall(name string, policy *routing.Policy, disableIPv6, replace bool) (string, error) {
	if !ValidName(name) {
		return "", fmt.Errorf("Linux interface name must be at most 15 ASCII characters")
	}
	rules, err := killswitch.Plan(policy, disableIPv6)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if replace {
		fmt.Fprintf(&b, "delete table inet %s\n", FirewallTable)
	}
	fmt.Fprintf(&b, "add table inet %s { comment %q; }\n", FirewallTable, Owner)
	fmt.Fprintf(&b, "add chain inet %s output { type filter hook output priority -10; policy drop; }\n", FirewallTable)
	fmt.Fprintf(&b, "add rule inet %s output oifname \"lo\" accept\n", FirewallTable)
	fmt.Fprintf(&b, "add rule inet %s output meta mark %s accept\n", FirewallTable, MarkText)
	fmt.Fprintf(&b, "add rule inet %s output oifname %s accept\n", FirewallTable, strconv.Quote(name))
	fmt.Fprintf(&b, "add rule inet %s output udp sport 68 udp dport 67 accept\n", FirewallTable)
	fmt.Fprintf(&b, "add rule inet %s output udp sport 546 udp dport 547 accept\n", FirewallTable)
	fmt.Fprintf(&b, "add rule inet %s output icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept\n", FirewallTable)
	for _, r := range rules {
		family := "ip"
		if r.Prefix.Addr().Is6() {
			family = "ip6"
		}
		verdict := "drop"
		if r.Allow {
			verdict = "accept"
		}
		fmt.Fprintf(&b, "add rule inet %s output %s daddr %s counter %s\n", FirewallTable, family, r.Prefix, verdict)
	}
	// Forwarded/container traffic is outside the local TUN flow handler. Fail closed.
	fmt.Fprintf(&b, "add chain inet %s forward { type filter hook forward priority -10; policy drop; }\n", FirewallTable)
	return b.String(), nil
}
