package dnsconfig

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"bimeron/internal/problem"
)

const MaxDoHEndpoints = 4
const MaxDoHBootstrapIPs = 4

type DoHEndpoint struct {
	URL string
	IPs []netip.Addr
}

func DoHProblem(code, field, message string) *problem.Error {
	return problem.New(code, message).In("Interface").At(field)
}

func ParseDoH(endpoints, bootstrap *string, vpn, disableIPv6 bool) ([]DoHEndpoint, error) {
	if endpoints == nil && bootstrap == nil {
		return nil, nil
	}
	if endpoints == nil {
		return nil, DoHProblem("doh_bootstrap_required", "DoH", "DoHBootstrap requires DoH")
	}
	if bootstrap == nil {
		return nil, DoHProblem("doh_bootstrap_required", "DoHBootstrap", "DoH requires DoHBootstrap")
	}
	if !vpn {
		return nil, DoHProblem("doh_unsupported_mode", "DoH", "DoH requires VPN mode")
	}
	urls, groups := strings.Split(*endpoints, ","), strings.Split(*bootstrap, ",")
	if len(urls) > MaxDoHEndpoints {
		return nil, DoHProblem("doh_too_many_endpoints", "DoH", "DoH supports up to four endpoints")
	}
	if len(urls) != len(groups) {
		return nil, DoHProblem("doh_bootstrap_count_mismatch", "DoHBootstrap", "DoH requires one bootstrap group per endpoint")
	}
	result := make([]DoHEndpoint, 0, len(urls))
	seen := make(map[string]bool)
	for i, raw := range urls {
		spelling := strings.TrimSpace(raw)
		u, err := url.Parse(spelling)
		if err != nil || u.Scheme != "https" || u.User != nil || u.EscapedPath() == "" || strings.ContainsAny(spelling, "? #|") || !dnsHostname(u.Hostname()) || strings.ContainsAny(u.Host, "[]") || strings.HasSuffix(u.Host, ":") {
			return nil, DoHProblem("doh_invalid_endpoint", "DoH", "DoH requires an HTTPS URL with a DNS hostname and path")
		}
		port := 443
		if u.Port() != "" {
			port, err = strconv.Atoi(u.Port())
			if err != nil || port < 1 || port > 65535 {
				return nil, DoHProblem("doh_invalid_endpoint", "DoH", "DoH port is invalid")
			}
		}
		key := strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")) + ":" + strconv.Itoa(port) + u.EscapedPath()
		if seen[key] {
			return nil, DoHProblem("doh_duplicate_endpoint", "DoH", "DoH endpoints must be distinct")
		}
		seen[key] = true
		tokens := strings.Split(groups[i], "|")
		if len(tokens) > MaxDoHBootstrapIPs {
			return nil, DoHProblem("doh_too_many_bootstrap_ips", "DoHBootstrap", "DoH supports up to four IPs per endpoint")
		}
		endpoint := DoHEndpoint{URL: spelling}
		addresses := make(map[netip.Addr]bool)
		usable := false
		for _, token := range tokens {
			ip, err := netip.ParseAddr(strings.TrimSpace(token))
			if err != nil || !ip.IsGlobalUnicast() || ip.Is4In6() || ip.Zone() != "" {
				return nil, DoHProblem("doh_invalid_bootstrap_ip", "DoHBootstrap", "DoH bootstrap requires numeric unicast IPs")
			}
			if addresses[ip] {
				return nil, DoHProblem("doh_duplicate_bootstrap_ip", "DoHBootstrap", "DoH bootstrap IPs must be distinct within each group")
			}
			addresses[ip] = true
			endpoint.IPs = append(endpoint.IPs, ip)
			usable = usable || ip.Is4() || !disableIPv6
		}
		if !usable {
			return nil, DoHProblem("doh_no_usable_bootstrap_ip", "DoHBootstrap", "Each DoH endpoint needs a usable IP address")
		}
		result = append(result, endpoint)
	}
	return result, nil
}

func ValidateDoHScope(endpoints []DoHEndpoint, allowed []netip.Prefix, disableIPv6 bool) error {
	for _, endpoint := range endpoints {
		for _, ip := range endpoint.IPs {
			if disableIPv6 && ip.Is6() {
				continue
			}
			covered := false
			for _, prefix := range allowed {
				covered = covered || prefix.Contains(ip)
			}
			if !covered {
				return DoHProblem("doh_bootstrap_outside_allowed_ips", "DoHBootstrap", "DoH bootstrap IP is outside WireGuard AllowedIPs")
			}
		}
	}
	return nil
}

func dnsHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range strings.ToLower(label) {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
