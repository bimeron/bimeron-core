package routing

import (
	"fmt"
	"net/netip"
	"strings"
)

type Action string

const (
	Direct Action = "direct"
	Proxy  Action = "proxy"
	Block  Action = "block"
)

type Rule struct {
	CIDR   string `json:"cidr,omitempty"`
	Domain string `json:"domain,omitempty"`
	Action Action `json:"action"`
}
type Config struct {
	Default Action `json:"default"`
	Rules   []Rule `json:"rules"`
}
type compiledRule struct {
	prefix netip.Prefix
	domain string
	action Action
}
type Policy struct {
	fallback Action
	rules    []compiledRule
}

// Config returns a detached, normalized snapshot for system policy adapters.
func (p *Policy) Config() Config {
	if p == nil {
		return Config{Default: Proxy}
	}
	c := Config{Default: p.fallback}
	for _, r := range p.rules {
		rule := Rule{Domain: r.domain, Action: r.action}
		if r.prefix.IsValid() {
			rule.CIDR = r.prefix.String()
		}
		c.Rules = append(c.Rules, rule)
	}
	return c
}

// DirectPrefixes returns CIDR rules that can safely bypass the system tunnel
// without overriding an earlier first-match rule.
func (p *Policy) DirectPrefixes() []netip.Prefix {
	if p == nil {
		return nil
	}
	var prefixes []netip.Prefix
	for i, r := range p.rules {
		if r.prefix.IsValid() && r.action == Direct {
			safe := true
			for _, earlier := range p.rules[:i] {
				if earlier.action != Direct && (earlier.domain != "" || earlier.prefix.IsValid() && earlier.prefix.Overlaps(r.prefix)) {
					safe = false
					break
				}
			}
			if safe {
				prefixes = append(prefixes, r.prefix)
			}
		}
	}
	return prefixes
}

func valid(a Action) bool       { return a == Direct || a == Proxy || a == Block }
func normalize(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }
func matchesDomain(domain, rule string) bool {
	return domain == rule || strings.HasSuffix(domain, "."+rule)
}
func Compile(c Config) (*Policy, error) {
	if !valid(c.Default) {
		return nil, fmt.Errorf("invalid default action")
	}
	p := &Policy{fallback: c.Default}
	for i, r := range c.Rules {
		if !valid(r.Action) || (r.CIDR == "") == (r.Domain == "") {
			return nil, fmt.Errorf("invalid rule %d", i+1)
		}
		cr := compiledRule{action: r.Action}
		if r.CIDR != "" {
			for _, value := range strings.Split(r.CIDR, ",") {
				prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
				if err != nil {
					return nil, fmt.Errorf("invalid CIDR in rule %d", i+1)
				}
				p.rules = append(p.rules, compiledRule{prefix: prefix.Masked(), action: r.Action})
			}
			continue
		} else {
			cr.domain = normalize(r.Domain)
			if cr.domain == "" || strings.ContainsAny(cr.domain, " /*:\t\r\n") {
				return nil, fmt.Errorf("invalid domain in rule %d", i+1)
			}
		}
		p.rules = append(p.rules, cr)
	}
	return p, nil
}

// DomainRelevant reports whether a trusted DNS answer can affect this policy.
func (p *Policy) DomainRelevant(domain string) bool {
	domain = normalize(domain)
	for _, r := range p.rules {
		if r.domain != "" && matchesDomain(domain, r.domain) {
			return true
		}
	}
	return false
}

// DecideDomains uses first-match rule order across the IP and every trusted
// domain associated with it. Domain slice order never changes the result.
func (p *Policy) DecideDomains(ip netip.Addr, domains []string) Action {
	ip = ip.Unmap()
	for _, r := range p.rules {
		if r.prefix.IsValid() && r.prefix.Contains(ip) {
			return r.action
		}
		if r.domain != "" {
			for _, domain := range domains {
				if matchesDomain(normalize(domain), r.domain) {
					return r.action
				}
			}
		}
	}
	return p.fallback
}

// Decide keeps the single-domain API used by the SOCKS proxy.
func (p *Policy) Decide(ip netip.Addr, domain string) Action {
	if domain == "" {
		return p.DecideDomains(ip, nil)
	}
	return p.DecideDomains(ip, []string{domain})
}
