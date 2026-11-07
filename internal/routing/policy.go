package routing

import (
	"fmt"
	"net/netip"
	"strings"

	"bimeron/internal/problem"
)

type Action string

const (
	Direct Action = "direct"
	Proxy  Action = "proxy"
	Block  Action = "block"
)

type Rule struct {
	CIDR    string `json:"cidr,omitempty"`
	Domain  string `json:"domain,omitempty"`
	GeoIP   string `json:"geoip,omitempty"`
	GeoSite string `json:"geosite,omitempty"`
	Action  Action `json:"action"`
}
type Config struct {
	Default Action `json:"default"`
	Rules   []Rule `json:"rules"`
}
type compiledRule struct {
	prefix         netip.Prefix
	domain         string
	action         Action
	geoIP, geoSite string
	ips            []*ipGroup
	sites          []*domainGroup
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
		rule := Rule{Domain: r.domain, GeoIP: r.geoIP, GeoSite: r.geoSite, Action: r.action}
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
				if earlier.action != Direct && (earlier.domain != "" || len(earlier.ips) > 0 || len(earlier.sites) > 0 || earlier.prefix.IsValid() && earlier.prefix.Overlaps(r.prefix)) {
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

// actions lists the permitted actions for choice_invalid problems.
const actions = "direct, proxy, block"

func valid(a Action) bool { return a == Direct || a == Proxy || a == Block }

// checkRule requires one matcher and a valid action. rule is the one-based
// [Rule] index; every failure keeps the historical "invalid rule N" message.
func checkRule(r Rule, rule int) error {
	var matchers []string
	for _, m := range []struct{ field, value string }{{"CIDR", r.CIDR}, {"Domain", r.Domain}, {"GeoIP", r.GeoIP}, {"GeoSite", r.GeoSite}} {
		if m.value != "" {
			matchers = append(matchers, m.field)
		}
	}
	message := fmt.Sprintf("invalid rule %d", rule)
	switch {
	case len(matchers) == 0:
		return problem.New("rule_matcher_count", message).In("Rule").AtRule(rule)
	case len(matchers) > 1:
		return problem.New("rule_matcher_count", message).In("Rule").At(matchers[0]).Also(matchers[1:]...).AtRule(rule)
	case r.Action == "":
		return problem.New("value_required", message).In("Rule").On("Action", "").AtRule(rule)
	case !valid(r.Action):
		return problem.New("choice_invalid", message).In("Rule").At("Action").Arg("allowed", actions).AtRule(rule)
	}
	return nil
}
func normalize(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }
func matchesDomain(domain, rule string) bool {
	return domain == rule || strings.HasSuffix(domain, "."+rule)
}
func Compile(c Config) (*Policy, error) { return CompileWithGeoData(c, nil) }

// CompileWithGeoData compiles ordered rules against an immutable dataset snapshot.
func CompileWithGeoData(c Config, data *GeoData) (*Policy, error) {
	if !valid(c.Default) {
		return nil, problem.New("choice_invalid", "invalid default action").In("Routing").At("Default").Arg("allowed", actions)
	}
	p := &Policy{fallback: c.Default}
	for i, r := range c.Rules {
		if err := checkRule(r, i+1); err != nil {
			return nil, err
		}
		cr := compiledRule{action: r.Action}
		if r.GeoIP != "" || r.GeoSite != "" {
			value := r.GeoIP
			kind := "GeoIP"
			if value == "" {
				value = r.GeoSite
				kind = "GeoSite"
			}
			if data == nil || kind == "GeoIP" && len(data.ips) == 0 || kind == "GeoSite" && len(data.sites) == 0 {
				return nil, &GeoDataError{Code: "geodata_required", Kind: strings.ToLower(kind), Rule: i + 1, Err: fmt.Errorf("dataset is unavailable")}
			}
			for _, raw := range strings.Split(value, ",") {
				id, err := groupID(strings.TrimSpace(raw))
				if err != nil {
					return nil, geoError(kind, "", i+1, err)
				}
				if kind == "GeoIP" {
					g, ok := data.ips[id]
					if !ok {
						return nil, &GeoDataError{Code: "geodata_group_unknown", Kind: strings.ToLower(kind), Group: id, Rule: i + 1, Err: fmt.Errorf("unknown group")}
					}
					cr.ips = append(cr.ips, g)
				} else {
					g, ok := data.sites[id]
					if !ok {
						return nil, &GeoDataError{Code: "geodata_group_unknown", Kind: strings.ToLower(kind), Group: id, Rule: i + 1, Err: fmt.Errorf("unknown group")}
					}
					cr.sites = append(cr.sites, g)
				}
			}
			cr.geoIP = r.GeoIP
			cr.geoSite = r.GeoSite
		} else if r.CIDR != "" {
			for _, value := range strings.Split(r.CIDR, ",") {
				prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
				if err != nil {
					return nil, problem.New("cidr_invalid", fmt.Sprintf("invalid CIDR in rule %d", i+1)).In("Rule").At("CIDR").AtRule(i + 1)
				}
				p.rules = append(p.rules, compiledRule{prefix: prefix.Masked(), action: r.Action})
			}
			continue
		} else {
			cr.domain = normalize(r.Domain)
			if cr.domain == "" || strings.ContainsAny(cr.domain, " /*:\t\r\n") {
				return nil, problem.New("domain_invalid", fmt.Sprintf("invalid domain in rule %d", i+1)).In("Rule").At("Domain").AtRule(i + 1)
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
		if r.matchesDomain(domain) {
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
		if r.matchesIP(ip) {
			return r.action
		}
		if r.domain != "" || len(r.sites) > 0 {
			for _, domain := range domains {
				if r.matchesDomain(normalize(domain)) {
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

func (r compiledRule) matchesDomain(domain string) bool {
	if r.domain != "" && matchesDomain(domain, r.domain) {
		return true
	}
	for _, g := range r.sites {
		if g.matches(domain) {
			return true
		}
	}
	return false
}
func (r compiledRule) matchesIP(ip netip.Addr) bool {
	if r.prefix.IsValid() && r.prefix.Contains(ip) {
		return true
	}
	for _, g := range r.ips {
		if g.matches(ip) {
			return true
		}
	}
	return false
}
