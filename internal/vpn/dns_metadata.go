package vpn

import (
	"math"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"bimeron/internal/routing"
)

const defaultDNSMetadataEntries = 4096
const maxDNSMetadataTTL = 24 * time.Hour

// DNSMetadata keeps bounded, session-local associations learned from validated
// DNS answers. It never persists or reports domain names.
type DNSMetadata struct {
	mu         sync.Mutex
	entries    map[netip.Addr]map[string]time.Time
	count      int
	maxEntries int
	now        func() time.Time
}

func NewDNSMetadata() *DNSMetadata {
	return &DNSMetadata{entries: make(map[netip.Addr]map[string]time.Time), maxEntries: defaultDNSMetadataEntries, now: time.Now}
}

func metadataDomain(name dnsmessage.Name) string {
	return strings.ToLower(strings.TrimSuffix(name.String(), "."))
}

func minTTL(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

type metadataAnswer struct {
	ip     netip.Addr
	domain string
	ttl    uint32
}

// Observe learns only a single relevant IN A/AAAA question and addresses
// reachable from it through the answer's CNAME chain.
func (m *DNSMetadata) Observe(query, response []byte, policy *routing.Policy) {
	if m == nil || policy == nil {
		return
	}
	var request, answer dnsmessage.Message
	if request.Unpack(query) != nil || answer.Unpack(response) != nil || request.Response || !answer.Response || answer.Truncated || answer.ID != request.ID || answer.OpCode != request.OpCode || answer.RCode != dnsmessage.RCodeSuccess || len(request.Questions) != 1 || len(answer.Questions) != 1 {
		return
	}
	question, echoed := request.Questions[0], answer.Questions[0]
	if question.Class != dnsmessage.ClassINET || (question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA) || echoed.Class != question.Class || echoed.Type != question.Type || !strings.EqualFold(echoed.Name.String(), question.Name.String()) {
		return
	}
	domain := metadataDomain(question.Name)
	if !policy.DomainRelevant(domain) {
		return
	}

	reachable := map[string]uint32{domain: math.MaxUint32}
	for range answer.Answers {
		changed := false
		for _, resource := range answer.Answers {
			cname, ok := resource.Body.(*dnsmessage.CNAMEResource)
			if !ok || resource.Header.Class != dnsmessage.ClassINET {
				continue
			}
			pathTTL, ok := reachable[metadataDomain(resource.Header.Name)]
			if !ok {
				continue
			}
			target := metadataDomain(cname.CNAME)
			ttl := minTTL(pathTTL, resource.Header.TTL)
			if current, exists := reachable[target]; !exists || ttl < current {
				reachable[target] = ttl
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	var learned []metadataAnswer
	for _, resource := range answer.Answers {
		if resource.Header.Class != dnsmessage.ClassINET {
			continue
		}
		pathTTL, ok := reachable[metadataDomain(resource.Header.Name)]
		if !ok {
			continue
		}
		ttl := minTTL(pathTTL, resource.Header.TTL)
		if ttl == 0 {
			continue
		}
		switch body := resource.Body.(type) {
		case *dnsmessage.AResource:
			if question.Type == dnsmessage.TypeA {
				learned = append(learned, metadataAnswer{netip.AddrFrom4(body.A), domain, ttl})
			}
		case *dnsmessage.AAAAResource:
			if question.Type == dnsmessage.TypeAAAA {
				learned = append(learned, metadataAnswer{netip.AddrFrom16(body.AAAA), domain, ttl})
			}
		}
	}
	m.remember(learned)
}

func (m *DNSMetadata) remember(answers []metadataAnswer) {
	if len(answers) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.purgeExpired(now)
	limit := m.maxEntries
	if limit <= 0 {
		return
	}
	for _, answer := range answers {
		duration := time.Duration(answer.ttl) * time.Second
		if duration > maxDNSMetadataTTL {
			duration = maxDNSMetadataTTL
		}
		expires := now.Add(duration)
		if byDomain := m.entries[answer.ip]; byDomain != nil {
			if _, exists := byDomain[answer.domain]; exists {
				byDomain[answer.domain] = expires
				continue
			}
		}
		for m.count >= limit {
			if !m.evictSoonest() {
				return
			}
		}
		byDomain := m.entries[answer.ip]
		if byDomain == nil {
			byDomain = make(map[string]time.Time)
			m.entries[answer.ip] = byDomain
		}
		if _, exists := byDomain[answer.domain]; exists {
			byDomain[answer.domain] = expires
			continue
		}
		byDomain[answer.domain] = expires
		m.count++
	}
}

func (m *DNSMetadata) purgeExpired(now time.Time) {
	for ip, domains := range m.entries {
		for domain, expires := range domains {
			if !expires.After(now) {
				delete(domains, domain)
				m.count--
			}
		}
		if len(domains) == 0 {
			delete(m.entries, ip)
		}
	}
}

func (m *DNSMetadata) evictSoonest() bool {
	var selectedIP netip.Addr
	var selectedDomain string
	var selectedExpiry time.Time
	found := false
	for ip, domains := range m.entries {
		for domain, expiry := range domains {
			key, selectedKey := ip.String()+"\x00"+domain, selectedIP.String()+"\x00"+selectedDomain
			if !found || expiry.Before(selectedExpiry) || (expiry.Equal(selectedExpiry) && key < selectedKey) {
				selectedIP, selectedDomain, selectedExpiry, found = ip, domain, expiry, true
			}
		}
	}
	if !found {
		return false
	}
	delete(m.entries[selectedIP], selectedDomain)
	if len(m.entries[selectedIP]) == 0 {
		delete(m.entries, selectedIP)
	}
	m.count--
	return true
}

// Domains returns a detached, sorted snapshot for deterministic policy input.
func (m *DNSMetadata) Domains(ip netip.Addr) []string {
	if m == nil {
		return nil
	}
	ip = ip.Unmap()
	m.mu.Lock()
	defer m.mu.Unlock()
	domains := m.entries[ip]
	now := m.now()
	result := make([]string, 0, len(domains))
	for domain, expires := range domains {
		if !expires.After(now) {
			delete(domains, domain)
			m.count--
			continue
		}
		result = append(result, domain)
	}
	if len(domains) == 0 {
		delete(m.entries, ip)
	}
	sort.Strings(result)
	return result
}
