package vpn

import (
	"container/heap"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"bimeron/internal/routing"
	"golang.org/x/net/dns/dnsmessage"
)

const defaultDNSMetadataEntries = 4096
const maxDNSMetadataTTL = 24 * time.Hour

// Per-response bounds. Real answers carry a handful of aliases and addresses;
// records beyond these limits are ignored, which only means fewer associations.
const (
	maxMetadataCNAMEs    = 16
	maxMetadataAddresses = 64
)

// DNSMetadata keeps bounded, session-local associations learned from validated
// DNS answers. It never persists or reports domain names.
type DNSMetadata struct {
	mu         sync.Mutex
	entries    map[netip.Addr]map[string]*metadataEntry
	expiry     metadataHeap
	seq        uint64
	count      int
	maxEntries int
	now        func() time.Time
}

// metadataEntry is one IP–domain association. Entries are ordered by expiry,
// then by insertion sequence, so eviction is deterministic.
type metadataEntry struct {
	ip      netip.Addr
	domain  string
	expires time.Time
	seq     uint64
	index   int
}

type metadataHeap []*metadataEntry

func (h metadataHeap) Len() int { return len(h) }
func (h metadataHeap) Less(i, j int) bool {
	if !h[i].expires.Equal(h[j].expires) {
		return h[i].expires.Before(h[j].expires)
	}
	return h[i].seq < h[j].seq
}
func (h metadataHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index, h[j].index = i, j
}
func (h *metadataHeap) Push(x any) {
	e := x.(*metadataEntry)
	e.index = len(*h)
	*h = append(*h, e)
}
func (h *metadataHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	e.index = -1
	return e
}

func NewDNSMetadata() *DNSMetadata {
	return &DNSMetadata{entries: make(map[netip.Addr]map[string]*metadataEntry), maxEntries: defaultDNSMetadataEntries, now: time.Now}
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

type metadataAlias struct {
	owner, target string
	ttl           uint32
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

	// Normalize each owner name once. Only the first maxMetadataCNAMEs aliases
	// take part, so the closure below is bounded regardless of answer size.
	var aliases []metadataAlias
	for _, resource := range answer.Answers {
		cname, ok := resource.Body.(*dnsmessage.CNAMEResource)
		if !ok || resource.Header.Class != dnsmessage.ClassINET {
			continue
		}
		if len(aliases) == maxMetadataCNAMEs {
			break
		}
		aliases = append(aliases, metadataAlias{metadataDomain(resource.Header.Name), metadataDomain(cname.CNAME), resource.Header.TTL})
	}
	// Each pass either lowers a path TTL or stops; with at most
	// maxMetadataCNAMEs aliases this is at most maxMetadataCNAMEs² steps.
	reachable := map[string]uint32{domain: ^uint32(0)}
	for range aliases {
		changed := false
		for _, alias := range aliases {
			pathTTL, ok := reachable[alias.owner]
			if !ok {
				continue
			}
			ttl := minTTL(pathTTL, alias.ttl)
			if current, exists := reachable[alias.target]; !exists || ttl < current {
				reachable[alias.target] = ttl
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	var learned []metadataAnswer
	for _, resource := range answer.Answers {
		if len(learned) == maxMetadataAddresses {
			break
		}
		if resource.Header.Class != dnsmessage.ClassINET {
			continue
		}
		var ip netip.Addr
		switch body := resource.Body.(type) {
		case *dnsmessage.AResource:
			if question.Type != dnsmessage.TypeA {
				continue
			}
			ip = netip.AddrFrom4(body.A)
		case *dnsmessage.AAAAResource:
			if question.Type != dnsmessage.TypeAAAA {
				continue
			}
			ip = netip.AddrFrom16(body.AAAA)
		default:
			continue
		}
		pathTTL, ok := reachable[metadataDomain(resource.Header.Name)]
		if !ok {
			continue
		}
		if ttl := minTTL(pathTTL, resource.Header.TTL); ttl != 0 {
			learned = append(learned, metadataAnswer{ip, domain, ttl})
		}
	}
	m.remember(learned)
}

// remember costs O(len(answers) · log n) under the lock.
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
		if existing := m.entries[answer.ip][answer.domain]; existing != nil {
			existing.expires = expires
			heap.Fix(&m.expiry, existing.index)
			continue
		}
		for m.count >= limit {
			m.removeEntry(m.expiry[0])
		}
		byDomain := m.entries[answer.ip]
		if byDomain == nil {
			byDomain = make(map[string]*metadataEntry)
			m.entries[answer.ip] = byDomain
		}
		m.seq++
		entry := &metadataEntry{ip: answer.ip, domain: answer.domain, expires: expires, seq: m.seq}
		byDomain[answer.domain] = entry
		heap.Push(&m.expiry, entry)
		m.count++
	}
}

// purgeExpired removes only expired entries: O(expired · log n).
func (m *DNSMetadata) purgeExpired(now time.Time) {
	for len(m.expiry) > 0 && !m.expiry[0].expires.After(now) {
		m.removeEntry(m.expiry[0])
	}
}

func (m *DNSMetadata) removeEntry(e *metadataEntry) {
	heap.Remove(&m.expiry, e.index)
	domains := m.entries[e.ip]
	delete(domains, e.domain)
	if len(domains) == 0 {
		delete(m.entries, e.ip)
	}
	m.count--
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
	var expired []*metadataEntry
	for domain, entry := range domains {
		if !entry.expires.After(now) {
			expired = append(expired, entry)
			continue
		}
		result = append(result, domain)
	}
	for _, entry := range expired {
		m.removeEntry(entry)
	}
	sort.Strings(result)
	return result
}
