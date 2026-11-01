package core

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ConfigDocument is an in-memory, byte-preserving configuration draft. It never
// reads files or validates runnable policy, capabilities, or dataset membership.
// It is not safe for concurrent use. Row indexes follow the current rule order.
type ConfigDocument struct {
	prefix string
	parts  []configDocumentPart
}
type configDocumentPart struct {
	raw, alternate string
	rule, disabled bool
}

// ConfigDocumentRule describes a table row. Error explains malformed active
// rules or fields the table cannot safely edit. Disabled candidates are included
// only when structurally valid. Enabled is editor state, never a config option.
type ConfigDocumentRule struct {
	Index    int    `json:"index"`
	Enabled  bool   `json:"enabled"`
	Matcher  string `json:"matcher"`
	Value    string `json:"value"`
	Action   string `json:"action"`
	Editable bool   `json:"editable"`
	Error    string `json:"error,omitempty"`
}

// ParseConfigDocument retains arbitrary drafts, including unknown sections and
// invalid active rules. Unchanged Bytes always returns the original bytes.
func ParseConfigDocument(data []byte) *ConfigDocument {
	d := &ConfigDocument{}
	text := string(data)
	if strings.HasPrefix(text, "\ufeff") {
		d.prefix = "\ufeff"
		text = strings.TrimPrefix(text, d.prefix)
	}
	lines := documentLines(text)
	for i := 0; i < len(lines); {
		name, disabled := documentHeader(lines[i])
		if name != "Rule" {
			d.parts = append(d.parts, configDocumentPart{raw: lines[i]})
			i++
			continue
		}
		end := i + 1
		for end < len(lines) {
			h, _ := documentHeader(lines[end])
			if h != "" {
				break
			}
			if disabled && strings.TrimSpace(lines[end]) != "" && !strings.HasPrefix(strings.TrimSpace(lines[end]), "#") {
				break
			}
			end++
		}
		raw := strings.Join(lines[i:end], "")
		p := configDocumentPart{raw: raw, rule: true, disabled: disabled}
		if disabled {
			_, structural, _ := documentRule(documentUncomment(raw))
			p.rule = structural == nil
		}
		d.parts = append(d.parts, p)
		i = end
	}
	return d
}

// Bytes returns a detached copy of the draft, without runtime serialization.
func (d *ConfigDocument) Bytes() []byte {
	var b strings.Builder
	b.WriteString(d.prefix)
	for _, p := range d.parts {
		b.WriteString(p.raw)
	}
	return []byte(b.String())
}

// RuleCount includes active rules and structurally valid disabled candidates.
func (d *ConfigDocument) RuleCount() int {
	n := 0
	for _, p := range d.parts {
		if p.rule {
			n++
		}
	}
	return n
}
func (d *ConfigDocument) part(index int) (int, error) {
	n := 0
	for i, p := range d.parts {
		if p.rule {
			if n == index {
				return i, nil
			}
			n++
		}
	}
	return 0, fmt.Errorf("rule index out of range")
}

// Rule returns a detached row snapshot.
func (d *ConfigDocument) Rule(index int) (*ConfigDocumentRule, error) {
	i, err := d.part(index)
	if err != nil {
		return nil, err
	}
	p := d.parts[i]
	raw := p.raw
	if p.disabled {
		raw = documentUncomment(raw)
	}
	r, structural, unknown := documentRule(raw)
	r.Index = index
	r.Enabled = !p.disabled
	r.Editable = structural == nil && unknown == nil
	if structural != nil {
		r.Error = structural.Error()
	} else if unknown != nil {
		r.Error = unknown.Error()
	}
	return &r, nil
}

// RulesJSON provides the row array using only gomobile-compatible bridge types.
func (d *ConfigDocument) RulesJSON() (string, error) {
	rows := make([]*ConfigDocumentRule, 0, d.RuleCount())
	for i := 0; i < d.RuleCount(); i++ {
		r, err := d.Rule(i)
		if err != nil {
			return "", err
		}
		rows = append(rows, r)
	}
	b, err := json.Marshal(rows)
	return string(b), err
}

// SetRuleEnabled adds/removes one outer # layer on every nonblank line.
// Enabling checks structure and refuses unknown fields; callers must additionally
// validate runtime policy and datasets before applying the returned draft.
func (d *ConfigDocument) SetRuleEnabled(index int, enabled bool) error {
	i, err := d.part(index)
	if err != nil {
		return err
	}
	p := &d.parts[i]
	if enabled == !p.disabled {
		return nil
	}
	if enabled {
		r, _ := d.Rule(index)
		if !r.Editable {
			return fmt.Errorf("cannot enable rule: %s", r.Error)
		}
	}
	next := p.alternate
	if next == "" {
		if enabled {
			next = documentUncomment(p.raw)
		} else {
			for _, line := range documentLines(p.raw) {
				if strings.TrimSpace(line) != "" {
					next += "# " + line
				} else {
					next += line
				}
			}
		}
	}
	p.alternate, p.raw = p.raw, next
	p.disabled = !enabled
	return nil
}

// SetRule replaces only the matcher key/value and action value, retaining their
// indentation, spacing, line endings, comments and position. Unknown fields or
// malformed rows block editing rather than silently discarding content.
func (d *ConfigDocument) SetRule(index int, matcher, value, action string) error {
	if strings.TrimSpace(value) != value || strings.TrimSpace(action) != action || strings.ContainsAny(value+action, "\r\n") {
		return fmt.Errorf("invalid rule value")
	}
	if err := documentValidate(matcher, value, action); err != nil {
		return err
	}
	i, err := d.part(index)
	if err != nil {
		return err
	}
	r, _ := d.Rule(index)
	if !r.Editable {
		return fmt.Errorf("cannot edit rule: %s", r.Error)
	}
	p := &d.parts[i]
	lines := documentLines(p.raw)
	for j, line := range lines {
		prefix := ""
		body := line
		if p.disabled && strings.TrimSpace(line) != "" {
			prefix, body = documentOuter(line)
		}
		key, _, ok := strings.Cut(strings.TrimSpace(body), "=")
		key = strings.TrimSpace(key)
		if !ok || (key != r.Matcher && key != "Action") {
			continue
		}
		eq := strings.IndexByte(body, '=')
		left := body[:eq]
		right := body[eq+1:]
		replacement := value
		newKey := matcher
		if key == "Action" {
			replacement = action
			newKey = "Action"
		}
		// The runtime decodes values beginning with a double quote.
		if strings.HasPrefix(replacement, `"`) {
			replacement = strconv.Quote(replacement)
		}
		leading := left[:len(left)-len(strings.TrimLeft(left, " \t"))]
		trailing := left[len(strings.TrimRight(left, " \t")):]
		ws := right[:len(right)-len(strings.TrimLeft(right, " \t"))]
		tail := right[len(strings.TrimRight(right, " \t\r\n")):]
		lines[j] = prefix + leading + newKey + trailing + "=" + ws + replacement + tail
	}
	p.raw = strings.Join(lines, "")
	p.alternate = ""
	return nil
}

// MoveRule moves the complete block to a final zero-based row index. Text
// outside rule blocks stays in its relative position. A missing final newline
// stays missing; a necessary line separator travels to the new block boundary.
func (d *ConfigDocument) MoveRule(from, to int) error {
	a, err := d.part(from)
	if err != nil {
		return err
	}
	b, err := d.part(to)
	if err != nil {
		return err
	}
	if a == b {
		return nil
	}
	original := string(d.Bytes())
	p := d.parts[a]
	if a < b {
		copy(d.parts[a:b], d.parts[a+1:b+1])
	} else {
		copy(d.parts[b+1:a+1], d.parts[b:a])
	}
	d.parts[b] = p
	eol := "\n"
	if strings.Contains(original, "\r\n") {
		eol = "\r\n"
	}
	for i := 0; i < len(d.parts)-1; i++ {
		if d.parts[i].raw != "" && !strings.HasSuffix(d.parts[i].raw, "\n") {
			d.parts[i].raw += eol
			d.parts[i].alternate = ""
		}
	}
	if !strings.HasSuffix(original, "\n") && len(d.parts) > 0 {
		p := &d.parts[len(d.parts)-1]
		if p.rule && strings.HasSuffix(p.raw, "\n") {
			p.raw = strings.TrimSuffix(strings.TrimSuffix(p.raw, "\n"), "\r")
			p.alternate = ""
		}
	}
	return nil
}

func documentLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}
func documentOuter(line string) (string, string) {
	i := strings.IndexByte(line, '#')
	if i < 0 {
		return "", line
	}
	end := i + 1
	if end < len(line) && line[end] == ' ' {
		end++
	}
	return line[:end], line[end:]
}
func documentUncomment(raw string) string {
	var b strings.Builder
	for _, line := range documentLines(raw) {
		if strings.TrimSpace(line) != "" {
			prefix, body := documentOuter(line)
			line = prefix[:strings.IndexByte(prefix, '#')] + body
		}
		b.WriteString(line)
	}
	return b.String()
}
func documentHeader(line string) (string, bool) {
	s := strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
	disabled := strings.HasPrefix(s, "#")
	if disabled {
		_, s = documentOuter(s)
		s = strings.TrimSpace(s)
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		name := strings.TrimSpace(s[1 : len(s)-1])
		if !disabled || name == "Rule" {
			return name, disabled
		}
	}
	return "", false
}

func documentRule(raw string) (ConfigDocumentRule, error, error) {
	r := ConfigDocumentRule{}
	seen := map[string]bool{}
	matchers := 0
	var structural, unknown error
	lines := documentLines(raw)
	for _, line := range lines[1:] {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		key, value, ok := strings.Cut(s, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || key == "" || seen[key] {
			structural = fmt.Errorf("malformed or duplicate rule field")
			continue
		}
		seen[key] = true
		if strings.HasPrefix(value, `"`) {
			decoded, err := strconv.Unquote(value)
			if err != nil {
				structural = fmt.Errorf("invalid quoted rule value")
				continue
			}
			value = decoded
		}
		switch key {
		case "CIDR", "Domain", "GeoIP", "GeoSite":
			matchers++
			r.Matcher = key
			r.Value = value
		case "Action":
			r.Action = value
		default:
			unknown = fmt.Errorf("unknown rule field %q; use raw editing", key)
		}
	}
	if matchers != 1 {
		structural = fmt.Errorf("rule requires exactly one matcher")
	}
	if err := documentValidate(r.Matcher, r.Value, r.Action); err != nil {
		structural = err
	}
	return r, structural, unknown
}
func documentValidate(matcher, value, action string) error {
	if strings.ContainsAny(value+action, "\r\n") {
		return fmt.Errorf("invalid rule value")
	}
	if action != "direct" && action != "proxy" && action != "block" {
		return fmt.Errorf("invalid rule action")
	}
	switch matcher {
	case "CIDR":
		for _, v := range strings.Split(value, ",") {
			if _, err := netip.ParsePrefix(strings.TrimSpace(v)); err != nil {
				return fmt.Errorf("invalid CIDR")
			}
		}
	case "Domain":
		v := strings.TrimSuffix(value, ".")
		if v == "" || strings.ContainsAny(v, " /*:\t\r\n") {
			return fmt.Errorf("invalid domain")
		}
	case "GeoIP", "GeoSite":
		for _, v := range strings.Split(value, ",") {
			v = strings.TrimSpace(v)
			if v == "" || strings.ContainsAny(v, " \t\r\n#;=[]") {
				return fmt.Errorf("invalid geodata identifier")
			}
		}
	default:
		return fmt.Errorf("invalid matcher")
	}
	return nil
}
